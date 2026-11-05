"""Durable IPv4/IPv6 permanent-ban worker. Linux runtime; standard library only."""
from f2block_config import parse_address
import contextlib
import datetime as dt
import math
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import threading
import time
from f2block_config import load_config

ROOT = Path(__file__).resolve().parent
# Importing schema helpers must never read machine-specific configuration.
CONFIG = {}
DATA_DIR = ROOT
DB_PATH = DATA_DIR / 'f2block.db'
PATTERN = re.compile(r'^(\S+ \S+).*\[([^\]]+)\]\s+Ban\s+(\S+)')


class DeferredFirewallError(subprocess.CalledProcessError):
    """Desired state committed; the cursor may advance while delivery retries."""


def migrate_legacy_cursor(db, source):
    """Copy the former single-source cursor to the matching source record."""
    if not source:
        return
    legacy = db.execute('SELECT device,inode,offset FROM log_cursor WHERE id=1').fetchone()
    if not legacy or db.execute('SELECT 1 FROM source_cursors WHERE source=?', (source,)).fetchone():
        return
    try:
        offset = _cursor_integer(legacy[2])
    except (TypeError, ValueError, OverflowError):
        return
    if offset < 0:
        return
    # The old cursor had no source key.  Only migrate it when the configured
    # path still names the same file; after rotation, replacement, or a
    # changed/removed log_file, applying its byte offset to a different file
    # would defeat start_at_end and replay an unrelated backlog.
    try:
        current = Path(source).stat()
    except OSError:
        return
    if (str(legacy[0]), str(legacy[1])) != (str(current.st_dev), str(current.st_ino)):
        return
    with db:
        db.execute('INSERT OR IGNORE INTO source_cursors '
                   '(source,device,inode,offset,generation) VALUES(?,?,?,?,0)',
                   (source, legacy[0], legacy[1], offset))


def _cursor_integer(value):
    if isinstance(value, bool):
        raise ValueError('布尔值不是日志游标')
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        raise ValueError('日志游标必须是有限整数')
    return int(value)


def _local_time(value):
    """Parse old and new persisted timestamps into comparable local-naive time."""
    parsed = dt.datetime.fromisoformat(str(value).replace(',', '.'))
    return parsed.astimezone().replace(tzinfo=None) if parsed.tzinfo else parsed


def initialize(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, country TEXT,
      region TEXT, city TEXT, org TEXT, first_seen TEXT, last_ban_time TEXT,
      ban_count INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS ban_events (id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL, jail TEXT, ban_time TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS allowlist (ip TEXT PRIMARY KEY, added_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS released_ips (ip TEXT PRIMARY KEY, released_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS admin_events (id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL, action TEXT NOT NULL, action_time TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS log_cursor (id INTEGER PRIMARY KEY CHECK(id=1),
      device TEXT, inode TEXT, offset INTEGER);
    CREATE TABLE IF NOT EXISTS runtime_migrations (name TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS runtime_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS f2b_pending (ip TEXT PRIMARY KEY, action TEXT NOT NULL,
      queued_at TEXT NOT NULL, last_error TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS whitelist_jails (ip TEXT NOT NULL, jail TEXT NOT NULL,
      PRIMARY KEY(ip,jail));
    CREATE TABLE IF NOT EXISTS source_cursors (
      source TEXT PRIMARY KEY, device TEXT, inode TEXT, offset INTEGER,
      generation INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS detection_hits (
      rule TEXT NOT NULL, receipt TEXT NOT NULL, ip TEXT NOT NULL, stamp REAL NOT NULL,
      PRIMARY KEY(rule,receipt));
    CREATE INDEX IF NOT EXISTS idx_detection_window ON detection_hits(rule,ip,stamp);
    CREATE TABLE IF NOT EXISTS detection_bans (
      id INTEGER PRIMARY KEY, ip TEXT NOT NULL, rule TEXT NOT NULL, matched INTEGER,
      threshold INTEGER, window INTEGER, created TEXT NOT NULL);
    ''')
    # Readers (status/TUI/scans) must not delay commits made by ban/import
    # writers. WAL is persistent; repeated initialization leaves it enabled.
    db.execute('PRAGMA journal_mode=WAL').fetchone()
    from f2block_enrich import initialize_geo
    initialize_geo(db)
    with db:
        if 'reason' not in {row[1] for row in db.execute('PRAGMA table_info(admin_events)')}:
            db.execute("ALTER TABLE admin_events ADD COLUMN reason TEXT NOT NULL DEFAULT ''")
        if not db.execute("SELECT 1 FROM runtime_migrations WHERE name='dedup-v1'").fetchone():
            db.execute('DELETE FROM ban_events WHERE id NOT IN '
                       '(SELECT MIN(id) FROM ban_events GROUP BY ip,jail,ban_time)')
            db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_ban_events_dedup '
                       'ON ban_events(ip,jail,ban_time)')
            db.execute("INSERT INTO runtime_migrations VALUES ('dedup-v1')")


@contextlib.contextmanager
def locked(path):
    import fcntl
    with open(path, 'a') as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(file, fcntl.LOCK_UN)


def run(*args, check=True):
    return subprocess.run(args, check=check, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE, timeout=30)


def ban_set(ip):
    return 'f2block6' if parse_address(ip).version == 6 else 'f2block'


def reconcile(db):
    for name, family, tool in (('f2block', 'inet', 'iptables'), ('f2block6', 'inet6', 'ip6tables')):
        run('ipset', 'create', name, 'hash:ip', 'family', family, 'timeout', '0', '-exist')
        rule = ('INPUT', '-m', 'set', '--match-set', name, 'src', '-j', 'DROP')
        if run(tool, '-C', *rule, check=False).returncode:
            run(tool, '-I', *rule)
    errors = []
    for (ip,) in db.execute('SELECT ip FROM released_ips UNION SELECT ip FROM allowlist'):
        try:
            command = ('ipset', 'test', ban_set(ip), ip)
            result = run(*command, check=False)
            if result.returncode not in (0, 1):
                raise subprocess.CalledProcessError(result.returncode, command)
            run('ipset', 'del', ban_set(ip), ip, '-exist')
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(error)
    for (ip,) in db.execute('SELECT ip FROM blocked_ips WHERE '
                            'ip NOT IN (SELECT ip FROM released_ips) AND '
                            'ip NOT IN (SELECT ip FROM allowlist)'):
        try:
            run('ipset', 'add', ban_set(ip), ip, '-exist')
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            errors.append(error)
    if errors:
        raise errors[0]


def record(db, line):
    match = PATTERN.search(line)
    if not match:
        return
    raw_time, jail, ip = match.groups()
    try:
        address = parse_address(ip)
        stamp = dt.datetime.fromisoformat(raw_time.replace(',', '.'))
    except ValueError:
        return
    if '%' in ip:
        return
    if stamp.tzinfo is not None:
        stamp = stamp.astimezone().replace(tzinfo=None)
    # Persist one local, timezone-free ISO representation.  Comparing raw log
    # strings makes MAX/MIN wrong when equivalent events use offsets or comma
    # versus dot fractional seconds.
    event_time = stamp.isoformat(' ')
    ip = str(address)
    with db:
        save_ban(db, ip, jail, raw_time)
    if not db.execute('SELECT 1 FROM allowlist WHERE ip=? UNION SELECT 1 FROM released_ips WHERE ip=?', (ip, ip)).fetchone():
        deliver_ban(ip)


def save_ban(db, ip, jail, raw_time):
    """Persist a ban inside the caller's transaction; no external effects."""
    stamp = _local_time(raw_time)
    event_time = stamp.isoformat(' ')
    if db.execute('SELECT 1 FROM allowlist WHERE ip=?', (ip,)).fetchone():
        return
    released = db.execute('SELECT released_at FROM released_ips WHERE ip=?', (ip,)).fetchone()
    if released:
        try:
            barrier = _local_time(released[0])
        except (TypeError, ValueError) as error:
            # A corrupt barrier must stop this event and be visible to the
            # daemon retry loop; treating it as absent could re-ban silently.
            raise sqlite3.DatabaseError(f'损坏的 released_at：{released[0]!r}') from error
        if stamp <= barrier:
            return
    # Keep the raw log timestamp in the unique event key so replaying an
    # upgrade-era log remains idempotent.  The current-state summary below
    # uses the normalized timestamp for chronological comparisons.
    inserted = db.execute('INSERT OR IGNORE INTO ban_events(ip,jail,ban_time) VALUES(?,?,?)',
                          (ip, jail, raw_time)).rowcount
    if inserted:
        current = db.execute('SELECT first_seen,last_ban_time FROM blocked_ips WHERE ip=?', (ip,)).fetchone()
        first_seen = event_time
        last_ban = event_time
        if current:
            try:
                first_seen = event_time if _local_time(event_time) < _local_time(current[0]) else current[0]
            except (TypeError, ValueError, OverflowError):
                first_seen = min(str(current[0]), event_time)
            try:
                last_ban = event_time if _local_time(event_time) > _local_time(current[1]) else current[1]
            except (TypeError, ValueError, OverflowError):
                last_ban = max(str(current[1]), event_time)
        db.execute('''INSERT INTO blocked_ips
          (ip,country,region,city,org,first_seen,last_ban_time,ban_count)
          VALUES(?,'Unknown','Unknown','Unknown','Unknown',?,?,
            (SELECT COUNT(*) FROM ban_events WHERE ip=?))
          ON CONFLICT(ip) DO UPDATE SET
            first_seen=excluded.first_seen, last_ban_time=excluded.last_ban_time,
            ban_count=(SELECT COUNT(*) FROM ban_events WHERE ip=excluded.ip)
          ''', (ip, first_seen, last_ban, ip))
        db.execute('DELETE FROM released_ips WHERE ip=?', (ip,))
        db.execute("DELETE FROM f2b_pending WHERE ip=? AND action='unban'", (ip,))


def deliver_ban(ip):
    try:
        run('ipset', 'add', ban_set(ip), ip, '-exist')
    except (OSError, subprocess.SubprocessError) as error:
        raise DeferredFirewallError(getattr(error, 'returncode', 1),
                                    ('ipset', 'add', ban_set(ip), ip), stderr=str(error)) from error



def enrich(stop):
    from f2block_enrich import enrich as run_enrichment
    run_enrichment(stop, CONFIG, DATA_DIR, DB_PATH)


class LogReader:
    def __init__(self, path, db, cursor_key=None, start_at_end=False, legacy_source=False):
        self.path, self.db, self.handle = path, db, None
        self.cursor_key, self.start_at_end = cursor_key, start_at_end
        self.legacy_source = legacy_source
        self.generation = 0
        self.epochs = {}
        self.pending = []
        self.source = None

    def read(self):
        # A rotating writer may finish its last line after the new file opens.
        # Retain partial old streams and poll them without blocking the new log.
        for stream in list(self.pending):
            position = stream.tell()
            line = stream.readline()
            if line.endswith(b'\n'):
                self.source, self.position = stream, position
                return line
            stream.seek(position)
            if not line:
                self.pending.remove(stream)
                self.epochs.pop(stream, None)
                stream.close()
        if self.handle is None:
            self.handle = self.path.open('rb')
            stat = os.fstat(self.handle.fileno())
            if self.cursor_key is None:
                cursor = self.db.execute('SELECT device,inode,offset FROM log_cursor WHERE id=1').fetchone()
            else:
                if self.legacy_source:
                    migrate_legacy_cursor(self.db, self.cursor_key)
                cursor = self.db.execute('SELECT device,inode,offset,generation FROM source_cursors WHERE source=?',
                                         (self.cursor_key,)).fetchone()
            if cursor:
                try:
                    offset = _cursor_integer(cursor[2])
                    generation = _cursor_integer(cursor[3]) if self.cursor_key is not None else 0
                    if offset < 0 or generation < 0:
                        raise ValueError('负日志游标')
                    cursor = (*cursor[:2], offset, generation) if self.cursor_key is not None else (*cursor[:2], offset)
                except (TypeError, ValueError, OverflowError):
                    cursor = None
                    self.generation = 0
                    if self.cursor_key is not None:
                        with self.db:
                            self.db.execute('DELETE FROM source_cursors WHERE source=?', (self.cursor_key,))
            if cursor:
                self.generation = cursor[3] if self.cursor_key is not None else 0
                if tuple(map(str, cursor[:2])) == (str(stat.st_dev), str(stat.st_ino)) and cursor[2] > stat.st_size:
                    self.generation += 1
            elif self.start_at_end:
                self.handle.seek(0, 2)
            if cursor and tuple(map(str, cursor[:2])) == (str(stat.st_dev), str(stat.st_ino)) and cursor[2] <= stat.st_size:
                self.handle.seek(cursor[2])
            if self.cursor_key is not None:
                self._checkpoint(self.handle)
            self.epochs[self.handle] = self.generation

        self.source = self.handle
        self.position = self.handle.tell()
        line = self.handle.readline()
        if line and line.endswith(b'\n'):
            return line
        self.retry()
        old, current = os.fstat(self.handle.fileno()), self.path.stat()
        if (old.st_dev, old.st_ino) != (current.st_dev, current.st_ino):
            if line:
                if len(self.pending) >= 128:
                    raise OSError('过多未完成的轮转日志，请检查日志写入器')
                self.pending.append(self.handle)
            else:
                self.epochs.pop(self.handle, None)
                self.handle.close()
            self.handle = None
        elif current.st_size < self.position:
            self.generation += 1
            self.epochs[self.handle] = self.generation
            self.handle.seek(0)
            if self.cursor_key is not None:
                self._checkpoint(self.handle)
        return None

    def retry(self):
        self.source.seek(self.position)

    def receipt(self):
        import hashlib
        stat = os.fstat(self.source.fileno())
        value = (self.cursor_key, stat.st_dev, stat.st_ino, self.epochs.get(self.source, 0), self.position)
        return hashlib.sha256(repr(value).encode()).hexdigest()

    def _checkpoint(self, stream):
        stat = os.fstat(stream.fileno())
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO source_cursors VALUES(?,?,?,?,?)',
                            (self.cursor_key, str(stat.st_dev), str(stat.st_ino), stream.tell(),
                             self.epochs.get(stream, self.generation)))

    def acknowledge(self):
        stat = os.fstat(self.source.fileno())
        with self.db:
            if self.cursor_key is None:
                self.db.execute('INSERT OR REPLACE INTO log_cursor VALUES(1,?,?,?)',
                                (str(stat.st_dev), str(stat.st_ino), self.source.tell()))
            elif self.source is self.handle:
                self._checkpoint(self.source)
            self.db.execute("INSERT OR REPLACE INTO runtime_state VALUES('last_processed',?)",
                            (dt.datetime.now().isoformat(' ', timespec='seconds'),))

    def close(self):
        if self.handle:
            self.handle.close()
        self.handle = None
        for stream in self.pending:
            stream.close()
        self.pending.clear()
        self.epochs.clear()


def main():
    global CONFIG, DATA_DIR, DB_PATH
    from f2block_detect import rules_for, process_line, prune
    CONFIG = load_config()
    rules = rules_for(CONFIG)
    DATA_DIR = Path(CONFIG['data_dir'])
    DB_PATH = DATA_DIR / 'f2block.db'
    import fcntl
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(DATA_DIR / '.daemon.lock', 'a') as singleton:
        try:
            fcntl.flock(singleton, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('f2blockd is already running')
        db = sqlite3.connect(DB_PATH, timeout=30)
        with locked(DATA_DIR / '.operations.lock'):
            initialize(db)
        grouped = {}
        for rule in rules:
            source = str(Path(rule['log_file']).resolve())
            grouped.setdefault(source, []).append(rule)
        legacy_source = CONFIG.get('log_file')
        if legacy_source:
            legacy_source = str(Path(legacy_source).resolve())
            if legacy_source in grouped:
                migrate_legacy_cursor(db, legacy_source)
        readers = {source: LogReader(Path(source), db, source, CONFIG.get('start_at_end', True),
                                     legacy_source=(source == legacy_source))
                   for source in grouped}
        geo_stop = threading.Event()
        geo = threading.Thread(target=enrich, args=(geo_stop,), daemon=True)
        if CONFIG['geo_enabled']:
            geo.start()
        next_sync = next_heartbeat = 0
        errors = {}
        try:
            while not stopping:
                busy = False
                try:
                    if time.monotonic() >= next_sync:
                        next_sync = time.monotonic() + CONFIG['sync_interval']
                        with locked(DATA_DIR / '.operations.lock'):
                            try:
                                reconcile(db)
                                prune(db, rules)
                                errors.pop('firewall', None)
                                with db:
                                    db.execute("INSERT OR REPLACE INTO runtime_state VALUES('last_sync',?)",
                                               (dt.datetime.now().isoformat(' ', timespec='seconds'),))
                            except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
                                errors['firewall'] = str(error)
                    for source, reader in readers.items():
                        try:
                            line = reader.read()
                            errors.pop(source, None)
                            if line is None:
                                continue
                            busy = True
                            with locked(DATA_DIR / '.operations.lock'):
                                try:
                                    process_line(db, grouped[source], line.decode('utf-8', errors='replace'), reader.receipt())
                                except DeferredFirewallError as error:
                                    errors['firewall'] = str(error)
                                    next_sync = 0
                                reader.acknowledge()
                        except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
                            if reader.source is not None and not reader.source.closed:
                                reader.retry()
                            errors[source] = str(error)
                    if time.monotonic() >= next_heartbeat:
                        with db:
                            db.execute("INSERT OR REPLACE INTO runtime_state VALUES('heartbeat',?)", (str(time.time()),))
                            db.execute("INSERT OR REPLACE INTO runtime_state VALUES('last_error',?)",
                                       ('; '.join(f'{key}: {value}' for key, value in errors.items()),))
                        next_heartbeat = time.monotonic() + 5
                except (OSError, sqlite3.Error) as error:
                    print(f'[RETRY] {error}', flush=True)
                    time.sleep(1)
                if not busy:
                    time.sleep(0.2)
        finally:
            geo_stop.set()
            if geo.is_alive():
                geo.join(timeout=11)
            for reader in readers.values():
                reader.close()
            db.close()


if __name__ == '__main__':
    main()
