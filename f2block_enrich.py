"""Independent library maintenance and durable, bounded local/online enrichment."""
from email.utils import parsedate_to_datetime
import json
from pathlib import Path
import sqlite3
import threading
import time
import urllib.error
import urllib.request

from f2block_config import parse_address
from f2block_geo import LocalGeo

FIELDS = ('country', 'region', 'city', 'org')
LABELS = {'found': '已查询，有结果', 'partial': '已查询，部分字段未收录',
          'not_found': '已查询，未收录', 'retry': '临时失败，等待重试',
          'unresolved': '重试已达上限，结果未知'}


def initialize_geo(db):
    db.execute('CREATE TABLE IF NOT EXISTS geo_lookup ('
               'ip TEXT PRIMARY KEY,state TEXT NOT NULL,attempted REAL NOT NULL,retry_at REAL NOT NULL,'
               'attempts INTEGER NOT NULL,release TEXT NOT NULL,record_seen TEXT NOT NULL,detail TEXT NOT NULL)')
    db.commit()


def state_set(db, **values):
    with db:
        db.executemany('INSERT OR REPLACE INTO runtime_state(key,value) VALUES(?,?)',
                       [(key, str(value)) for key, value in values.items()])


def known(value):
    return isinstance(value, str) and bool(value.strip()) and value.strip().casefold() != 'unknown'


class OnlineFallback:
    def __init__(self, next_allowed=0):
        self.next_allowed = next_allowed
        self.error = ''

    def lookup(self, ip, now):
        """Return values, outcome, retry time, and whether a request was made."""
        if not parse_address(ip).is_global:
            return {}, 'not_found', 0, False
        if now < self.next_allowed:
            return {}, 'retry', self.next_allowed, False
        self.next_allowed = now + 5
        try:
            request = urllib.request.Request(f'https://ipinfo.io/{ip}/json', headers={'User-Agent': 'f2block/2 geo-fallback'})
            with urllib.request.urlopen(request, timeout=3) as response:
                raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError('联网地理信息响应过大')
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError('联网地理信息响应格式错误')
            if payload.get('error'):
                raise ValueError('联网地理信息接口返回错误')
            values = {key: payload[key].strip() for key in FIELDS
                      if known(payload.get(key)) and len(payload[key]) <= 4096}
            self.error = ''
            return values, 'found' if values else 'not_found', 0, True
        except urllib.error.HTTPError as error:
            if error.code == 404:
                self.error = ''
                return {}, 'not_found', 0, True
            delay = 3600 if error.code in (401, 403, 429) else 60
            retry = error.headers.get('Retry-After') if error.headers else None
            if retry:
                try:
                    delay = max(delay, float(retry))
                except ValueError:
                    try:
                        delay = max(delay, parsedate_to_datetime(retry).timestamp() - now)
                    except (ValueError, TypeError, OverflowError):
                        pass
            self.next_allowed = now + max(60, min(delay, 86400))
            self.error = f'HTTP {error.code}，已退避'
        except (OSError, ValueError, UnicodeError) as error:
            self.next_allowed = now + 60
            self.error = str(error)
        return {}, 'retry', self.next_allowed, True


def maintain(stop, config, data_dir, db_path):
    """Own reader/connection: builds never share enrichment or operation locks."""
    library = LocalGeo(data_dir)
    db = sqlite3.connect(db_path, timeout=5)
    due = retry = last_progress = 0
    try:
        def progress():
            nonlocal last_progress
            if stop.is_set():
                raise OSError('IP 库更新已停止')
            now = time.monotonic()
            if now - last_progress >= 5:
                last_progress = now
                try:
                    state_set(db, geo_update_heartbeat=time.time())
                except sqlite3.Error:
                    # Reporting must never abort a valid database build.
                    pass
        while not stop.is_set():
            try:
                state = dict(db.execute('SELECT key,value FROM runtime_state'))
                repair = state.get('geo_repair_requested') == '1'
                try:
                    library.reload()
                    unavailable = False
                except (OSError, ValueError, sqlite3.Error):
                    unavailable = True
                try:
                    marker = json.loads((library.directory / 'release.json').read_text())
                    marker_ok = marker.get('release') == (library.packed.release if library.packed else '')
                except (OSError, ValueError, AttributeError):
                    marker_ok = False
                missing = unavailable or not (library.directory / 'lookup.geo').is_file() or not marker_ok
                now = time.monotonic()
                if now >= due or ((repair or missing) and now >= retry):
                    try:
                        release = library.update(force=repair, progress=progress)
                        state_set(db, geo_update_error='', geo_repair_requested='', geo_release=release,
                                  geo_update_heartbeat=time.time())
                        due = time.monotonic() + config.get('geo_update_interval', 86400)
                        retry = 0
                    except (OSError, ValueError, sqlite3.Error, EOFError, RuntimeError) as error:
                        if stop.is_set():
                            break
                        state_set(db, geo_update_error=str(error), geo_update_heartbeat=time.time())
                        print(f'[GEO UPDATE] {error}', flush=True)
                        due = time.monotonic() + 3600
                        retry = time.monotonic() + 60
            except (OSError, ValueError, sqlite3.Error) as error:
                print(f'[GEO MAINTENANCE] {error}', flush=True)
            stop.wait(5)
    finally:
        library.close()
        db.close()


def scan_once(db, library, online, now=None, stop=None):
    """Scan missing fields; terminal negative results are not repeatedly queried."""
    now = time.time() if now is None else now
    release = ''
    local_error = ''
    try:
        library.reload()
        release = library.generation
    except (OSError, ValueError, sqlite3.Error) as error:
        local_error = str(error)
    missing = ' OR '.join(f"b.{key} IS NULL OR trim(b.{key})='' OR lower(trim(b.{key}))='unknown'" for key in FIELDS)
    cursor = db.execute('SELECT b.ip,b.country,b.region,b.city,b.org,b.first_seen,'
                        'g.state,g.attempts,g.release,g.record_seen FROM blocked_ips b LEFT JOIN geo_lookup g ON g.ip=b.ip '
                        f'WHERE ({missing}) AND (g.ip IS NULL OR g.state=\'found\' OR g.record_seen!=COALESCE(b.first_seen,\'\') '
                        "OR (g.state='retry' AND g.attempts<3 AND g.retry_at<=?) "
                        "OR (?!='' AND g.release!=?)) ORDER BY COALESCE(g.attempted,0),b.ip LIMIT 50", (now, release, release))
    rows = cursor.fetchall()
    cursor.close()
    for ip, country, region, city, org, first_seen, previous_state, attempts, previous_release, record_seen in rows:
        if stop is not None and stop.is_set():
            break
        values = dict(zip(FIELDS, (country, region, city, org)))
        if record_seen != (first_seen or ''):
            previous_state, attempts, previous_release = None, 0, ''
        values = {key: value if known(value) else 'Unknown' for key, value in values.items()}
        local = {}
        try:
            if release:
                local = library.lookup(ip)
        except (OSError, ValueError, sqlite3.Error) as error:
            local_error = str(error)
            state_set(db, geo_repair_requested='1')
        for key in FIELDS:
            if not known(values[key]) and known(local.get(key)):
                values[key] = local[key]
        attempts = attempts or 0
        outcome, retry_at = 'not_found', 0
        # A new monthly release rechecks negative results locally, without
        # renewing a previously exhausted or definitive online lookup.
        local_only = previous_state in ('partial', 'not_found', 'unresolved')
        if any(not known(values[key]) for key in FIELDS) and not local_only:
            remote, outcome, retry_at, requested = online.lookup(ip, now)
            attempts += int(requested)
            for key in FIELDS:
                if not known(values[key]) and known(remote.get(key)):
                    values[key] = remote[key]
            state_set(db, geo_network_retry_at=online.next_allowed, geo_network_error=online.error)
        if all(known(value) for value in values.values()):
            status = 'found'
        elif outcome == 'retry':
            status = 'retry' if attempts < 3 else 'unresolved'
        elif any(known(value) for value in values.values()):
            status = 'partial'
        else:
            status = 'unresolved' if previous_state == 'unresolved' else 'not_found'
        with db:
            assignments, parameters = [], []
            for key in FIELDS:
                assignments.append(f"{key}=CASE WHEN {key} IS NULL OR trim({key})='' OR lower(trim({key}))='unknown' THEN ? ELSE {key} END")
                parameters.append(values[key])
            db.execute('UPDATE blocked_ips SET ' + ','.join(assignments) + ' WHERE ip=?', (*parameters, ip))
            db.execute('INSERT OR REPLACE INTO geo_lookup VALUES(?,?,?,?,?,?,?,?)',
                       (ip, status, now, retry_at, attempts, release, first_seen or '', online.error if outcome == 'retry' else ''))
    state_set(db, geo_heartbeat=time.time(), geo_error=local_error)
    return len(rows)


def enrich(stop, config, data_dir, db_path):
    db = sqlite3.connect(db_path, timeout=5)
    initialize_geo(db)
    library = LocalGeo(data_dir)
    state = dict(db.execute('SELECT key,value FROM runtime_state'))
    try:
        cooldown = float(state.get('geo_network_retry_at', 0))
    except ValueError:
        cooldown = 0
    online = OnlineFallback(cooldown)
    updater = threading.Thread(target=maintain, args=(stop, config, data_dir, db_path), daemon=True)
    updater.start()
    try:
        while not stop.is_set():
            try:
                count = scan_once(db, library, online, stop=stop)
                stop.wait(.2 if count else 5)
            except (OSError, ValueError, sqlite3.Error) as error:
                print(f'[GEO] {error}', flush=True)
                try:
                    state_set(db, geo_error=str(error), geo_heartbeat=time.time())
                except sqlite3.Error:
                    pass
                stop.wait(5)
    finally:
        updater.join(timeout=1)
        library.close()
        db.close()
