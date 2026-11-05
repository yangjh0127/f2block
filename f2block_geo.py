"""Local IPv4/IPv6 lookup. IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0."""
import contextlib
import csv
import datetime as dt
import gzip
import json
import os
import sqlite3
from pathlib import Path
import tempfile
import time
import urllib.request

from f2block_config import parse_address
from f2block_geopack import Reader, build


@contextlib.contextmanager
def update_lock(directory):
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / '.update.lock').open('a+b') as file:
        try:
            if os.name == 'nt':
                import msvcrt
                file.seek(0)
                if not file.read(1):
                    file.write(b'0')
                    file.flush()
                file.seek(0)
                msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError('IP 库正在更新，请稍后重试') from None
        try:
            yield
        finally:
            if os.name == 'nt':
                file.seek(0)
                msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(file, fcntl.LOCK_UN)


def import_csv(db, kind, compressed, progress):
    """Stream records with bounded memory; big-endian BLOB keys preserve IP order."""
    last = {}
    batch = []
    count = 0
    size = 0
    columns = 8 if kind == 'city' else 4
    sql = f'INSERT INTO {kind} VALUES(' + ','.join('?' for _ in range(6 if kind == 'city' else 5)) + ')'
    with gzip.open(compressed, 'rt', encoding='utf-8', newline='') as source:
        def lines():
            nonlocal size
            while True:
                line = source.readline(65537)
                if not line:
                    break
                size += len(line)
                if len(line) > 65536 or size > 2 * 1024 * 1024 * 1024:
                    raise ValueError('IP 库 CSV 超出大小限制')
                yield line
        for row in csv.reader(lines(), strict=True):
            if len(row) != columns:
                raise ValueError(f'{kind} CSV 字段数量错误：第 {count + 1} 条')
            start, end = parse_address(row[0]), parse_address(row[1])
            if start.version != end.version or int(start) > int(end):
                raise ValueError('IP 库范围无效')
            if int(start) <= last.get(start.version, -1):
                raise ValueError('IP 库范围重叠或顺序错误')
            last[start.version] = int(end)
            if kind == 'city':
                payload = (row[3] or 'Unknown', row[4] or 'Unknown', row[5] or 'Unknown')
            else:
                number = int(row[2])
                if not 0 <= number <= 4294967295:
                    raise ValueError('ASN 编号无效')
                payload = (str(number), row[3])
            batch.append((start.version, start.packed, end.packed, *payload))
            count += 1
            if len(batch) >= 4096:
                db.executemany(sql, batch)
                batch.clear()
                progress()
        db.executemany(sql, batch)
    if set(last) != {4, 6}:
        raise ValueError(f'{kind} IP 库为空或缺少 IPv4/IPv6 数据')
    progress()
    return count


class LocalGeo:
    def __init__(self, data_dir):
        self.directory = Path(data_dir) / 'geo'
        self.db = None
        self.packed = None
        self.invalid = False
        self.signature = None

    def close(self):
        if self.db is not None:
            self.db.close()
        if self.packed is not None:
            self.packed.close()
        self.db = None
        self.packed = None
        self.signature = None

    def reload(self):
        path = self.directory / 'lookup.geo'
        if not path.exists():
            path = self.directory / 'lookup.sqlite'
        stat = path.stat()
        signature = (path.name, stat.st_ino, stat.st_mtime_ns, stat.st_size)
        if self.signature != signature or self.invalid:
            if path.suffix == '.geo':
                new = Reader(path)
                self.close()
                self.packed, self.signature = new, signature
                self.invalid = False
                return
            new = sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
            try:
                if new.execute('PRAGMA user_version').fetchone()[0] != 1:
                    raise ValueError('IP 库格式版本错误')
                for kind in ('city', 'asn'):
                    for version in (4, 6):
                        if not new.execute(f'SELECT 1 FROM {kind} WHERE version=? LIMIT 1', (version,)).fetchone():
                            raise ValueError(f'{kind} IP 库缺少 IPv{version} 数据')
            except Exception:
                new.close()
                raise
            self.close()
            self.db, self.signature = new, signature
            self.invalid = False

    def lookup(self, ip):
        address = parse_address(ip)
        self.reload()
        result = dict(country='Unknown', region='Unknown', city='Unknown', org='Unknown')
        for kind in ('city', 'asn'):
            if self.packed is not None:
                try:
                    row = self.packed.lookup(kind, address)
                except (OSError, ValueError):
                    self.invalid = True
                    raise
            else:
                row = self.db.execute(f'SELECT * FROM {kind} WHERE version=? AND start<=? '
                                      'ORDER BY start DESC LIMIT 1', (address.version, address.packed)).fetchone()
                row = row[3:] if row and address.packed <= row[2] else None
            if row is not None:
                if kind == 'city':
                    result.update(country=row[0], region=row[1], city=row[2])
                else:
                    result['org'] = (' '.join(filter(None, [f'AS{row[0]}' if row[0] != '0' else '', row[1]]))) or 'Unknown'
        return result

    def remove_legacy(self):
        """Only remove obsolete geographic data after the packed reader works."""
        if self.packed is None:
            return
        for name in ('lookup.sqlite', 'city.mmdb', 'asn.mmdb'):
            path = self.directory / name
            if path.exists():
                path.unlink()

    @property
    def generation(self):
        release = self.packed.release if self.packed else self.db.execute('SELECT release FROM metadata').fetchone()[0]
        return f'{release}:{self.signature[2]}:{self.signature[3]}'

    def publish(self, db, staging, month, progress):
        destination = staging / 'lookup.geo'
        build(db, destination, progress)  # Includes full block-by-block validation.
        progress()
        self.close()
        os.replace(destination, self.directory / 'lookup.geo')
        self.reload()
        self.invalid = False
        stamp = staging / 'release.json'
        stamp.write_text(json.dumps({'release': month, 'updated_at': time.time(), 'format': 'F2GEO001'}))
        os.replace(stamp, self.directory / 'release.json')
        self.remove_legacy()

    def update(self, force=False, progress=lambda: None):
        """Build, fully validate and publish one indexed compressed database."""
        with update_lock(self.directory):
            # Recover only our abandoned build files while holding the sole
            # writer lock. Never touch user files or the blacklist database.
            owned = {'lookup.sqlite', 'lookup.geo', 'city.gz', 'asn.gz', 'release.json'}
            for directory in self.directory.iterdir():
                if directory.name.startswith('tmp') and directory.is_dir() and not directory.is_symlink():
                    contents = list(directory.iterdir())
                    if all(item.name in owned and item.is_file() and not item.is_symlink() for item in contents):
                        for item in contents:
                            item.unlink()
                        directory.rmdir()
            month = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m')
            if not force and not self.invalid:
                try:
                    self.reload()
                    release = self.packed.release if self.packed is not None else self.db.execute('SELECT release FROM metadata').fetchone()[0]
                except (OSError, ValueError, sqlite3.Error, TypeError):
                    release = None
                if release == month:
                    if self.packed is None:
                        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                            self.publish(self.db, Path(temporary), month, progress)
                        return month
                    try:
                        self.packed.validate(progress)
                    except ValueError:
                        self.invalid = True
                    if not self.invalid:
                        marker = self.directory / 'release.json'
                        try:
                            valid_marker = json.loads(marker.read_text()).get('release') == month
                        except (OSError, ValueError, AttributeError):
                            valid_marker = False
                        if not valid_marker:
                            with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                                stamp = Path(temporary) / 'release.json'
                                stamp.write_text(json.dumps({'release': month, 'updated_at': time.time(), 'format': 'F2GEO001'}))
                                os.replace(stamp, marker)
                        self.remove_legacy()
                        return month
            with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                staging = Path(temporary)
                path = staging / 'lookup.sqlite'
                with contextlib.closing(sqlite3.connect(path)) as db:
                    db.executescript('PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; '
                                     'PRAGMA cache_size=-8192; PRAGMA user_version=1; '
                                     'CREATE TABLE city(version INTEGER,start BLOB,end BLOB,country TEXT,region TEXT,city TEXT,PRIMARY KEY(version,start)) WITHOUT ROWID; '
                                     'CREATE TABLE asn(version INTEGER,start BLOB,end BLOB,number TEXT,org TEXT,PRIMARY KEY(version,start)) WITHOUT ROWID; '
                                     'CREATE TABLE metadata(release TEXT);')
                    for kind in ('city', 'asn'):
                        url = f'https://download.db-ip.com/free/dbip-{kind}-lite-{month}.csv.gz'
                        request = urllib.request.Request(url, headers={'User-Agent': 'f2block/2 local-geo'})
                        compressed = staging / (kind + '.gz')
                        deadline = time.monotonic() + 600
                        with urllib.request.urlopen(request, timeout=20) as response, compressed.open('wb') as output:
                            size = 0
                            while True:
                                progress()
                                if time.monotonic() > deadline:
                                    raise OSError('IP 库下载超时')
                                chunk = response.read1(256 * 1024) if hasattr(response, 'read1') else response.read(256 * 1024)
                                if not chunk:
                                    break
                                size += len(chunk)
                                if size > 256 * 1024 * 1024:
                                    raise ValueError('IP 库压缩文件过大')
                                output.write(chunk)
                        try:
                            import_csv(db, kind, compressed, progress)
                        except (csv.Error, UnicodeError) as error:
                            raise ValueError(f'IP 库 CSV 解析失败：{error}') from error
                        compressed.unlink()
                    db.execute('INSERT INTO metadata VALUES(?)', (month,))
                    db.commit()
                    if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                        raise ValueError('IP 库完整性检查失败')
                with contextlib.closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as source:
                    self.publish(source, staging, month, progress)
            self.reload()
            return month
