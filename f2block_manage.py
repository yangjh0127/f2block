"""Portable list exchange and read-only terminal overview."""
from f2block_config import parse_address
import csv
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import tempfile
import time


def overview(config, store):
    from f2block_cli import status
    result = status(config, store)
    counts = store.counts()
    state = result.get('runtime', {})
    age = time.time() - float(state.get('heartbeat', '0'))
    lines = [f"当前黑名单 {counts['blocked']}    白名单 {counts['allowed']}    历史封禁 {counts['events']}",
             f"服务：{result['service']}    检测：本地日志规则",
             '后台心跳：' + ('正常' if -5 <= age < 90 else '异常/尚无'),
             '防火墙：' + ('正常' if all(result['firewall'].values()) else '异常/无法读取'),
             '日志：' + result.get('backlog', {}).get('detail', '未知'),
             '最近对账：' + state.get('last_sync', '尚无'),
             '最近错误：' + (state.get('last_error') or state.get('geo_error') or '无已报告错误'),
             '最近 7 天封禁事件（服务器本地日期）：']
    today = dt.date.today()
    first = today - dt.timedelta(days=6)
    rows = store.query("SELECT substr(ban_time,1,10) AS day,COUNT(*) AS n FROM ban_events "
                       "WHERE substr(ban_time,1,10)>=? AND substr(ban_time,1,10)<=? GROUP BY day",
                       (first.isoformat(), today.isoformat()))
    days = {row['day']: row['n'] for row in rows}
    peak = max(days.values(), default=1) or 1
    for offset in range(7):
        day = (first + dt.timedelta(days=offset)).isoformat()
        n = days.get(day, 0)
        lines.append(f"  {day} {n:>6}  " + '#' * (max(1, n * 24 // peak) if n else 0))
    lines.append('当前黑名单来源国家 Top 5：')
    countries = store.query("SELECT COALESCE(NULLIF(country,''),'Unknown') AS country,COUNT(*) AS n "
                            'FROM blocked_ips WHERE ' + store.active_sql() +
                            ' GROUP BY 1 ORDER BY n DESC, country LIMIT 5')
    lines.extend(f"  {row['country']}  {row['n']}" for row in countries)
    if not countries:
        lines.append('  暂无数据')
    lines.append('历史封禁规则 Top 5：')
    lines.extend(f"  {row['jail'] or 'Unknown'}  {row['n']}" for row in store.query(
        'SELECT jail,COUNT(*) AS n FROM ban_events GROUP BY jail ORDER BY n DESC LIMIT 5'))
    return lines


def export_lists(store, format='json', kind='blocked', destination=None):
    if format not in ('csv', 'json') or kind not in ('blocked', 'allowed'):
        raise ValueError('不支持的导出格式或名单类型')
    rows = store.query('SELECT * FROM allowlist ORDER BY ip' if kind == 'allowed' else
                       'SELECT * FROM blocked_ips WHERE ' + store.active_sql() + ' ORDER BY ip')
    path = Path(destination).expanduser() if destination else Path.cwd() / (
        'f2block_' + kind + '_' + dt.datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '.' + format)
    # Build the complete file beside the destination, then publish it in one
    # rename.  A killed process or a full filesystem must never leave a file
    # that looks like a successful export.  Keep the historical no-overwrite
    # contract for an explicitly supplied destination.
    if os.path.lexists(path):
        raise FileExistsError(path)
    temporary = None
    try:
        fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent), text=True)
        os.close(fd)
        temporary = Path(name)
        os.chmod(temporary, 0o600)
        with temporary.open('w', encoding='utf-8', newline='') as file:
            if format == 'json':
                json.dump(rows, file, ensure_ascii=False, indent=2)
            else:
                columns = ('ip', 'added_at') if kind == 'allowed' else (
                    'ip', 'country', 'region', 'city', 'org', 'first_seen', 'last_ban_time', 'ban_count')
                writer = csv.DictWriter(file, fieldnames=columns)
                writer.writeheader()
                writer.writerows(rows)
            file.flush()
            os.fsync(file.fileno())
        # link(2)/CreateHardLink creates the destination only when its name is
        # absent, so a concurrent creator or dangling symlink cannot be
        # overwritten by the publish step.
        os.link(temporary, path)
        temporary.unlink()
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
    print(f'已导出：{path.resolve()}（{len(rows)} 条）')
    return path


GEO_FIELDS = ('country', 'region', 'city', 'org')


class ImportedAddresses(list):
    """Keep the address-list API while carrying optional portable metadata."""
    def __init__(self, addresses, geography):
        super().__init__(addresses)
        self.geography = geography


def read_import(path):
    path = Path(path).expanduser()
    if path.is_symlink():
        raise ValueError('导入文件不能是符号链接')
    try:
        with path.open(encoding='utf-8-sig', newline='') as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('导入路径必须是普通文件')
            if info.st_size > 16 * 1024 * 1024:
                raise ValueError('导入文件不能超过 16 MiB')
            if path.suffix.lower() == '.json':
                try:
                    rows = json.load(file)
                except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, MemoryError) as error:
                    raise ValueError('JSON 导入文件格式无效') from error
            elif path.suffix.lower() == '.csv':
                original_limit = csv.field_size_limit()
                csv.field_size_limit(1024 * 1024)
                try:
                    reader = csv.DictReader(file)
                    if not reader.fieldnames or 'ip' not in reader.fieldnames:
                        raise ValueError('CSV 必须含 ip 表头')
                    rows = list(reader)
                except (csv.Error, UnicodeDecodeError) as error:
                    raise ValueError('CSV 导入文件格式无效或字段过大') from error
                finally:
                    csv.field_size_limit(original_limit)
            else:
                raise ValueError('请选择 CSV 或 JSON 文件')
    except OSError:
        raise
    if not isinstance(rows, list) or len(rows) > 10000:
        raise ValueError('文件必须是记录数组，最多 10000 条')
    addresses = set()
    geography = {}
    for index, row in enumerate(rows, 1):
        try:
            if not isinstance(row, dict) or not isinstance(row.get('ip'), str):
                raise ValueError
            ip = str(parse_address(row['ip']))
            addresses.add(ip)
        except (ValueError, KeyError, TypeError, ipaddress.AddressValueError):
            raise ValueError(f'第 {index} 条记录缺少有效 IPv4 或 IPv6 地址') from None
        fields = geography.setdefault(ip, {})
        for key in GEO_FIELDS:
            value = row.get(key)
            if value is None:
                continue
            if not isinstance(value, str) or len(value) > 4096:
                raise ValueError(f'第 {index} 条记录的 {key} 必须是最多 4096 字符的文本')
            value = value.strip()
            if value and value.casefold() != 'unknown':
                fields.setdefault(key, value)
    return ImportedAddresses(sorted(addresses), geography), len(rows) - len(addresses)


def import_lists(config, store, addresses, kind, reason='名单导入'):
    from f2block_cli import operate, legacy
    from f2block_runtime import locked, initialize
    if kind not in ('blocked', 'allowed'):
        raise ValueError('不支持的名单类型')
    geography = getattr(addresses, 'geography', {})
    addresses = sorted({str(parse_address(ip)) for ip in addresses})
    if not store.path.is_file():
        raise ValueError('数据库不存在，请先安装')
    if kind == 'allowed':
        failed = 0
        succeeded = 0
        for ip in addresses:
            try:
                code = operate(config, store, 'allow', ip, reason)
            except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
                code = 1
                print(f'白名单导入 {ip} 失败：{error}')
            if code:
                failed += 1
            else:
                succeeded += 1
        print(f'白名单导入完成：{succeeded} 成功，{failed} 未完全成功；可重试')
        return 1 if failed else 0
    added = skipped = enriched = 0
    with locked(Path(config['data_dir']) / '.operations.lock'):
        db = sqlite3.connect(store.path, timeout=30)
        try:
            initialize(db)
            with db:
                for ip in addresses:
                    # Never undo a manual release or an existing whitelist during a merge.
                    if db.execute('SELECT ip FROM allowlist WHERE ip=? UNION SELECT ip FROM released_ips WHERE ip=?',
                                  (ip, ip)).fetchone():
                        skipped += 1
                        continue
                    stamp = dt.datetime.now().isoformat(' ', timespec='microseconds')
                    fields = geography.get(ip, {})
                    values = tuple(fields.get(key, 'Unknown') for key in GEO_FIELDS)
                    changed = db.execute('INSERT OR IGNORE INTO blocked_ips '
                                         '(ip,country,region,city,org,first_seen,last_ban_time,ban_count) '
                                         'VALUES(?,?,?,?,?,?,?,0)', (ip, *values, stamp, stamp)).rowcount
                    if changed:
                        added += 1
                        db.execute('INSERT INTO admin_events(ip,action,action_time,reason) VALUES(?,?,?,?)',
                                   (ip, 'import', stamp, reason))
                    else:
                        skipped += 1
                        old = db.execute('SELECT country,region,city,org FROM blocked_ips WHERE ip=?', (ip,)).fetchone()
                        merged = tuple(fields.get(key, previous) if previous is None or not str(previous).strip() or
                                       str(previous).strip().casefold() == 'unknown' else previous
                                       for key, previous in zip(GEO_FIELDS, old))
                        if merged != old:
                            db.execute('UPDATE blocked_ips SET country=?,region=?,city=?,org=? WHERE ip=?', (*merged, ip))
                            enriched += 1
                            db.execute('DELETE FROM geo_lookup WHERE ip=?', (ip,))
                    # A previous lookup attempt for a released/reimported address
                    # must not postpone local enrichment for another 24 hours.
                    if changed and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='geo_attempts'").fetchone():
                        db.execute('DELETE FROM geo_attempts WHERE ip=?', (ip,))
                    if changed:
                        db.execute('DELETE FROM geo_lookup WHERE ip=?', (ip,))
        finally:
            db.close()
    print(f'已合并：新增 {added}，跳过 {skipped}（已有记录、白名单或人工解封），补齐地理信息 {enriched}；历史计数不导入')
    # Import is a one-way desired-state update.  A stale, unrelated ipset
    # member must not be adopted as a new database ban while reconciling it.
    code = legacy(config, ['-sync'], sync_orphans=False)
    if code:
        print('名单已保存，防火墙同步未完全成功；后台会重试，也可运行 f2block sync')
    return code


def uninstall_program(confirmed=False):
    if not confirmed:
        raise ValueError('卸载需 --yes；保留数据、配置、备份和现有永久防火墙封禁')
    import install
    return install.main(['uninstall'])
