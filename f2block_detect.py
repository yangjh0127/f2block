"""Configurable local-log detection; thresholds and receipts survive restart."""
import datetime as dt
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import time

from f2block_config import parse_address


def default_rules(path='/var/log/auth.log'):
    return [{
        'name': 'sshd', 'log_file': path, 'max_retry': 3, 'find_time': 3600,
        'pattern': r'^(?P<time>\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:-session)?\[\d+\]: Failed (?:password|publickey) for (?:invalid user )?\S+ from (?P<ip>\S+) port \d+(?: ssh\d+)?(?: \[preauth\])?\s*$',
    }]


def compile_rules(items):
    if not isinstance(items, list) or not 1 <= len(items) <= 128:
        raise ValueError('rules 必须是含 1 到 128 条规则的数组')
    result, names = [], set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('每条规则必须是对象')
        unknown = item.keys() - {'name', 'log_file', 'pattern', 'max_retry', 'find_time', 'time_format', 'enabled'}
        if unknown:
            raise ValueError('未知规则配置项：' + ', '.join(sorted(unknown)))
        rule = dict(item)
        name = rule.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name) or name in names:
            raise ValueError('规则名须为唯一的 1 到 64 位字母、数字、下划线或短横线')
        names.add(name)
        path = rule.get('log_file')
        if not isinstance(path, str) or not (Path(path).is_absolute() or PurePosixPath(path).is_absolute()):
            raise ValueError(f'{name}: log_file 必须是绝对路径')
        for key, low, high in (('max_retry', 1, 100000), ('find_time', 1, 604800)):
            value = rule.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f'{name}: {key} 必须是 {low} 到 {high} 的整数')
        if not isinstance(rule.get('enabled', True), bool):
            raise ValueError(f'{name}: enabled 必须为布尔值')
        if not isinstance(rule.get('time_format', 'auto'), str):
            raise ValueError(f'{name}: time_format 必须是字符串')
        pattern = rule.get('pattern')
        if not isinstance(pattern, str) or len(pattern) > 8192:
            raise ValueError(f'{name}: pattern 必须是最多 8192 字符的正则表达式')
        try:
            regex = re.compile(pattern)
        except re.error as error:
            raise ValueError(f'{name}: 正则表达式无效：{error}') from error
        if not {'ip', 'time'} <= regex.groupindex.keys():
            raise ValueError(f'{name}: pattern 必须包含 (?P<ip>...) 和 (?P<time>...) 捕获组')
        fingerprint = hashlib.sha256(json.dumps(rule, sort_keys=True).encode()).hexdigest()
        rule.update(regex=regex, fingerprint=fingerprint)
        if rule.get('enabled', True):
            result.append(rule)
    if not result:
        raise ValueError('必须启用至少一条日志规则')
    return result


def rules_for(config):
    return compile_rules(config.get('rules', default_rules(config.get('log_file', '/var/log/auth.log'))))


def event_time(raw, format, now):
    if raw is None:
        return now
    if format == 'unix':
        value = float(raw)
    elif format != 'auto':
        value = dt.datetime.strptime(raw, format).timestamp()
    else:
        try:
            value = dt.datetime.fromisoformat(raw.replace(',', '.').replace('Z', '+00:00')).timestamp()
        except ValueError:
            # RFC3164 omits the year. Choose the nearest year at New Year.
            months = {name: index for index, name in enumerate(
                ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'), 1)}
            parts = raw.split()
            if len(parts) != 3 or parts[0] not in months:
                raise ValueError('无法识别日志时间，请配置 time_format')
            hour, minute, second = map(int, parts[2].split(':'))
            year = dt.datetime.fromtimestamp(now).year
            choices = []
            for candidate in (year - 1, year, year + 1):
                try:
                    choices.append(dt.datetime(candidate, months[parts[0]], int(parts[1]), hour, minute, second).timestamp())
                except ValueError:
                    continue
            if not choices:
                raise ValueError('无效的日志日期')
            value = min(choices, key=lambda stamp: abs(stamp - now))
    if not math.isfinite(value):
        raise ValueError('无效的日志时间')
    return value


def match_line(rule, line, now=None):
    match = rule['regex'].search(line.rstrip('\r\n'))
    if not match:
        return None
    ip = str(parse_address(match.group('ip')))
    now = time.time() if now is None else now
    raw_time = match.group('time')
    if raw_time is None:
        raise ValueError('日志匹配缺少时间')
    stamp = event_time(raw_time, rule.get('time_format', 'auto'), now)
    return ip, stamp


def process_line(db, rules, line, receipt, now=None):
    from f2block_runtime import save_ban, deliver_ban, _local_time
    now = time.time() if now is None else now
    bans = set()
    with db:
        for rule in rules:
            try:
                matched = match_line(rule, line, now)
            except (ValueError, OverflowError, OSError) as error:
                db.execute("INSERT OR REPLACE INTO runtime_state VALUES(?,?)",
                           ('rule_error:' + rule['name'], str(error)))
                continue
            if matched is None:
                continue
            db.execute("DELETE FROM runtime_state WHERE key=?", ('rule_error:' + rule['name'],))
            ip, stamp = matched
            # Old backlog and future timestamps must not cause current bans.
            if not now - rule['find_time'] <= stamp <= now + 5:
                continue
            if db.execute('SELECT 1 FROM allowlist WHERE ip=?', (ip,)).fetchone():
                continue
            released = db.execute('SELECT released_at FROM released_ips WHERE ip=?', (ip,)).fetchone()
            if released and stamp <= _local_time(released[0]).timestamp():
                continue
            if db.execute('SELECT 1 FROM blocked_ips WHERE ip=?', (ip,)).fetchone():
                continue
            key = rule['fingerprint']
            inserted = db.execute('INSERT OR IGNORE INTO detection_hits(rule,receipt,ip,stamp) VALUES(?,?,?,?)',
                                  (key, receipt, ip, stamp)).rowcount
            if not inserted:
                continue
            db.execute('DELETE FROM detection_hits WHERE rule=? AND stamp<?', (key, now - rule['find_time']))
            count = db.execute('SELECT COUNT(*) FROM detection_hits WHERE rule=? AND ip=? AND stamp>=?',
                               (key, ip, now - rule['find_time'])).fetchone()[0]
            if count >= rule['max_retry']:
                # Use a stable receipt as part of the event key; replay cannot recount.
                raw_time = dt.datetime.fromtimestamp(max(now, stamp)).isoformat(' ', timespec='microseconds')
                save_ban(db, ip, rule['name'], raw_time)
                bans.add(ip)
                db.execute('INSERT INTO detection_bans(ip,rule,matched,threshold,window,created) VALUES(?,?,?,?,?,?)',
                           (ip, rule['name'], count, rule['max_retry'], rule['find_time'], raw_time))
    # The desired state and threshold decision commit together before delivery.
    for ip in bans:
        deliver_ban(ip)
    return bans


def prune(db, rules, now=None):
    now = time.time() if now is None else now
    active = {rule['fingerprint']: rule['find_time'] for rule in rules}
    with db:
        for (key,) in db.execute('SELECT DISTINCT rule FROM detection_hits').fetchall():
            if key not in active:
                db.execute('DELETE FROM detection_hits WHERE rule=?', (key,))
            else:
                db.execute('DELETE FROM detection_hits WHERE rule=? AND stamp<?', (key, now - active[key]))
