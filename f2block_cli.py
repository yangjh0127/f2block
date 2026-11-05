"""Unified commands and an optional dependency-free terminal dashboard."""
from f2block_config import parse_address
import argparse
import contextlib
import json
import math
import os
from pathlib import Path
import shutil
import shlex
import sqlite3
import subprocess
import sys
import time
import unicodedata

from f2block_config import ROOT, load_config

VERSION = '2.0.0'
TOOLS = ('python3', 'bash', 'sqlite3', 'flock', 'ipset', 'iptables', 'ip6tables',
         'systemctl', 'journalctl')


def clean(value):
    return ''.join(ch if not unicodedata.category(ch).startswith('C') else ' '
                   for ch in str(value if value is not None else '—'))


def ip_value(value):
    try:
        return str(parse_address(value))
    except ValueError:
        raise argparse.ArgumentTypeError('需要有效的 IPv4 或 IPv6 地址') from None


def positive(value):
    try:
        number = int(value)
        if 1 <= number <= 10000:
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError('数量必须在 1 到 10000 之间')


def probe(args, timeout=5):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                                encoding='utf-8', errors='replace')
        return result.returncode, (result.stdout + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, str(error)


class Store:
    def __init__(self, config):
        self.path = Path(config['data_dir']) / 'f2block.db'

    @contextlib.contextmanager
    def connection(self):
        if not self.path.is_file():
            raise FileNotFoundError(f'数据库不存在：{self.path}；请先安装或启动服务')
        db = sqlite3.connect(self.path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    def query(self, sql, params=()):
        with self.connection() as db:
            return [dict(row) for row in db.execute(sql, params)]

    def has(self, name):
        return bool(self.query('SELECT 1 FROM sqlite_master WHERE type="table" AND name=?', (name,)))

    def state(self):
        if not self.has('runtime_state'):
            return {}
        return {row['key']: row['value'] for row in self.query('SELECT * FROM runtime_state')}

    def active_sql(self):
        filters = []
        for table in ('allowlist', 'released_ips'):
            if self.has(table):
                filters.append(f'ip NOT IN (SELECT ip FROM {table})')
        return ' AND '.join(filters) or '1=1'

    def counts(self):
        active = self.query('SELECT COUNT(*) AS n FROM blocked_ips WHERE ' + self.active_sql())[0]['n']
        return {'blocked': active,
                'events': self.query('SELECT COUNT(*) AS n FROM ban_events')[0]['n'],
                'allowed': self.query('SELECT COUNT(*) AS n FROM allowlist')[0]['n'] if self.has('allowlist') else 0,
                'pending': 0}

    def listing(self, limit=50, search='', country=None, jail=None):
        clauses, params = [self.active_sql()], []
        if search:
            clauses.append('(instr(ip,?)>0 OR instr(COALESCE(org,\'\'),?)>0)')
            params.extend((search, search))
        if country:
            clauses.append('UPPER(country)=?')
            params.append(country.upper())
        if jail:
            clauses.append('ip IN (SELECT ip FROM ban_events WHERE jail=?)')
            params.append(jail)
        return self.query('SELECT ip,country,ban_count,last_ban_time FROM blocked_ips WHERE ' +
                          ' AND '.join(clauses) + ' ORDER BY last_ban_time DESC LIMIT ?', params + [limit])

    def details(self, ip):
        blocked = self.query('SELECT * FROM blocked_ips WHERE ip=?', (ip,))
        allowed = bool(self.query('SELECT 1 FROM allowlist WHERE ip=?', (ip,))) if self.has('allowlist') else False
        released = bool(self.query('SELECT 1 FROM released_ips WHERE ip=?', (ip,))) if self.has('released_ips') else False
        return {'ip': ip, 'blocked': bool(blocked) and not allowed and not released,
                'allowed': allowed, 'record': blocked[0] if blocked else None,
                'geography': (self.query('SELECT state,attempted,retry_at,attempts,release,detail FROM geo_lookup WHERE ip=?', (ip,))
                              if self.has('geo_lookup') else []),
                'triggers': self.query('SELECT rule,matched,threshold,window,created FROM detection_bans '
                                       'WHERE ip=? ORDER BY id DESC LIMIT 5', (ip,))
                if self.has('detection_bans') else [],
                'events': self.query('SELECT ban_time,jail FROM ban_events WHERE ip=? ORDER BY id DESC LIMIT 20', (ip,)),
                'actions': self.query('SELECT * FROM admin_events WHERE ip=? ORDER BY id DESC LIMIT 20', (ip,))
                if self.has('admin_events') else []}


def health(config, store):
    checks = []

    def add(name, ok, detail):
        checks.append({'name': name, 'ok': bool(ok), 'detail': str(detail)})

    def age_status(raw):
        try:
            age = time.time() - float(raw)
        except (TypeError, ValueError, OverflowError):
            return False, '时间无效'
        if not math.isfinite(age):
            return False, '时间无效'
        return -5 <= age < 90, f'{int(age)} 秒前'

    for tool in TOOLS:
        location = shutil.which(tool)
        add(tool, location is not None, location or '未安装')
    code, text = probe(['systemctl', 'is-active', 'f2block.service'])
    add('后台服务', code == 0, text)
    from f2block_detect import rules_for
    for source in sorted({rule['log_file'] for rule in rules_for(config)}):
        log = Path(source)
        add('日志读取 ' + source, log.is_file() and os.access(log, os.R_OK), log)
    data = Path(config['data_dir'])
    add('数据目录', data.is_dir() and os.access(data, os.W_OK), data)
    try:
        result = store.query('PRAGMA quick_check')[0]
        add('数据库', next(iter(result.values())) == 'ok', next(iter(result.values())))
        state = store.state()
        heartbeat_ok, heartbeat_detail = age_status(state.get('heartbeat', '0'))
        add('后台心跳', heartbeat_ok, heartbeat_detail if state.get('heartbeat') else '暂无，需启动新版本服务')
        add('后台重试', not state.get('last_error'), state.get('last_error') or '无已报告错误')
        for key, value in state.items():
            if key.startswith('rule_error:') and value:
                add('规则匹配 ' + key.split(':', 1)[1], False, value)
        if config.get('geo_enabled', True):
            if state.get('geo_update_error'):
                add('IP 库更新', False, state['geo_update_error'])
            if state.get('geo_network_error'):
                add('联网兜底', True, '已退避，本地查询继续运行：' + state['geo_network_error'])
            geo_ok, _geo_detail = age_status(state.get('geo_heartbeat', '0'))
            add('地理信息线程', geo_ok and not state.get('geo_error'),
                state.get('geo_error') or ('运行正常' if geo_ok else '尚无心跳或线程已停止'))
        backlog = log_backlog(config, store)
        add('日志进度', backlog.get('bytes') is not None, backlog.get('detail', '未知'))
    except (OSError, sqlite3.Error, ValueError) as error:
        add('数据库/后台状态', False, error)
    code, text = probe(['ipset', 'list', 'f2block'])
    add('ipset 集合', code == 0, 'f2block 已存在' if code == 0 else text)
    code, text = probe(['iptables', '-C', 'INPUT', '-m', 'set', '--match-set', 'f2block', 'src', '-j', 'DROP'])
    add('防火墙规则', code == 0, 'INPUT DROP 已生效' if code == 0 else text)
    code, text = probe(['ipset', 'list', 'f2block6'])
    add('IPv6 ipset 集合', code == 0, 'f2block6 已存在' if code == 0 else text)
    code, text = probe(['ip6tables', '-C', 'INPUT', '-m', 'set', '--match-set', 'f2block6', 'src', '-j', 'DROP'])
    add('IPv6 防火墙规则', code == 0, 'INPUT DROP 已生效' if code == 0 else text)
    return checks


def log_backlog(config, store):
    from f2block_detect import rules_for
    sources = []
    for path in sorted({str(Path(rule['log_file']).resolve()) for rule in rules_for(config)}):
        try:
            cursor = store.query('SELECT * FROM source_cursors WHERE source=?', (path,)) if store.has('source_cursors') else []
            if not cursor and 'rules' not in config and store.has('log_cursor'):
                cursor = store.query('SELECT * FROM log_cursor WHERE id=1')
            stat = Path(path).stat()
            if not cursor:
                size = None
                detail = '尚无消费进度'
            else:
                try:
                    offset = cursor[0]['offset']
                    if isinstance(offset, bool) or (isinstance(offset, float) and
                                                    (not math.isfinite(offset) or not offset.is_integer())):
                        raise ValueError
                    offset = int(offset)
                    if offset < 0:
                        raise ValueError
                except (TypeError, ValueError, OverflowError):
                    size, detail = None, '日志游标无效，等待后台修复'
                    sources.append({'path': path, 'bytes': size, 'detail': detail})
                    continue
                if (str(cursor[0]['device']), str(cursor[0]['inode'])) != (str(stat.st_dev), str(stat.st_ino)):
                    size, detail = None, '日志已轮转，等待后台切换'
                elif offset > stat.st_size:
                    size, detail = None, '日志已截断，等待后台重读'
                else:
                    size = stat.st_size - offset
                    detail = f'待处理 {size} 字节'
            sources.append({'path': path, 'bytes': size, 'detail': detail})
        except (OSError, sqlite3.Error) as error:
            sources.append({'path': path, 'bytes': None, 'detail': str(error)})
    known = all(source['bytes'] is not None for source in sources)
    total = sum(source['bytes'] for source in sources) if known else None
    detail = sources[0]['detail'] if len(sources) == 1 else '; '.join(source['path'] + ': ' + source['detail'] for source in sources)
    return {'bytes': total, 'detail': detail, 'sources': sources}


def status(config, store):
    code, text = probe(['systemctl', 'is-active', 'f2block.service'])
    result = {'version': VERSION, 'policy': '永久封禁', 'service': clean(text),
              'service_active': code == 0, 'database': str(store.path)}
    set_code, _ = probe(['ipset', 'list', 'f2block'])
    rule_code, _ = probe(['iptables', '-C', 'INPUT', '-m', 'set', '--match-set', 'f2block', 'src', '-j', 'DROP'])
    result['firewall'] = {'set_exists': set_code == 0, 'rule_exists': rule_code == 0}
    set6_code, _ = probe(['ipset', 'list', 'f2block6'])
    rule6_code, _ = probe(['ip6tables', '-C', 'INPUT', '-m', 'set', '--match-set', 'f2block6', 'src', '-j', 'DROP'])
    result['firewall'].update(set6_exists=set6_code == 0, rule6_exists=rule6_code == 0)
    try:
        result.update(store.counts())
        result['runtime'] = store.state()
        result['backlog'] = log_backlog(config, store)
    except (OSError, sqlite3.Error) as error:
        result['error'] = str(error)
    return result


def table(rows, columns):
    if not rows:
        print('暂无记录')
        return
    print('  '.join(label for _, label in columns))
    for row in rows:
        print('  '.join(clean(row.get(key, '')) for key, _ in columns))


def describe(detail):
    lines = [f"IP：{detail['ip']}", f"当前封禁：{'是（永久）' if detail['blocked'] else '否'}",
             f"白名单：{'是' if detail['allowed'] else '否'}"]
    if detail['record']:
        for key, label in (('country', '国家'), ('region', '省份/地区'), ('city', '城市'),
                           ('org', '组织'), ('ban_count', '累计次数')):
            lines.append(f"{label}：{clean(detail['record'][key])}")
        from f2block_enrich import LABELS, FIELDS, known
        state = detail.get('geography') or []
        label = LABELS.get(state[0]['state'], '状态未知') if state else (
            '已有地理信息' if all(known(detail['record'].get(key)) for key in FIELDS) else '未查询')
        lines.append('地理信息查询：' + label)
    for trigger in detail.get('triggers', []):
        lines.append(f"触发规则：{clean(trigger['rule'])}，{trigger['window']} 秒内 "
                     f"{trigger['matched']} 次匹配（阈值 {trigger['threshold']}），{clean(trigger['created'])}")
    lines.append('最近封禁历史：')
    lines.extend(f"  {clean(row['ban_time'])}  {clean(row['jail'])}" for row in detail['events'])
    lines.append('最近管理操作：')
    lines.extend(f"  {clean(row['action_time'])}  {clean(row['action'])}  {clean(row.get('reason', ''))}"
                 for row in detail['actions'])
    return lines


def legacy(config, args, reason='', sync_orphans=True):
    """Compatibility adapter for old flags; all operations are now native."""
    from f2block_actions import operate as native_operate, sync
    if args == ['-sync']:
        return sync(config, adopt_orphans=sync_orphans)
    actions = {'-unban': 'unban', '-allow': 'allow', '-allowdel': 'allowdel'}
    if len(args) == 2 and args[0] in actions:
        return native_operate(config, actions[args[0]], args[1], reason)
    raise ValueError('不支持的兼容命令')


def set_members():
    code, output = probe(['ipset', 'list', '-name'])
    if code:
        raise OSError('无法读取 ipset 集合：' + output)
    members = set()
    for name, version in (('f2block', 4), ('f2block6', 6)):
        if name not in output.splitlines():
            continue
        code, snapshot = probe(['ipset', 'save', name])
        if code:
            raise OSError('无法读取 ipset 成员：' + snapshot)
        created = False
        for line in snapshot.splitlines():
            fields = shlex.split(line)
            if fields[:2] == ['create', name]:
                created = True
            elif fields[:2] == ['add', name] and len(fields) >= 3:
                address = parse_address(fields[2])
                if address.version != version:
                    raise ValueError('ipset 地址族不匹配')
                members.add(str(address))
        if not created:
            raise OSError('ipset 返回了无法识别的集合快照')
    return members


def sync_preview(config, store):
    members = set_members()
    active = {row['ip'] for row in store.query('SELECT ip FROM blocked_ips WHERE ' + store.active_sql())}
    released = set()
    for name in ('allowlist', 'released_ips'):
        if store.has(name):
            released.update(row['ip'] for row in store.query('SELECT ip FROM ' + name))
    print('[DRY-RUN] 只读预览，不创建表、锁或防火墙规则')
    for ip in sorted(active - members):
        print('将加入永久黑名单：' + ip)
    for ip in sorted(released & members):
        print('将解除封禁：' + ip)
    for ip in sorted(members - active - released):
        print('将补全孤儿记录：' + ip)
    code, output = probe(['iptables', '-C', 'INPUT', '-m', 'set', '--match-set', 'f2block', 'src', '-j', 'DROP'])
    if code:
        print('防火墙规则缺失或无法读取，实际同步前请核对：' + clean(output))
    code6, output6 = probe(['ip6tables', '-C', 'INPUT', '-m', 'set', '--match-set', 'f2block6', 'src', '-j', 'DROP'])
    if code6:
        print('IPv6 防火墙规则缺失或无法读取：' + clean(output6))
    return 0 if code == 0 and code6 == 0 else 1


def operate(config, store, action, ip, reason=''):
    # CLI argparse canonicalizes its own arguments, but the TUI and callers of
    # this public helper can supply an equivalent noncanonical IPv6 spelling.
    # Use the database key for both the native operation and verification.
    ip = str(parse_address(ip))
    flag = {'unban': '-unban', 'allow': '-allow', 'allowdel': '-allowdel'}[action]
    code = legacy(config, [flag, ip], reason)
    if code:
        return code
    detail = store.details(ip)
    try:
        present = ip in set_members()
    except (OSError, ValueError) as error:
        print('无法确认防火墙状态：' + clean(error), file=sys.stderr)
        return 1
    if action in ('allow', 'unban') and (detail['blocked'] or present):
        print('状态尚未收敛，请执行 f2block doctor 并查看后台日志', file=sys.stderr)
        return 1
    if action == 'allow' and not detail['allowed'] or action == 'allowdel' and detail['allowed']:
        print('白名单状态核验失败', file=sys.stderr)
        return 1
    print('数据库与 ipset 状态已核验，历史流水保留。')
    return 0


def aliases(argv):
    mapping = {'-l': 'list', '-s': 'stats', '-ip': 'info', '-c': 'country', '-j': 'jail',
               '-top': 'top', '-events': 'events', '-unban': 'unban', '-allow': 'allow-add',
               '-allowlist': 'allow-list', '-allowdel': 'allow-remove', '-sync': 'sync', '-export': 'export'}
    if argv and argv[0] == '-h':
        return ['--help']
    if argv and argv[0] in mapping:
        name = mapping[argv[0]]
        rest = argv[1:]
        if name in ('allow-add', 'allow-list', 'allow-remove'):
            return ['allow', name.split('-')[1], *rest]
        return [name, *rest]
    return argv


def inspect_rules(config, args):
    from f2block_detect import rules_for, match_line
    rules = rules_for(config)
    if args.rules_action == 'list':
        table([{'name': rule['name'], 'file': rule['log_file'],
                'threshold': f"{rule['find_time']} 秒内 {rule['max_retry']} 次"} for rule in rules],
              [('name', '规则'), ('file', '日志文件'), ('threshold', '封禁阈值')])
        return 0
    selected = next((rule for rule in rules if rule['name'] == args.name), None)
    if selected is None:
        raise ValueError('未找到启用的规则：' + args.name)
    count = errors = scanned = 0
    with Path(args.file).open(encoding='utf-8', errors='replace') as source:
        for index, line in enumerate(source, 1):
            if index > args.lines:
                break
            scanned += 1
            try:
                match = match_line(selected, line)
            except (ValueError, OSError, OverflowError) as error:
                errors += 1
                print(f'第 {index} 行解析失败：{clean(error)}')
                continue
            if match:
                count += 1
                print(f'第 {index} 行匹配：{match[0]} 时间戳 {match[1]}')
    print(f'只读预检：检查 {scanned} 行，匹配 {count} 行，解析失败 {errors} 行；未执行封禁')
    return 1 if errors else 0


def parser():
    p = argparse.ArgumentParser(prog='f2block', description='永久黑名单管理；不带参数打开终端面板。')
    p.add_argument('--version', action='version', version=VERSION)
    sub = p.add_subparsers(dest='command')
    geo = sub.add_parser('geo', help='管理本地 IP 库').add_subparsers(dest='geo_action', required=True)
    geo.add_parser('update', help='立即重新下载并更新 City 和 ASN 库')
    geo.add_parser('status', help='查看本地库和地理信息查询状态')
    sub.add_parser('menu', help='打开交互面板')
    for name in ('status', 'doctor'):
        sub.add_parser(name, help='查看运行状态' if name == 'status' else '健康检查').add_argument('--json', action='store_true')
    listing = sub.add_parser('list', help='查看当前永久黑名单')
    listing.add_argument('limit', nargs='?', type=positive, default=50)
    listing.add_argument('--search', default='')
    listing.add_argument('--country')
    listing.add_argument('--jail')
    sub.add_parser('info', help='IP 状态与历史').add_argument('ip', type=ip_value)
    for name in ('events', 'history'):
        child = sub.add_parser(name, help='历史封禁事件' if name == 'events' else '管理操作历史')
        child.add_argument('limit', nargs='?', type=positive, default=50)
        child.add_argument('--ip', type=ip_value)
    unban = sub.add_parser('unban', help='解封；未来新 Ban 仍会永久封禁')
    unban.add_argument('ip', type=ip_value)
    unban.add_argument('--reason', default='')
    allow = sub.add_parser('allow', help='白名单管理').add_subparsers(dest='allow_action', required=True)
    allow.add_parser('list')
    for name in ('add', 'remove'):
        child = allow.add_parser(name)
        child.add_argument('ip', type=ip_value)
        child.add_argument('--reason', default='')
    sub.add_parser('sync', help='对账并恢复防火墙').add_argument('--dry-run', action='store_true')
    logs = sub.add_parser('logs', help='查看服务日志（默认实时跟随）')
    logs.add_argument('--lines', type=positive, default=50)
    logs.add_argument('--no-follow', action='store_true')
    sub.add_parser('service', help='管理后台服务').add_argument('action', choices=('start', 'stop', 'restart'))
    for name in ('stats', 'top'):
        sub.add_parser(name)
    for name in ('country', 'jail'):
        sub.add_parser(name).add_argument('value')
    export = sub.add_parser('export', help='导出名单')
    export.add_argument('format', choices=('csv', 'json'))
    export.add_argument('--kind', choices=('blocked', 'allowed'), default='blocked')
    export.add_argument('--output')
    incoming = sub.add_parser('import', help='导入名单；默认仅预览')
    incoming.add_argument('path')
    incoming.add_argument('--kind', choices=('blocked', 'allowed'), required=True)
    incoming.add_argument('--yes', action='store_true')
    incoming.add_argument('--reason', default='名单导入')
    rules = sub.add_parser('rules', help='查看和预检日志规则').add_subparsers(dest='rules_action', required=True)
    rules.add_parser('list')
    check = rules.add_parser('test')
    check.add_argument('name')
    check.add_argument('--file', required=True)
    check.add_argument('--lines', type=positive, default=1000)
    sub.add_parser('dashboard', help='查看总览看板')
    sub.add_parser('uninstall', help='卸载程序，保留数据与封禁').add_argument('--yes', action='store_true')
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(aliases(list(sys.argv[1:] if argv is None else argv)))
    try:
        config = load_config()
        store = Store(config)
        command = args.command
        if command in (None, 'menu'):
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                p.print_help()
                return 0
            from f2block_tui import launch
            return launch(config, store)
        if command == 'geo':
            from f2block_geo import LocalGeo
            geo = LocalGeo(config['data_dir'])
            try:
                if args.geo_action == 'status':
                    from f2block_enrich import LABELS
                    from f2block_enrich import FIELDS
                    complete = ' AND '.join(f"b.{key} IS NOT NULL AND trim(b.{key})!='' AND lower(trim(b.{key}))!='unknown'" for key in FIELDS)
                    states = store.query(f"SELECT CASE WHEN g.state IS NOT NULL THEN g.state WHEN {complete} "
                                         "THEN 'existing' ELSE 'unqueried' END AS state,COUNT(*) AS n "
                                         'FROM blocked_ips b LEFT JOIN geo_lookup g ON g.ip=b.ip GROUP BY 1')
                    path = Path(config['data_dir']) / 'geo' / 'lookup.geo'
                    print(json.dumps(dict(library=str(path), bytes=path.stat().st_size if path.exists() else 0,
                                          states={dict(LABELS, existing='已有信息（历史/导入）', unqueried='未查询').get(row['state'], row['state']): row['n'] for row in states}),
                                     ensure_ascii=False, indent=2))
                    return 0
                release = geo.update(force=True)
                print(f'本地 IP 库已更新：{release}；IP Geolocation by DB-IP (https://db-ip.com)')
            finally:
                geo.close()
            return 0
        if command == 'rules':
            return inspect_rules(config, args)
        if command == 'status':
            result = status(config, store)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(f"f2block {VERSION} · 永久封禁")
                print('服务：' + result['service'])
                firewall = result['firewall']
                print('IPv4/IPv6 防火墙：' + ('正常' if all(firewall.values()) else '异常/无法读取'))
                print(f"黑名单：{result.get('blocked', '—')}  白名单：{result.get('allowed', '—')}  历史事件：{result.get('events', '—')}")
                from f2block_detect import rules_for
                print(f'启用日志规则：{len(rules_for(config))} 条')
                state = result.get('runtime', {})
                age = time.time() - float(state.get('heartbeat', '0'))
                print('心跳：' + ('正常' if -5 <= age < 90 else '异常/尚无'))
                print('最后处理：' + clean(state.get('last_processed', '尚无')))
                print('日志进度：' + clean(result.get('backlog', {}).get('detail', '未知')))
                print('最近对账：' + clean(state.get('last_sync', '尚无')))
                print('最近错误：' + clean(state.get('last_error') or result.get('error') or '无已报告错误'))
                if config.get('geo_enabled', True):
                    print('地理信息错误：' + clean(state.get('geo_error') or '无已报告错误'))
                    print('IP 库更新错误：' + clean(state.get('geo_update_error') or '无已报告错误'))
            state = result.get('runtime', {})
            age = time.time() - float(state.get('heartbeat', '0'))
            geo_age = time.time() - float(state.get('geo_heartbeat', '0'))
            geo_ok = (not config.get('geo_enabled', True) or
                      (-5 <= geo_age < 90 and not state.get('geo_error')))
            return 0 if (result['service_active'] and not result.get('error') and
                         all(result['firewall'].values()) and -5 <= age < 90 and not state.get('last_error') and
                         result.get('pending', 0) == 0 and geo_ok) else 1
        if command == 'doctor':
            checks = health(config, store)
            if args.json:
                print(json.dumps(checks, ensure_ascii=False, indent=2))
            else:
                for check in checks:
                    print(f"[{'正常' if check['ok'] else '异常'}] {check['name']}：{clean(check['detail'])}")
            return 0 if all(check['ok'] for check in checks) else 1
        if command == 'list':
            table(store.listing(args.limit, args.search, args.country, args.jail),
                  [('ip', 'IP'), ('country', '国家'), ('ban_count', '次数'), ('last_ban_time', '最后封禁')])
            return 0
        if command == 'info':
            print('\n'.join(describe(store.details(args.ip))))
            return 0
        if command in ('events', 'history'):
            name = 'ban_events' if command == 'events' else 'admin_events'
            rows = store.query('SELECT * FROM ' + name + (' WHERE ip=?' if args.ip else '') + ' ORDER BY id DESC LIMIT ?',
                               ([args.ip] if args.ip else []) + [args.limit]) if store.has(name) else []
            columns = [('ban_time', '时间'), ('ip', 'IP'), ('jail', 'jail')] if command == 'events' else [
                ('action_time', '时间'), ('ip', 'IP'), ('action', '操作'), ('reason', '原因')]
            table(rows, columns)
            return 0
        if command == 'unban':
            return operate(config, store, 'unban', args.ip, args.reason)
        if command == 'allow':
            if args.allow_action == 'list':
                table(store.query('SELECT * FROM allowlist ORDER BY added_at DESC'), [('ip', 'IP'), ('added_at', '加入时间')])
                return 0
            return operate(config, store, 'allow' if args.allow_action == 'add' else 'allowdel', args.ip, args.reason)
        if command == 'stats':
            counts = store.counts()
            print(f"永久黑名单：{counts['blocked']}  白名单：{counts['allowed']}  历史事件：{counts['events']}")
            table(store.query('SELECT country,COUNT(*) AS n FROM blocked_ips WHERE ' + store.active_sql() +
                              ' GROUP BY country ORDER BY n DESC LIMIT 10'), [('country', '国家'), ('n', 'IP 数')])
            return 0
        if command in ('top', 'country'):
            if command == 'country':
                rows = store.listing(10000, country=args.value)
            else:
                rows = store.query('SELECT ip,country,ban_count,last_ban_time FROM blocked_ips WHERE ' +
                                   store.active_sql() + ' ORDER BY ban_count DESC LIMIT 20')
            table(rows, [('ip', 'IP'), ('country', '国家'), ('ban_count', '次数'), ('last_ban_time', '最后封禁')])
            return 0
        if command == 'jail':
            table(store.query('SELECT ip,ban_time,jail FROM ban_events WHERE jail=? ORDER BY id DESC LIMIT 100', (args.value,)),
                  [('ban_time', '时间'), ('ip', 'IP'), ('jail', 'jail')])
            return 0
        if command == 'dashboard':
            from f2block_manage import overview
            print('\n'.join(clean(line) for line in overview(config, store)))
            return 0
        if command == 'export':
            from f2block_manage import export_lists
            export_lists(store, args.format, args.kind, args.output)
            return 0
        if command == 'import':
            from f2block_manage import read_import, import_lists
            addresses, duplicates = read_import(args.path)
            print(f'预览：{len(addresses)} 个有效 IP，重复 {duplicates} 条；目标 {args.kind}，合并导入')
            print('黑名单导入跳过白名单和人工解封；保留文件中的地理信息，补齐已有记录的缺失字段，不恢复历史计数。')
            if not args.yes:
                print('尚未写入；确认后加 --yes 执行')
                return 0
            return import_lists(config, store, addresses, args.kind, args.reason)
        if command == 'uninstall':
            from f2block_manage import uninstall_program
            return uninstall_program(args.yes)
        if command == 'logs':
            return subprocess.call(['journalctl', '-u', 'f2block.service', '-n', str(args.lines),
                                    '--no-pager', *([] if args.no_follow else ['-f'])])
        if command == 'service':
            return subprocess.call(['systemctl', args.action, 'f2block.service'])
        if args.dry_run:
            return sync_preview(config, store)
        return legacy(config, ['-sync'])
    except (OSError, sqlite3.Error, ValueError, ImportError, EOFError, RuntimeError, subprocess.SubprocessError) as error:
        print('f2block：' + clean(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
