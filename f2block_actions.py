"""Native database/firewall management without an external detector."""
import datetime as dt
from pathlib import Path
import sqlite3

from f2block_config import parse_address
from f2block_runtime import initialize, locked, reconcile, run, ban_set


def open_database(config):
    path = Path(config['data_dir']) / 'f2block.db'
    if not path.is_file():
        raise FileNotFoundError('数据库不存在，请先安装或启动服务')
    return sqlite3.connect(path, timeout=30)


def operate(config, action, ip, reason=''):
    from f2block_cli import probe
    ip = str(parse_address(ip))
    if action not in ('allow', 'allowdel', 'unban'):
        raise ValueError('不支持的管理操作')
    with locked(Path(config['data_dir']) / '.operations.lock'):
        db = open_database(config)
        try:
            initialize(db)
            now = dt.datetime.now().isoformat(' ', timespec='microseconds')
            with db:
                was_allowed = db.execute('SELECT 1 FROM allowlist WHERE ip=?', (ip,)).fetchone()
                if action == 'allow':
                    db.execute('INSERT OR IGNORE INTO allowlist VALUES(?,?)', (ip, now))
                elif action == 'allowdel':
                    db.execute('DELETE FROM allowlist WHERE ip=?', (ip,))
                if action in ('allow', 'unban') or was_allowed:
                    db.execute('INSERT OR REPLACE INTO released_ips VALUES(?,?)', (ip, now))
                    db.execute('DELETE FROM blocked_ips WHERE ip=?', (ip,))
                db.execute('DELETE FROM detection_hits WHERE ip=?', (ip,))
                # Obsolete delivery tasks from older installations are never sent.
                db.execute('DELETE FROM f2b_pending WHERE ip=?', (ip,))
                db.execute('DELETE FROM whitelist_jails WHERE ip=?', (ip,))
                db.execute('INSERT INTO admin_events(ip,action,action_time,reason) VALUES(?,?,?,?)',
                           (ip, action, now, reason))
            if action in ('allow', 'unban'):
                code, names = probe(['ipset', 'list', '-name'])
                if code:
                    raise OSError('无法核验防火墙集合：' + names)
                name = ban_set(ip)
                if name in names.splitlines():
                    run('ipset', 'del', name, ip, '-exist')
        finally:
            db.close()
    return 0


def sync(config, adopt_orphans=True):
    from f2block_cli import set_members
    with locked(Path(config['data_dir']) / '.operations.lock'):
        db = open_database(config)
        try:
            initialize(db)
            members = set_members() if adopt_orphans else set()
            with db:
                now = dt.datetime.now().isoformat(' ', timespec='microseconds')
                for ip in members:
                    if db.execute('SELECT 1 FROM allowlist WHERE ip=? UNION SELECT 1 FROM released_ips WHERE ip=?',
                                  (ip, ip)).fetchone():
                        continue
                    changed = db.execute("INSERT OR IGNORE INTO blocked_ips(ip,country,first_seen,last_ban_time,ban_count) "
                                         "VALUES(?,'Unknown',?,?,0)", (ip, now, now)).rowcount
                    if changed:
                        db.execute('INSERT INTO admin_events(ip,action,action_time,reason) VALUES(?,?,?,?)',
                                   (ip, 'sync', now, '防火墙孤儿记录'))
            reconcile(db)
        finally:
            db.close()
    print('数据库与 IPv4/IPv6 防火墙已同步')
    return 0
