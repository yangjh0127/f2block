#!/usr/bin/env python3
"""Install/upgrade atomically per file; never ship the repository database."""
import argparse
import contextlib
import datetime as dt
import json
import os
from pathlib import Path
import py_compile
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from f2block_config import validate_config, validate_data_dir
from f2block_runtime import initialize

SOURCE = Path(__file__).resolve().parent
FILES = ('f2block', 'f2blockd', 'f2block_legacy', 'f2block_cli.py', 'f2block_tui.py',
         'f2block_config.py', 'f2block_geo.py', 'f2block_geopack.py', 'f2block_enrich.py', 'f2block_runtime.py', 'f2block_detect.py', 'f2block_actions.py', 'f2block_manage.py', 'install.py')
DEPENDENCIES = ('python3', 'bash', 'sqlite3', 'flock', 'ipset', 'iptables', 'ip6tables',
                'systemctl', 'journalctl')
DEFAULTS = {'data_dir': '/var/lib/f2block', 'log_file': '/var/log/auth.log',
            'sync_interval': 30, 'geo_enabled': True, 'geo_update_interval': 86400, 'start_at_end': True}
ENTRY = b'#!/bin/bash\n# f2block managed launcher\nexec /opt/f2block/f2block "$@"\n'


def validate_program_location(root):
    path = Path(root) / 'opt' / 'f2block'
    if path.resolve() != path.parent.resolve() / path.name:
        raise ValueError('程序目录不能是符号链接或目录联接，拒绝修改其他目录中的文件')


def target(root, absolute):
    root = Path(root).resolve()
    candidate = root / absolute.lstrip('/')
    try:
        candidate.resolve().relative_to(root)
    except ValueError:
        raise ValueError(f'安装路径通过链接越过暂存根目录：{candidate}') from None
    return candidate


def write_atomic(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as file:
            temporary = Path(file.name)
            file.write(content)
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def backup_database(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    original = sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True, timeout=30)
    backup = sqlite3.connect(destination)
    try:
        original.backup(backup)
    finally:
        backup.close()
        original.close()


@contextlib.contextmanager
def operation_lock(data_dir, staging):
    if staging:
        yield
        return
    import fcntl
    with open(data_dir / '.operations.lock', 'a') as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        yield


def install(root, source=SOURCE, migrate=None, start=True):
    staging = root != Path('/')
    validate_program_location(root)
    for name in (*FILES, 'f2block.service'):
        if not (source / name).is_file():
            raise ValueError(f'缺少安装文件：{name}')
    # Validate syntax before touching an existing service or install.
    with tempfile.TemporaryDirectory() as directory:
        for name in FILES:
            if name.endswith('.py'):
                py_compile.compile(str(source / name), cfile=str(Path(directory) / (name + 'c')), doraise=True)
    if not staging:
        missing = [name for name in DEPENDENCIES if not shutil.which(name)]
        if missing:
            raise ValueError('请先安装依赖：' + ', '.join(missing))
    config_path = target(root, '/etc/f2block/config.json')
    config = dict(DEFAULTS)
    if config_path.exists():
        supplied = json.loads(config_path.read_text(encoding='utf-8-sig'))
        if not isinstance(supplied, dict):
            raise ValueError('配置文件必须是 JSON 对象')
        config.update(supplied)
    if 'rules' not in config:
        from f2block_detect import default_rules
        if config.get('log_file') == '/var/log/fail2ban.log':
            config['log_file'] = '/var/log/auth.log'
        if not staging and config['log_file'] == '/var/log/auth.log' and not Path(config['log_file']).exists() and Path('/var/log/secure').exists():
            config['log_file'] = '/var/log/secure'
        config['rules'] = default_rules(config['log_file'])
    validate_config(config)
    data_name = config['data_dir']
    if not isinstance(data_name, str) or not data_name.startswith('/') or '..' in Path(data_name).parts:
        raise ValueError('安装配置的 data_dir 必须是绝对 Linux 路径且不含 ..')
    data = target(root, data_name)
    relative_data = data.resolve().relative_to(Path(root).resolve()).as_posix()
    validate_data_dir('/' if relative_data == '.' else '/' + relative_data)
    database = target(root, data_name.rstrip('/') + '/f2block.db')
    program_paths = {name: target(root, '/opt/f2block/' + name) for name in FILES}
    service_path = target(root, '/etc/systemd/system/f2block.service')
    target(root, data_name.rstrip('/') + '/backups')
    migration_db = Path(migrate).resolve() / 'f2block.db' if migrate else None
    if migration_db and not migration_db.is_file():
        raise ValueError(f'迁移源数据库不存在：{migration_db}')
    if migration_db and database.exists():
        raise ValueError('目标数据库已存在，拒绝覆盖；升级时请省略 --migrate-from')
    link = target(root, '/usr/local/bin/f2block')
    if link.exists() and not link.is_symlink() and link.read_bytes() != ENTRY:
        raise ValueError(f'入口已存在且不是链接，拒绝覆盖：{link}')
    if link.is_symlink() and os.readlink(link) != '/opt/f2block/f2block':
        raise ValueError(f'入口链接指向其他程序，拒绝覆盖：{link}')
    if not staging:
        unit = subprocess.run(['systemctl', 'show', '-p', 'LoadState', '--value', 'f2block.service'],
                              capture_output=True, text=True, check=True)
        if unit.stdout.strip() != 'not-found':
            subprocess.run(['systemctl', 'stop', 'f2block.service'], check=True)
    data.mkdir(parents=True, exist_ok=True)
    data.chmod(0o700)
    backup_path = None
    migration_lock = operation_lock(migration_db.parent, staging) if migration_db else contextlib.nullcontext()
    with migration_lock, operation_lock(data, staging):
        if database.exists():
            stamp = dt.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            backup_path = target(root, data_name.rstrip('/') + '/backups/' + stamp)
            backup_database(database, backup_path / 'f2block.db')
            old = target(root, '/opt/f2block')
            if old.exists():
                for name in FILES:
                    if (old / name).is_file():
                        write_atomic(backup_path / 'program' / name, (old / name).read_bytes())
            if config_path.exists():
                write_atomic(backup_path / 'config.json', config_path.read_bytes(), 0o600)
        elif migration_db:
            backup_database(migration_db, database)
        else:
            sqlite3.connect(database).close()
        database.chmod(0o600)
        # Migration is identical to the daemon's and preserves historical records.
        db = sqlite3.connect(database, timeout=30)
        try:
            initialize(db)
        finally:
            db.close()
        for name in FILES:
            content = (source / name).read_bytes().replace(b'\r\n', b'\n')
            write_atomic(program_paths[name], content,
                         0o755 if name in ('f2block', 'f2blockd', 'f2block_legacy') else 0o644)
        write_atomic(config_path, (json.dumps(config, ensure_ascii=False, indent=2) + '\n').encode(), 0o600)
        write_atomic(service_path, (source / 'f2block.service').read_bytes().replace(b'\r\n', b'\n'))
        link.parent.mkdir(parents=True, exist_ok=True)
        if not link.is_symlink():
            write_atomic(link, ENTRY, 0o755)
    if not staging:
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', 'f2block.service'], check=True)
        if start:
            subprocess.run(['systemctl', 'restart', 'f2block.service'], check=True)
    print('安装/升级完成。' + ('（暂存目录，不启动服务）' if staging else '运行 f2block doctor 检查状态。'))
    if backup_path:
        print('升级备份：' + str(backup_path))


def uninstall(root):
    validate_program_location(root)
    # Resolve every removal before stopping services or deleting any files.
    link = target(root, '/usr/local/bin/f2block')
    paths = [target(root, '/opt/f2block/' + name) for name in FILES]
    service = target(root, '/etc/systemd/system/f2block.service')
    if root == Path('/'):
        subprocess.run(['systemctl', 'disable', '--now', 'f2block.service'], check=True)
    if link.is_symlink() and os.readlink(link) == '/opt/f2block/f2block':
        link.unlink()
    elif link.is_file() and not link.is_symlink() and link.read_bytes() == ENTRY:
        link.unlink()
    for path in paths:
        if path.is_file() and not path.is_symlink():
            path.unlink()
    if service.is_file():
        service.unlink()
    if root == Path('/'):
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
    print('已卸载程序与服务。数据库、配置、备份及现有永久防火墙封禁均保留。')


def main(argv=None):
    parser = argparse.ArgumentParser(description='f2block 安装、升级与卸载（保留数据）')
    parser.add_argument('action', choices=('install', 'upgrade', 'uninstall'), nargs='?', default='install')
    parser.add_argument('--migrate-from', type=Path, help='明确指定旧部署目录；不会自动导入仓库数据库')
    parser.add_argument('--no-start', action='store_true')
    parser.add_argument('--root', type=Path, default=Path('/'), help='仅打包/测试用的暂存根目录，不操作系统服务')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if root == Path('/') and (os.name != 'posix' or os.geteuid() != 0):
            raise ValueError('安装到系统目录需要在 Linux 上以 root 运行')
        if args.action == 'uninstall':
            uninstall(root)
        else:
            install(root, migrate=args.migrate_from, start=not args.no_start)
        return 0
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError, py_compile.PyCompileError) as error:
        print('安装失败：' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
