"""Shared configuration for the worker, command line and installer."""
import json
import os
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
CONFIG_KEYS = {'data_dir', 'log_file', 'jail_config', 'sync_interval', 'geo_enabled', 'geo_update_interval', 'rules', 'start_at_end'}
RESERVED_DATA_DIRS = {
    '/', '/bin', '/boot', '/dev', '/etc', '/home', '/lib', '/lib64', '/media',
    '/mnt', '/opt', '/proc', '/root', '/run', '/sbin', '/srv', '/sys', '/tmp',
    '/usr', '/usr/bin', '/usr/local', '/usr/local/bin', '/var', '/var/lib',
    '/var/log', '/var/tmp', '/opt/f2block', '/etc/f2block', '/etc/fail2ban',
}


def validate_data_dir(value):
    path = Path(value)
    if '..' in path.parts or '..' in PurePosixPath(value).parts:
        raise ValueError('data_dir 必须是专用目录，不能包含 ..')
    resolved = path.resolve()
    names = {PurePosixPath(value).as_posix(), resolved.as_posix()}
    if (any((name.rstrip('/') or '/') in RESERVED_DATA_DIRS for name in names) or
            (resolved.anchor and resolved == Path(resolved.anchor))):
        raise ValueError('data_dir 必须是专用子目录，不能指向系统根目录或系统父目录')


def validate_config(config):
    unknown = config.keys() - CONFIG_KEYS
    if unknown:
        raise ValueError('未知配置项: ' + ', '.join(sorted(unknown)))
    for key in ('data_dir', 'log_file') + (('jail_config',) if 'jail_config' in config else ()):
        if not isinstance(config[key], str) or not (Path(config[key]).is_absolute() or PurePosixPath(config[key]).is_absolute()):
            raise ValueError(f'{key} 必须是绝对路径')
    validate_data_dir(config['data_dir'])
    if not isinstance(config.get('start_at_end', True), bool):
        raise ValueError('start_at_end 必须是布尔值')
    from f2block_detect import rules_for
    rules_for(config)
    if not isinstance(config['geo_enabled'], bool):
        raise ValueError('geo_enabled 必须是布尔值')
    geo_interval = config.get('geo_update_interval', 86400)
    if isinstance(geo_interval, bool) or not isinstance(geo_interval, (int, float)) or not 3600 <= geo_interval <= 2678400:
        raise ValueError('geo_update_interval 必须在 3600 到 2678400 秒之间')
    interval = config['sync_interval']
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not 5 <= interval <= 3600:
        raise ValueError('sync_interval 必须在 5 到 3600 秒之间')


def load_config():
    explicit = os.environ.get('F2BLOCK_CONFIG')
    path = Path(explicit or '/etc/f2block/config.json')
    local = (ROOT / 'f2block.db').exists() and not explicit
    config = {
        'data_dir': str(ROOT if local else Path('/var/lib/f2block')),
        'log_file': '/var/log/auth.log',
        'sync_interval': 30,
        'geo_enabled': True,
        'geo_update_interval': 86400,
        'start_at_end': True,
    }
    if explicit or (path.exists() and not local):
        with path.open(encoding='utf-8-sig') as file:
            supplied = json.load(file)
        if not isinstance(supplied, dict):
            raise ValueError('配置文件必须是 JSON 对象')
        config.update(supplied)
    for key, env in (('data_dir', 'F2BLOCK_DATA_DIR'), ('log_file', 'F2BLOCK_LOG_FILE'),
                     ('jail_config', 'F2BLOCK_JAIL_CONFIG')):
        if env in os.environ:
            config[key] = os.environ[env]
    if 'rules' not in config and config['log_file'] == '/var/log/fail2ban.log':
        config['log_file'] = '/var/log/auth.log' if Path('/var/log/auth.log').exists() or not Path('/var/log/secure').exists() else '/var/log/secure'
    validate_config(config)
    config['config_file'] = str(path)
    return config


def parse_address(value):
    """Canonical single host address shared by every management entry point."""
    import ipaddress
    if '%' in str(value):
        raise ValueError('不支持带接口区域标识的 IP 地址')
    return ipaddress.ip_address(value)
