import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import types
import unittest
from unittest.mock import patch

import f2block_cli as cli
import f2block_config as config_module
import f2block_runtime as runtime
import f2block_tui as tui
import install as installer


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.config = dict(data_dir=str(self.directory), log_file=str(self.directory / 'log'),
                           jail_config=str(self.directory / 'jail.local'), sync_interval=30, geo_enabled=False)
        self.store = cli.Store(self.config)
        self.db = sqlite3.connect(self.store.path)
        self.addCleanup(self.db.close)
        runtime.initialize(self.db)
        with patch.object(runtime, 'run'):
            runtime.record(self.db, '2026-10-18 12:00:00,001 x [sshd] Ban 203.0.113.7')
        self.db.execute("INSERT INTO runtime_state VALUES('heartbeat',?)", (str(time.time()),))
        self.db.commit()

    def test_old_flags_keep_their_meaning(self):
        for old, expected in [(['-l', '20'], ['list', '20']),
                              (['-allow', '203.0.113.7'], ['allow', 'add', '203.0.113.7']),
                              (['-allowdel', '203.0.113.7'], ['allow', 'remove', '203.0.113.7']),
                              (['-sync', '--dry-run'], ['sync', '--dry-run'])]:
            self.assertEqual(cli.aliases(old), expected)

    def test_list_filters_are_parameterized(self):
        self.assertEqual(len(self.store.listing(search='203.0', country='unknown', jail='sshd')), 1)
        self.assertEqual(self.store.listing(search="' OR 1=1 --"), [])

    def test_details_include_history_after_release(self):
        with self.db:
            self.db.execute("INSERT INTO released_ips VALUES('203.0.113.7','2026-10-18 12:01:00')")
            self.db.execute("DELETE FROM blocked_ips WHERE ip='203.0.113.7'")
            self.db.execute("INSERT INTO admin_events(ip,action,action_time,reason) VALUES(?,?,?,?)",
                            ('203.0.113.7', 'unban', '2026-10-18 12:01:00', "operator's test"))
        detail = self.store.details('203.0.113.7')
        self.assertFalse(detail['blocked'])
        self.assertEqual(len(detail['events']), 1)
        self.assertEqual(detail['actions'][0]['reason'], "operator's test")
        self.assertEqual(self.store.counts()['blocked'], 0)

    def test_read_commands_do_not_modify_database(self):
        before = self.store.path.read_bytes()
        output = io.StringIO()
        with patch.object(cli, 'load_config', return_value=self.config), contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(['list']), 0)
            self.assertEqual(cli.main(['info', '203.0.113.7']), 0)
            self.assertEqual(cli.main(['events']), 0)
            self.assertEqual(cli.main(['history']), 0)
            self.assertEqual(cli.main(['stats']), 0)
            self.assertEqual(cli.main(['top']), 0)
            self.assertEqual(cli.main(['country', 'CN']), 0)
            self.assertEqual(cli.main(['jail', 'sshd']), 0)
        self.assertEqual(before, self.store.path.read_bytes())
        self.assertIn('203.0.113.7', output.getvalue())

    def test_missing_database_query_does_not_create_file(self):
        missing = cli.Store(dict(self.config, data_dir=str(self.directory / 'missing')))
        with self.assertRaises(FileNotFoundError):
            missing.counts()
        self.assertFalse(missing.path.exists())

    def test_status_never_calls_unknown_state_healthy(self):
        with patch.object(cli, 'probe', return_value=(127, 'not available')):
            result = cli.status(self.config, self.store)
        self.assertFalse(result['service_active'])
        self.assertEqual(result['blocked'], 1)

    def test_doctor_reports_missing_firewall(self):
        with patch.object(cli.shutil, 'which', return_value=None), patch.object(cli, 'probe', return_value=(127, 'missing')):
            checks = cli.health(self.config, self.store)
        self.assertTrue(any(not check['ok'] and check['name'] == '防火墙规则' for check in checks))

    def test_backlog_uses_confirmed_offset(self):
        path = Path(self.config['log_file'])
        path.write_bytes(b'first\nsecond\n')
        reader = runtime.LogReader(path, self.db)
        try:
            reader.read()
            reader.acknowledge()
            reader.read()
            self.assertEqual(cli.log_backlog(self.config, self.store)['bytes'], len(b'second\n'))
        finally:
            reader.close()

    def test_new_reason_is_passed_without_shell_interpolation(self):
        reason = "operator's $(touch never)"
        import f2block_actions as actions
        with patch.object(actions, 'locked', return_value=contextlib.nullcontext()), \
             patch.object(cli, 'probe', return_value=(0, '')), \
             patch.object(cli.subprocess, 'run') as run:
            cli.legacy(self.config, ['-unban', '203.0.113.7'], reason)
        run.assert_not_called()
        self.assertEqual(self.db.execute('SELECT reason FROM admin_events ORDER BY id DESC LIMIT 1').fetchone()[0], reason)

    def test_config_and_environment_overrides(self):
        config_file = self.directory / 'config.json'
        config_file.write_text(json.dumps(self.config), encoding='utf-8')
        with patch.dict(os.environ, {'F2BLOCK_CONFIG': str(config_file), 'F2BLOCK_DATA_DIR': str(self.directory / 'other')}):
            loaded = config_module.load_config()
        self.assertFalse(loaded['geo_enabled'])
        self.assertEqual(loaded['data_dir'], str(self.directory / 'other'))
        config_file.write_text('{"sync_interval":0}', encoding='utf-8')
        with patch.dict(os.environ, {'F2BLOCK_CONFIG': str(config_file)}), self.assertRaises(ValueError):
            config_module.load_config()

    def test_terminal_text_cannot_inject_escape_sequences(self):
        self.assertNotIn('\x1b', cli.clean('\x1b[2Jmalicious'))
        self.assertEqual(tui.fit('中国abc', 5), '中国a')

    def test_noninteractive_default_prints_help(self):
        with patch.object(cli, 'load_config', return_value=self.config), patch.object(cli.sys.stdin, 'isatty', return_value=False), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main([]), 0)
        self.assertIn('status', output.getvalue())

    def test_terminal_dashboard_renders_and_exits(self):
        class Screen:
            def __init__(self):
                self.output = []

            def getmaxyx(self):
                return 24, 100

            def addstr(self, y, x, text, style):
                self.output.append(text)

            def getch(self):
                return ord('q')

            def __getattr__(self, name):
                return lambda *args: None

        screen = Screen()
        fake = types.SimpleNamespace(wrapper=lambda callback: callback(screen), curs_set=lambda *_: None,
                                     A_REVERSE=1, error=RuntimeError)
        with patch.dict('sys.modules', {'curses': fake}):
            self.assertEqual(tui.launch(self.config, self.store), 0)
        rendered = '\n'.join(screen.output)
        self.assertIn('永久封禁', rendered)
        self.assertIn('总览看板', rendered)
        self.assertIn('最近 7 天', rendered)
        self.assertIn('当前黑名单 1', rendered)
        self.assertIn('操作历史', rendered)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def install(self, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            installer.install(self.root, **kwargs)

    def test_install_upgrade_uninstall_preserve_data_and_config(self):
        self.install()
        data = self.root / 'var/lib/f2block/f2block.db'
        with contextlib.closing(sqlite3.connect(data)) as db, db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM blocked_ips').fetchone()[0], 0)
            db.execute("INSERT INTO allowlist VALUES('203.0.113.9','test')")
        config = self.root / 'etc/f2block/config.json'
        custom = json.loads(config.read_text())
        custom['geo_enabled'] = False
        config.write_text(json.dumps(custom))
        self.install()
        with contextlib.closing(sqlite3.connect(data)) as db, db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM allowlist').fetchone()[0], 1)
        self.assertFalse(json.loads(config.read_text())['geo_enabled'])
        self.assertTrue(list((data.parent / 'backups').glob('*/f2block.db')))
        with contextlib.redirect_stdout(io.StringIO()):
            installer.uninstall(self.root)
        self.assertTrue(data.exists())
        self.assertTrue(config.exists())
        self.assertFalse((self.root / 'opt/f2block/f2block').exists())

    def test_explicit_migration_never_overwrites_existing_database(self):
        old = self.root / 'legacy'
        old.mkdir()
        with contextlib.closing(sqlite3.connect(old / 'f2block.db')) as db, db:
            runtime.initialize(db)
            db.execute("INSERT INTO allowlist VALUES('203.0.113.8','test')")
        self.install(migrate=old)
        with contextlib.closing(sqlite3.connect(self.root / 'var/lib/f2block/f2block.db')) as db, db:
            self.assertEqual(db.execute('SELECT ip FROM allowlist').fetchone()[0], '203.0.113.8')
        with self.assertRaises(ValueError):
            self.install(migrate=old)

    def test_staging_never_calls_system_services(self):
        with patch.object(installer.subprocess, 'run') as run:
            self.install()
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
