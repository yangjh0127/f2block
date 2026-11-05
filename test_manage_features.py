import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import patch

import f2block_cli as cli
import f2block_manage as manage
from f2block_runtime import initialize


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {'data_dir': str(self.root), 'log_file': str(self.root / 'log')}
        self.store = cli.Store(self.config)
        self.db = sqlite3.connect(self.store.path)
        self.addCleanup(self.db.close)
        initialize(self.db)

    def test_exchange_validation_and_empty_roundtrip(self):
        path = self.root / 'list.json'
        path.write_text(json.dumps([{'ip': '203.0.113.1'}] * 2), encoding='utf-8')
        self.assertEqual(manage.read_import(path), (['203.0.113.1'], 1))
        path.write_text('[{"ip":"203.0.113.1"},{"ip":"invalid"}]', encoding='utf-8')
        with self.assertRaises(ValueError):
            manage.read_import(path)
        for format in ('csv', 'json'):
            target = self.root / ('empty.' + format)
            manage.export_lists(self.store, format, 'allowed', target)
            self.assertEqual(manage.read_import(target), ([], 0))
            with self.assertRaises(FileExistsError):
                manage.export_lists(self.store, format, 'allowed', target)

    def test_import_preserves_release_whitelist_history_and_is_idempotent(self):
        self.db.execute("INSERT INTO allowlist VALUES('203.0.113.1','2026-01-01')")
        self.db.execute("INSERT INTO released_ips VALUES('203.0.113.2','2026-01-01')")
        self.db.commit()
        with patch('f2block_runtime.locked', return_value=contextlib.nullcontext()), patch.object(cli, 'legacy', return_value=0):
            for _ in range(2):
                self.assertEqual(manage.import_lists(self.config, self.store,
                    ['203.0.113.1', '203.0.113.2', '203.0.113.3'], 'blocked'), 0)
        self.assertEqual([row['ip'] for row in self.store.listing()], ['203.0.113.3'])
        self.assertEqual(self.store.counts()['events'], 0)
        self.assertEqual(len(self.store.query('SELECT * FROM admin_events')), 1)

    def test_cross_server_roundtrip_preserves_geography_csv_and_json(self):
        geography = ('US', 'California', 'Mountain View', 'AS15169 Google LLC')
        self.db.execute('INSERT INTO blocked_ips(ip,country,region,city,org,ban_count) VALUES(?,?,?,?,?,17)',
                        ('2001:4860:4860::8888', *geography))
        self.db.commit()
        for format in ('csv', 'json'):
            with self.subTest(format=format):
                path = self.root / ('roundtrip.' + format)
                manage.export_lists(self.store, format, 'blocked', path)
                addresses, duplicates = manage.read_import(path)
                self.assertEqual(duplicates, 0)
                target_dir = self.root / format
                target_dir.mkdir()
                config = dict(self.config, data_dir=str(target_dir))
                target = cli.Store(config)
                with contextlib.closing(sqlite3.connect(target.path)) as db:
                    initialize(db)
                with patch('f2block_runtime.locked', return_value=contextlib.nullcontext()), patch.object(cli, 'legacy', return_value=0):
                    manage.import_lists(config, target, addresses, 'blocked')
                row = target.details(addresses[0])['record']
                self.assertEqual(tuple(row[key] for key in manage.GEO_FIELDS), geography)
                self.assertEqual(row['ban_count'], 0)
                self.assertEqual(target.counts()['events'], 0)

    def test_reimport_repairs_missing_geography_and_keeps_existing_known_fields(self):
        self.db.execute("INSERT INTO blocked_ips(ip,country,region,city,org,ban_count) "
                        "VALUES('203.0.113.3','Unknown',NULL,'','Known organization',23)")
        self.db.execute("INSERT INTO allowlist VALUES('203.0.113.1','2026-01-01')")
        self.db.execute("INSERT INTO released_ips VALUES('203.0.113.2','2026-01-01')")
        self.db.commit()
        path = self.root / 'repair.json'
        path.write_text(json.dumps([dict(ip=ip, country='CN', region='Province', city='City', org='Imported organization')
                                   for ip in ('203.0.113.1', '203.0.113.2', '203.0.113.3')]))
        addresses, _ = manage.read_import(path)
        with patch('f2block_runtime.locked', return_value=contextlib.nullcontext()), patch.object(cli, 'legacy', return_value=0):
            for _ in range(2):
                manage.import_lists(self.config, self.store, addresses, 'blocked')
        row = self.store.details('203.0.113.3')['record']
        self.assertEqual(tuple(row[key] for key in manage.GEO_FIELDS), ('CN', 'Province', 'City', 'Known organization'))
        self.assertEqual(row['ban_count'], 23)
        self.assertEqual(len(self.store.listing()), 1)
        self.assertEqual(self.store.counts()['events'], 0)

    def test_import_geography_validation_and_canonical_duplicate_merge(self):
        path = self.root / 'metadata.json'
        path.write_text(json.dumps([{'ip': '2001:0db8::1', 'country': 'Unknown', 'city': 'City'},
                                   {'ip': '2001:db8::1', 'country': 'US', 'city': 'Other city'}]))
        addresses, duplicates = manage.read_import(path)
        self.assertEqual(duplicates, 1)
        self.assertEqual(addresses.geography['2001:db8::1'], {'country': 'US', 'city': 'City'})
        for invalid in (123, {}, ['US'], 'x' * 4097):
            path.write_text(json.dumps([{'ip': '8.8.8.8', 'country': invalid}]))
            with self.assertRaises(ValueError):
                manage.read_import(path)

    def test_preview_does_not_write_and_uninstall_requires_confirmation(self):
        path = self.root / 'in.json'
        path.write_text('[{"ip":"203.0.113.1"}]', encoding='utf-8')
        before = self.store.path.read_bytes()
        with patch.object(cli, 'load_config', return_value=self.config), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['import', str(path), '--kind', 'blocked']), 0)
        self.assertEqual(self.store.path.read_bytes(), before)
        with patch('install.main') as uninstall:
            with self.assertRaises(ValueError):
                manage.uninstall_program()
            uninstall.assert_not_called()

    def test_dashboard_seven_days_and_excludes_whitelist(self):
        today = dt.date.today().isoformat()
        self.db.execute('INSERT INTO ban_events(ip,jail,ban_time) VALUES(?,?,?)',
                        ('203.0.113.1', 'sshd', today + ' 10:00:00'))
        self.db.execute("INSERT INTO blocked_ips(ip,country) VALUES('203.0.113.1','CN')")
        self.db.execute("INSERT INTO allowlist VALUES('203.0.113.1',?)", (today,))
        self.db.commit()
        with patch.object(cli, 'probe', return_value=(127, 'unavailable')):
            lines = manage.overview(self.config, self.store)
        self.assertEqual(sum(line.startswith('  20') for line in lines), 7)
        self.assertTrue(any(today in line and '#' in line for line in lines))
        self.assertIn('当前黑名单 0', lines[0])
        self.assertIn('防火墙：异常/无法读取', lines)

    def test_terminal_tabs_and_cancel_import(self):
        import f2block_tui as tui
        keys = iter([ord('1'), ord('6'), ord('i'), ord('q')])

        class Screen:
            def __init__(self):
                self.output = []

            def getmaxyx(self):
                return 30, 120

            def addstr(self, y, x, text, style):
                self.output.append(text)

            def getch(self):
                return next(keys)

            def get_wch(self):
                return '\x1b'

            def __getattr__(self, name):
                return lambda *args: None

        screen = Screen()
        fake = types.SimpleNamespace(wrapper=lambda callback: callback(screen), curs_set=lambda *_: None,
                                     A_REVERSE=1, error=RuntimeError)
        for index, name in enumerate(('KEY_UP', 'KEY_DOWN', 'KEY_NPAGE', 'KEY_PPAGE', 'KEY_LEFT',
                                      'KEY_RIGHT', 'KEY_ENTER', 'KEY_BACKSPACE', 'KEY_RESIZE'), 300):
            setattr(fake, name, index)
        with patch.dict('sys.modules', {'curses': fake}), patch.object(cli, 'probe', return_value=(1, 'offline')):
            self.assertEqual(tui.launch(self.config, self.store), 0)
        rendered = '\n'.join(screen.output)
        self.assertIn('E 导出', rendered)
        self.assertIn('总览看板', rendered)
        self.assertEqual(self.store.counts()['blocked'], 0)


if __name__ == '__main__':
    unittest.main()
