"""Failure recovery, durable negative cache and updater isolation regressions."""
import contextlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
from unittest.mock import Mock, patch

import f2block_enrich as enrich
import f2block_cli as cli
import f2block_manage as manage
from f2block_runtime import initialize

UNKNOWN = dict.fromkeys(enrich.FIELDS, 'Unknown')
FOUND = dict(country='US', region='California', city='Mountain View', org='AS15169 Google LLC')


class EnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'f2block.db'
        self.db = sqlite3.connect(self.path)
        self.addCleanup(self.db.close)
        initialize(self.db)
        self.db.execute("INSERT INTO blocked_ips(ip,country,first_seen) VALUES('8.8.8.8','Unknown','first')")
        self.db.commit()
        self.library = Mock(packed=Mock(release='2026-11'))
        self.library.generation = '2026-11:1'
        self.library.lookup.return_value = dict(UNKNOWN)
        self.online = Mock(next_allowed=0, error='')
        self.online.lookup.return_value = ({}, 'not_found', 0, True)

    def scan(self, now=100):
        return enrich.scan_once(self.db, self.library, self.online, now)

    def status(self):
        return self.db.execute('SELECT state,attempts FROM geo_lookup').fetchone()

    def test_negative_result_survives_restart_and_only_rechecks_new_release_locally(self):
        self.assertEqual(self.scan(), 1)
        self.assertEqual(self.status(), ('not_found', 1))
        self.online.lookup.reset_mock()
        self.assertEqual(self.scan(100000), 0)
        self.online.lookup.assert_not_called()
        self.library.packed.release = '2026-12'
        self.library.generation = '2026-12:1'
        self.library.lookup.return_value = FOUND
        self.assertEqual(self.scan(100001), 1)
        self.online.lookup.assert_not_called()
        self.assertEqual(self.status(), ('found', 1))

    def test_local_first_then_remote_only_missing_fields_and_terminal_partial(self):
        self.library.lookup.return_value = dict(UNKNOWN, country='US', city='Local city')
        self.online.lookup.return_value = ({'country': 'CA', 'region': 'Remote region'}, 'found', 0, True)
        self.scan()
        self.assertEqual(self.db.execute('SELECT country,region,city,org FROM blocked_ips').fetchone(),
                         ('US', 'Remote region', 'Local city', 'Unknown'))
        self.assertEqual(self.status(), ('partial', 1))
        self.assertEqual(self.scan(100000), 0)

    def test_transient_failure_has_backoff_and_finite_attempts(self):
        self.online.lookup.return_value = ({}, 'retry', 200, True)
        self.scan(100)
        self.assertEqual(self.scan(199), 0)
        self.scan(200)
        self.scan(300)
        self.assertEqual(self.status(), ('unresolved', 3))
        self.assertEqual(self.scan(100000), 0)
        self.assertEqual(self.online.lookup.call_count, 3)

    def test_deleted_and_recreated_record_is_not_suppressed_by_old_negative(self):
        self.scan()
        self.db.execute("UPDATE blocked_ips SET first_seen='new-ban'")
        self.db.commit()
        self.scan(200)
        self.assertEqual(self.online.lookup.call_count, 2)
        self.assertEqual(self.status(), ('not_found', 1))

    def test_local_corruption_requests_repair_and_uses_online(self):
        self.library.lookup.side_effect = ValueError('bad block')
        self.online.lookup.return_value = (FOUND, 'found', 0, True)
        self.scan()
        self.assertEqual(self.status(), ('found', 1))
        state = dict(self.db.execute('SELECT * FROM runtime_state'))
        self.assertEqual(state['geo_repair_requested'], '1')
        self.assertIn('bad block', state['geo_error'])

    def test_no_network_if_local_has_all_fields(self):
        self.library.lookup.return_value = FOUND
        self.scan()
        self.online.lookup.assert_not_called()
        self.assertEqual(self.status(), ('found', 0))

    @patch.object(enrich.urllib.request, 'urlopen')
    def test_http_429_global_cooldown_and_unknown_result(self, network):
        network.side_effect = urllib.error.HTTPError('https://ipinfo.io', 429, 'limited', {'Retry-After': '7200'}, None)
        fallback = enrich.OnlineFallback()
        self.assertEqual(fallback.lookup('8.8.8.8', 100)[1:], ('retry', 7300, True))
        self.assertEqual(fallback.lookup('1.1.1.1', 200)[1:], ('retry', 7300, False))
        self.assertEqual(network.call_count, 1)
        network.side_effect = None
        network.return_value = io.BytesIO(json.dumps({'bogon': True}).encode())
        self.assertEqual(fallback.lookup('8.8.8.8', 8000)[1], 'not_found')
        self.assertEqual(fallback.lookup('127.0.0.1', 9000)[1], 'not_found')
        self.assertEqual(network.call_count, 2)

    def test_updates_do_not_hold_import_lock_or_block_enrichment(self):
        entered, release, stop = threading.Event(), threading.Event(), threading.Event()
        updater = Mock(directory=self.root / 'geo', packed=Mock(release='2026-11'))
        updater.directory.mkdir()
        def slow_update(**kwargs):
            kwargs['progress']()
            entered.set()
            release.wait(5)
            return '2026-11'
        updater.update.side_effect = slow_update
        thread = threading.Thread(target=enrich.maintain, args=(stop, {}, self.root, self.path))
        with patch.object(enrich, 'LocalGeo', return_value=updater):
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                self.library.lookup.return_value = FOUND
                started = time.monotonic()
                self.scan()
                config = dict(data_dir=str(self.root))
                with patch('f2block_runtime.locked', return_value=contextlib.nullcontext()), patch.object(cli, 'legacy', return_value=0):
                    manage.import_lists(config, cli.Store(config), ['1.1.1.1'], 'blocked')
                self.assertLess(time.monotonic() - started, 2)
                self.assertFalse(release.is_set())
            finally:
                stop.set()
                release.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())

    def test_missing_library_triggers_repair_before_scheduled_interval(self):
        stop = Mock()
        stop.is_set.side_effect = [False, False, True]
        updater = Mock(directory=self.root / 'geo', packed=Mock(release='2026-11'))
        updater.directory.mkdir()
        updater.reload.side_effect = [None, OSError('library removed')]
        updater.update.return_value = '2026-11'
        with patch.object(enrich, 'LocalGeo', return_value=updater):
            enrich.maintain(stop, {'geo_update_interval': 86400}, self.root, self.path)
        self.assertEqual(updater.update.call_count, 2)

    def test_failed_repair_is_throttled_and_corruption_forces_update(self):
        stop = Mock()
        stop.is_set.side_effect = [False, False, False, True]
        updater = Mock(directory=self.root / 'geo', packed=None)
        updater.directory.mkdir()
        updater.reload.side_effect = OSError('missing file')
        updater.update.side_effect = OSError('offline')
        enrich.state_set(self.db, geo_repair_requested='1')
        with patch.object(enrich, 'LocalGeo', return_value=updater), patch.object(enrich.time, 'monotonic', return_value=1000):
            enrich.maintain(stop, {}, self.root, self.path)
        updater.update.assert_called_once()
        self.assertTrue(updater.update.call_args.kwargs['force'])
        self.assertEqual(dict(self.db.execute('SELECT * FROM runtime_state'))['geo_update_error'], 'offline')

    def test_progress_reporting_contention_does_not_abort_update(self):
        stop = Mock()
        stop.is_set.side_effect = [False, False, True]
        updater = Mock(directory=self.root / 'geo', packed=None)
        updater.directory.mkdir()
        updater.update.side_effect = lambda **kwargs: (kwargs['progress'](), '2026-11')[1]
        actual = enrich.state_set
        def sometimes_busy(db, **values):
            if set(values) == {'geo_update_heartbeat'}:
                raise sqlite3.OperationalError('database is locked')
            return actual(db, **values)
        with patch.object(enrich, 'LocalGeo', return_value=updater), patch.object(enrich, 'state_set', side_effect=sometimes_busy):
            enrich.maintain(stop, {}, self.root, self.path)
        updater.update.assert_called_once()
        self.assertEqual(dict(self.db.execute('SELECT * FROM runtime_state'))['geo_update_error'], '')

    def test_status_read_snapshot_does_not_block_ban_write(self):
        with contextlib.closing(sqlite3.connect(self.path, timeout=.2)) as reader, \
                contextlib.closing(sqlite3.connect(self.path, timeout=.2)) as writer:
            reader.execute('BEGIN')
            reader.execute('SELECT * FROM blocked_ips').fetchall()
            with writer:
                writer.execute("INSERT INTO blocked_ips(ip,country) VALUES('1.1.1.1','Unknown')")
            reader.rollback()
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM blocked_ips').fetchone()[0], 2)


if __name__ == '__main__':
    unittest.main()
