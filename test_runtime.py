import sqlite3
import subprocess
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock

import f2block_runtime as worker


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        worker.initialize(self.db)
        self.commands = patch.object(worker, 'run', return_value=Mock(returncode=0))
        self.run = self.commands.start()

    def tearDown(self):
        self.commands.stop()
        self.db.close()

    def event(self, stamp='2026-10-18 12:00:00,123', jail='sshd'):
        return f'{stamp} fail2ban.actions [42]: NOTICE [{jail}] Ban 203.0.113.7'

    def test_duplicate_and_multiple_jails(self):
        worker.record(self.db, self.event())
        worker.record(self.db, self.event())
        worker.record(self.db, self.event(jail='nginx'))
        self.assertEqual(self.db.execute('SELECT ban_count FROM blocked_ips').fetchone()[0], 2)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM ban_events').fetchone()[0], 2)

    def test_release_rejects_old_work_but_accepts_future_ban(self):
        worker.record(self.db, self.event())
        with self.db:
            self.db.execute("INSERT INTO released_ips VALUES('203.0.113.7','2026-10-18 12:01:00.000000')")
            self.db.execute('DELETE FROM blocked_ips')
        self.run.reset_mock()
        worker.record(self.db, self.event())
        self.run.assert_not_called()
        worker.record(self.db, self.event('2026-10-18 12:02:00,001'))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM released_ips').fetchone()[0], 0)
        self.assertEqual(self.db.execute('SELECT ban_count FROM blocked_ips').fetchone()[0], 2)

    def test_firewall_failure_can_retry_without_double_count(self):
        self.run.side_effect = subprocess.CalledProcessError(1, ['ipset'])
        with self.assertRaises(subprocess.CalledProcessError):
            worker.record(self.db, self.event())
        self.run.side_effect = None
        worker.record(self.db, self.event())
        self.assertEqual(self.db.execute('SELECT ban_count FROM blocked_ips').fetchone()[0], 1)

    def test_database_failure_rolls_back_event(self):
        self.db.execute("CREATE TRIGGER reject_block BEFORE INSERT ON blocked_ips "
                        "BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            worker.record(self.db, self.event())
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM ban_events').fetchone()[0], 0)
        self.run.assert_not_called()

    def test_allowlist_and_unban_logs_do_not_ban(self):
        self.db.execute("INSERT INTO allowlist VALUES('203.0.113.7','2026-10-18')")
        self.db.commit()
        worker.record(self.db, self.event())
        worker.record(self.db, self.event().replace(' Ban ', ' Unban '))
        self.run.assert_not_called()

    def test_reconcile_repairs_rule_independently_of_set(self):
        self.run.side_effect = lambda *args, **kw: Mock(returncode=1 if args[:2] == ('iptables', '-C') else 0)
        worker.reconcile(self.db)
        self.assertTrue(any(call.args[:2] == ('iptables', '-I') for call in self.run.call_args_list))

    def test_existing_database_migration_is_idempotent(self):
        worker.record(self.db, self.event())
        worker.initialize(self.db)
        worker.initialize(self.db)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM ban_events').fetchone()[0], 1)

    def test_cursor_only_advances_after_acknowledgement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'log'
            path.write_bytes(b'first\nsecond\npartial')
            reader = worker.LogReader(path, self.db)
            self.assertEqual(reader.read(), b'first\n')
            reader.acknowledge()
            self.assertEqual(reader.read(), b'second\n')
            reader.close()
            reader = worker.LogReader(path, self.db)
            self.assertEqual(reader.read(), b'second\n')
            reader.retry()
            self.assertEqual(reader.read(), b'second\n')
            reader.acknowledge()
            self.assertIsNone(reader.read())
            with path.open('ab') as file:
                file.write(b' complete\n')
            self.assertEqual(reader.read(), b'partial complete\n')
            reader.close()

    def test_rotation_drains_old_file_before_new_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'log'
            path.write_bytes(b'old1\nold2\n')
            reader = worker.LogReader(path, self.db)
            self.assertEqual(reader.read(), b'old1\n')
            reader.acknowledge()
            # Windows cannot rename open files; simulate replacement via path redirect.
            replacement = Path(directory) / 'newlog'
            replacement.write_bytes(b'new\n')
            reader.path = replacement
            self.assertEqual(reader.read(), b'old2\n')
            reader.acknowledge()
            self.assertIsNone(reader.read())
            self.assertEqual(reader.read(), b'new\n')
            reader.close()

    def test_copytruncate_resets_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'log'
            path.write_bytes(b'long old line\n')
            reader = worker.LogReader(path, self.db)
            reader.read()
            reader.acknowledge()
            path.write_bytes(b'new\n')
            self.assertIsNone(reader.read())
            self.assertEqual(reader.read(), b'new\n')
            reader.close()


if __name__ == '__main__':
    unittest.main()
