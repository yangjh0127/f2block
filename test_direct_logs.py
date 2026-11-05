"""Standalone log detection and native administration regression suite."""
import contextlib
import datetime as dt
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import f2block_actions as actions
import f2block_cli as cli
import f2block_config as configuration
import f2block_detect as detect
import f2block_runtime as runtime
import install


class DirectLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'auth.log'
        self.path.write_text('')
        self.config = {'data_dir': str(self.root), 'log_file': str(self.path),
                       'geo_enabled': False, 'sync_interval': 5, 'start_at_end': False,
                       'rules': [self.rule()]}
        self.db = sqlite3.connect(self.root / 'f2block.db')
        self.addCleanup(self.db.close)
        runtime.initialize(self.db)
        self.now = dt.datetime.now().replace(microsecond=0).timestamp()
        self.delivery = patch.object(runtime, 'run', return_value=Mock(returncode=0)).start()
        self.addCleanup(patch.stopall)

    def rule(self, name='ssh', **overrides):
        rule = dict(name=name, log_file=str(self.path), max_retry=3, find_time=60,
                    pattern=r'^(?P<time>\S+) failure from (?P<ip>\S+)$')
        rule.update(overrides)
        return rule

    def line(self, ip='2001:db8::7', stamp=None):
        return dt.datetime.fromtimestamp(self.now if stamp is None else stamp).isoformat() + f' failure from {ip}'

    def feed(self, receipt, ip='2001:db8::7', stamp=None, rules=None):
        return detect.process_line(self.db, rules or detect.rules_for(self.config), self.line(ip, stamp), receipt, self.now)

    def active(self):
        return self.db.execute('SELECT ip FROM blocked_ips ORDER BY ip').fetchall()

    def test_threshold_canonical_ipv6_and_replay(self):
        self.feed('one', '2001:0db8::7')
        self.feed('one')
        self.feed('two')
        self.assertEqual(self.active(), [])
        self.feed('three')
        self.delivery.assert_called_with('ipset', 'add', 'f2block6', '2001:db8::7', '-exist')
        self.assertEqual(self.active(), [('2001:db8::7',)])
        self.feed('three')
        self.feed('four')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM ban_events').fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT matched FROM detection_bans').fetchone()[0], 3)

    def test_window_expires_and_future_logs_ignored(self):
        self.feed('old', stamp=self.now - 61)
        self.feed('future', stamp=self.now + 120)
        self.feed('one')
        self.feed('two')
        self.assertEqual(self.active(), [])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM detection_hits').fetchone()[0], 2)

    def test_ips_and_rules_are_isolated(self):
        self.feed('one', '203.0.113.7')
        self.feed('two', '203.0.113.8')
        other = detect.compile_rules([self.rule('other')])
        self.feed('one', '203.0.113.7', rules=other)
        self.feed('two', '203.0.113.7', rules=other)
        self.assertEqual(self.active(), [])
        self.feed('three', '203.0.113.7', rules=other)
        self.assertEqual(self.active(), [('203.0.113.7',)])

    def test_restart_keeps_counter_and_receipts(self):
        self.feed('one')
        self.db.close()
        self.db = sqlite3.connect(self.root / 'f2block.db')
        self.addCleanup(self.db.close)
        self.feed('one')
        self.feed('two')
        self.assertEqual(self.active(), [])
        self.feed('three')
        self.assertEqual(len(self.active()), 1)

    def test_firewall_failure_keeps_desired_state_for_reconcile(self):
        self.feed('one')
        self.feed('two')
        self.delivery.side_effect = subprocess.CalledProcessError(1, ['ipset'])
        with self.assertRaises(runtime.DeferredFirewallError):
            self.feed('three')
        self.assertEqual(len(self.active()), 1)
        self.delivery.side_effect = None
        runtime.reconcile(self.db)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM ban_events').fetchone()[0], 1)

    def test_sql_failure_rolls_back_threshold_receipt(self):
        self.feed('one')
        self.feed('two')
        self.db.execute("CREATE TRIGGER reject_ban BEFORE INSERT ON blocked_ips BEGIN SELECT RAISE(ABORT,'fault'); END")
        self.db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            self.feed('three')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM detection_hits').fetchone()[0], 2)
        self.db.execute('DROP TRIGGER reject_ban')
        self.db.commit()
        self.feed('three')
        self.assertEqual(len(self.active()), 1)

    def test_allowlist_and_release_barrier(self):
        self.db.execute("INSERT INTO allowlist VALUES('2001:db8::7','now')")
        self.db.commit()
        for index in range(3):
            self.feed(str(index))
        self.assertEqual(self.active(), [])
        self.db.execute('DELETE FROM allowlist')
        self.db.execute('INSERT INTO released_ips VALUES(?,?)', ('2001:db8::7', dt.datetime.fromtimestamp(self.now).isoformat()))
        self.db.commit()
        for index in range(3):
            self.feed('r' + str(index), stamp=self.now - 1)
        self.assertEqual(self.active(), [])
        for index in range(3):
            self.feed('n' + str(index), stamp=self.now + 1)
        self.assertEqual(len(self.active()), 1)

    def test_ssh_preset_matches_realistic_formats_and_ignores_payloads(self):
        rule = detect.compile_rules(detect.default_rules(str(self.path)))[0]
        for prefix in ('Oct 29 12:00:00', '2026-10-29T12:00:00+08:00'):
            for ip in ('203.0.113.7', '2001:db8::7'):
                line = f'{prefix} host sshd[123]: Failed password for invalid user admin from {ip} port 4567 ssh2'
                self.assertEqual(detect.match_line(rule, line, self.now)[0], ip)
        for line in ('Oct 29 12:00:00 host app[1]: user says Failed password for root from 203.0.113.7 port 123 ssh2',
                     'Oct 29 12:00:00 host sshd[1]: Accepted password for root from 203.0.113.7 port 123 ssh2'):
            self.assertIsNone(detect.match_line(rule, line, self.now))

    def test_bad_time_and_ip_are_visible_and_do_not_ban(self):
        for line in ('garbage failure from 203.0.113.7', self.line('not-ip')):
            detect.process_line(self.db, detect.rules_for(self.config), line, line, self.now)
        self.assertEqual(self.active(), [])
        self.assertTrue(self.db.execute("SELECT value FROM runtime_state WHERE key='rule_error:ssh'").fetchone())

    def test_validation_and_rule_change_reset(self):
        for item in (self.rule(pattern='('), self.rule(pattern='(?P<ip>.*)'),
                     self.rule(max_retry=True), self.rule(find_time=0), self.rule(log_file='relative')):
            with self.assertRaises(ValueError):
                detect.compile_rules([item])
        self.feed('one')
        self.feed('two')
        changed = detect.compile_rules([self.rule(max_retry=4)])
        self.feed('three', rules=changed)
        detect.prune(self.db, changed, self.now)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM detection_hits').fetchone()[0], 1)

    def test_two_sources_resume_and_rotation(self):
        other = self.root / 'nginx.log'
        other.write_bytes(b'first\nsecond\n')
        self.path.write_bytes(b'first\nsecond\n')
        for path in (self.path, other):
            reader = runtime.LogReader(path, self.db, str(path), False)
            self.assertEqual(reader.read(), b'first\n')
            reader.acknowledge()
            reader.close()
        reader = runtime.LogReader(other, self.db, str(other), False)
        self.addCleanup(reader.close)
        self.assertEqual(reader.read(), b'second\n')
        receipt = reader.receipt()
        reader.close()
        reader = runtime.LogReader(other, self.db, str(other), False)
        self.addCleanup(reader.close)
        self.assertEqual(reader.read(), b'second\n')
        self.assertEqual(reader.receipt(), receipt)
        reader.acknowledge()
        reader.close()
        other.rename(other.with_suffix('.old'))
        other.write_bytes(b'new\n')
        reader = runtime.LogReader(other, self.db, str(other), True)
        self.addCleanup(reader.close)
        self.assertEqual(reader.read(), b'new\n')
        self.assertNotEqual(reader.receipt(), receipt)

    def test_initial_tail_and_truncation_receipt(self):
        self.path.write_bytes(b'historical\n')
        reader = runtime.LogReader(self.path, self.db, str(self.path), True)
        self.addCleanup(reader.close)
        self.assertIsNone(reader.read())
        with self.path.open('ab') as stream:
            stream.write(b'new\n')
        self.assertEqual(reader.read(), b'new\n')
        old = reader.receipt()
        reader.acknowledge()
        self.path.write_bytes(b'')
        self.assertIsNone(reader.read())
        self.path.write_bytes(b'new\n')
        self.assertEqual(reader.read(), b'new\n')
        self.assertNotEqual(reader.receipt(), old)

    def test_rule_preflight_does_not_touch_database(self):
        self.path.write_text(self.line() + '\nnot a match\n')
        before = (self.root / 'f2block.db').read_bytes()
        with patch.object(cli, 'load_config', return_value=self.config), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(['rules', 'test', 'ssh', '--file', str(self.path)]), 0)
        self.assertIn('匹配 1 行', output.getvalue())
        self.assertEqual((self.root / 'f2block.db').read_bytes(), before)

    def test_native_allow_unban_and_remove_never_call_fail2ban(self):
        self.feed('one')
        self.feed('two')
        self.feed('three')
        with patch.object(actions, 'locked', return_value=contextlib.nullcontext()), \
             patch.object(cli, 'probe', return_value=(0, 'f2block\nf2block6')), \
             patch.object(actions, 'run', return_value=Mock(returncode=0)) as run:
            actions.operate(self.config, 'allow', '2001:0db8::7', 'office')
            run.assert_called_with('ipset', 'del', 'f2block6', '2001:db8::7', '-exist')
            self.assertEqual(self.active(), [])
            actions.operate(self.config, 'allowdel', '2001:db8::7')
            actions.operate(self.config, 'unban', '203.0.113.7')
            self.assertTrue(all(call.args[0] == 'ipset' for call in run.call_args_list))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM detection_hits').fetchone()[0], 0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM ban_events').fetchone()[0], 1)
        self.assertNotIn('fail2ban-client', cli.TOOLS)
        self.assertNotIn('fail2ban-client', install.DEPENDENCIES)
        self.assertNotIn('fail2ban.service', (Path(__file__).parent / 'f2block.service').read_text())

    def test_native_import_sync_does_not_adopt_unrelated_orphans(self):
        with patch.object(actions, 'locked', return_value=contextlib.nullcontext()), \
             patch.object(cli, 'set_members', return_value={'2001:db8::9'}), \
             patch.object(actions, 'reconcile'):
            actions.sync(self.config, adopt_orphans=False)
            self.assertEqual(self.active(), [])
            actions.sync(self.config, adopt_orphans=True)
            self.assertEqual(self.active(), [('2001:db8::9',)])

    def test_native_sync_reports_database_failure_without_delivering(self):
        self.db.execute("CREATE TRIGGER reject_sync BEFORE INSERT ON blocked_ips BEGIN SELECT RAISE(ABORT,'fault'); END")
        self.db.commit()
        with patch.object(actions, 'locked', return_value=contextlib.nullcontext()), \
             patch.object(cli, 'set_members', return_value={'2001:db8::9'}), \
             patch.object(actions, 'reconcile') as reconcile:
            with self.assertRaises(sqlite3.IntegrityError):
                actions.sync(self.config)
            reconcile.assert_not_called()
        self.assertEqual(self.active(), [])

    def test_installer_migrates_old_configuration_and_packages_detector(self):
        stage = self.root / 'stage'
        config_path = stage / 'etc/f2block/config.json'
        config_path.parent.mkdir(parents=True)
        config_path.write_text(json.dumps({'data_dir': '/var/lib/f2block', 'log_file': '/var/log/fail2ban.log'}))
        self.assertEqual(install.main(['--root', str(stage)]), 0)
        config = json.loads(config_path.read_text())
        self.assertEqual(config['rules'][0]['log_file'], '/var/log/auth.log')
        self.assertTrue((stage / 'opt/f2block/f2block_detect.py').is_file())
        self.assertFalse((stage / 'opt/f2block/f2block_delivery.py').exists())

    def test_daemon_reads_multiple_sources_without_fail2ban_and_isolates_missing_file(self):
        first = self.root / 'first.log'
        second = self.root / 'second.log'
        first.write_text((self.line('2001:db8::7') + '\n') * 3)
        second.write_text((self.line('203.0.113.7') + '\n') * 2)
        config = dict(self.config, rules=[self.rule('first', log_file=str(first)),
                                         self.rule('second', log_file=str(second), max_retry=2),
                                         self.rule('missing', log_file=str(self.root / 'missing.log'))])
        config_file = self.root / 'config.json'
        config_file.write_text(json.dumps(config))
        wrapper = self.root / 'run.py'
        wrapper.write_text('''import contextlib, json, signal, sys, threading, types
import f2block_runtime as worker
fcntl = types.ModuleType('fcntl')
fcntl.LOCK_EX, fcntl.LOCK_NB, fcntl.LOCK_UN = 2, 4, 8
fcntl.flock = lambda *args: None
sys.modules['fcntl'] = fcntl
worker.locked = lambda *args: contextlib.nullcontext()
commands = []
def run(*args, **kwargs):
    assert args[0] in ('ipset', 'iptables', 'ip6tables'), args
    commands.append(args)
    return types.SimpleNamespace(returncode=0)
worker.run = run
handlers = {}
worker.signal.signal = lambda number, handler: handlers.__setitem__(number, handler)
timer = threading.Timer(1.5, lambda: handlers[signal.SIGTERM](None, None))
timer.start()
try:
    worker.main()
finally:
    timer.cancel()
print(json.dumps(commands))
''')
        result = subprocess.run([sys.executable, str(wrapper)], capture_output=True, text=True, timeout=15,
                                env=dict(os.environ, F2BLOCK_CONFIG=str(config_file), PYTHONPATH=str(Path(__file__).parent)))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.active(), [('2001:db8::7',), ('203.0.113.7',)],
                         result.stdout + repr(list(self.db.execute('SELECT * FROM runtime_state')))
                         + repr(list(self.db.execute('SELECT * FROM detection_hits'))))
        commands = json.loads(result.stdout)
        self.assertIn(['ipset', 'add', 'f2block6', '2001:db8::7', '-exist'], commands)
        self.assertIn(['ipset', 'add', 'f2block', '203.0.113.7', '-exist'], commands)
        state = dict(self.db.execute('SELECT key,value FROM runtime_state'))
        self.assertIn('missing.log', state['last_error'])
        self.assertIn('heartbeat', state)


if __name__ == '__main__':
    unittest.main()
