"""Actual CSV/SQLite conversion, range boundaries and update rollback tests."""
import contextlib
import gzip
import io
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import f2block_geo as geo
import f2block_runtime as runtime

CITY = ('8.8.8.0,8.8.8.255,NA,US,California,"Mountain View",37.4,-122.1\n'
        '2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,NA,US,California,Mountain View,37.4,-122.1\n')
ASN = ('8.8.8.0,8.8.8.255,15169,Google LLC\n'
       '2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,15169,Google LLC\n')


class GeoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.local = geo.LocalGeo(self.temp.name)
        self.addCleanup(self.local.close)

    def response(self, request, **kwargs):
        self.assertTrue(request.full_url.endswith('.csv.gz'))
        data = CITY if 'city-lite' in request.full_url else ASN
        return io.BytesIO(gzip.compress(data.encode()))

    @patch.object(geo.urllib.request, 'urlopen')
    def test_first_download_offline_ipv4_ipv6_skip_and_force(self, network):
        network.side_effect = self.response
        self.local.update()
        self.assertEqual(network.call_count, 2)
        self.local.update()
        self.assertEqual(network.call_count, 2)
        for ip in ('8.8.8.0', '8.8.8.255', '2001:4860::', '2001:4860:ffff:ffff:ffff:ffff:ffff:ffff'):
            self.assertEqual(self.local.lookup(ip), dict(country='US', region='California',
                             city='Mountain View', org='AS15169 Google LLC'))
        for ip in ('8.8.7.255', '8.8.9.0', '2001:485f:ffff:ffff:ffff:ffff:ffff:ffff', '2001:4861::'):
            self.assertEqual(set(self.local.lookup(ip).values()), {'Unknown'})
        self.assertEqual(network.call_count, 2)
        self.local.update(force=True)
        self.assertEqual(network.call_count, 4)

    @patch.object(geo.urllib.request, 'urlopen')
    def test_invalid_asn_preserves_old_database(self, network):
        network.side_effect = self.response
        self.local.update()
        path = self.local.directory / 'lookup.geo'
        before = path.read_bytes()
        for data in ('bad\n', ASN + ASN, ASN.splitlines()[0] + '\n'):
            network.side_effect = [io.BytesIO(gzip.compress(CITY.encode())), io.BytesIO(gzip.compress(data.encode()))]
            with self.assertRaises(ValueError):
                self.local.update(force=True)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(self.local.lookup('8.8.8.8')['country'], 'US')
        self.assertEqual(sorted(p.name for p in self.local.directory.iterdir()),
                         ['.update.lock', 'lookup.geo', 'release.json'])

    @patch.object(geo.urllib.request, 'urlopen')
    def test_manual_update_reopens_cached_database(self, network):
        network.side_effect = self.response
        self.local.update()
        other = geo.LocalGeo(self.temp.name)
        try:
            other.lookup('8.8.8.8')
            if geo.os.name == 'nt':
                other.close()
            network.side_effect = [io.BytesIO(gzip.compress(CITY.replace('California', 'Updated').encode())),
                                   io.BytesIO(gzip.compress(ASN.encode()))]
            self.local.update(force=True)
            self.assertEqual(other.lookup('8.8.8.8')['region'], 'Updated')
        finally:
            other.close()

    @patch.object(geo.urllib.request, 'urlopen')
    def test_missing_library_is_rebuilt_and_missing_marker_is_recovered(self, network):
        network.side_effect = self.response
        self.local.update()
        marker = self.local.directory / 'release.json'
        marker.unlink()
        self.local.update()
        self.assertEqual(network.call_count, 2)
        self.assertTrue(marker.is_file())
        self.local.close()
        (self.local.directory / 'lookup.geo').unlink()
        self.local.update()
        self.assertEqual(network.call_count, 4)
        self.assertEqual(self.local.lookup('8.8.8.8')['country'], 'US')

    @patch.object(geo.urllib.request, 'urlopen')
    def test_corrupted_block_and_index_are_automatically_repaired(self, network):
        network.side_effect = self.response
        self.local.update()
        path = self.local.directory / 'lookup.geo'
        position = self.local.packed.index['city4'][0][2]
        self.local.close()
        with path.open('r+b') as file:
            file.seek(position)
            file.write(b'BAD')
        with self.assertRaises(ValueError):
            self.local.lookup('8.8.8.8')
        self.local.update()
        self.assertEqual(self.local.lookup('8.8.8.8')['country'], 'US')
        self.local.close()
        with path.open('r+b') as file:
            file.seek(-1, 2)
            file.write(b'X')
        self.local.update()
        self.assertEqual(self.local.lookup('8.8.8.8')['country'], 'US')
        self.assertEqual(network.call_count, 6)

    @patch.object(geo.urllib.request, 'urlopen')
    def test_failed_compression_preserves_live_file_and_cleans_staging(self, network):
        network.side_effect = self.response
        self.local.update()
        path = self.local.directory / 'lookup.geo'
        before = path.read_bytes()
        with patch.object(geo, 'build', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.local.update(force=True)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.local.directory.iterdir()),
                         ['.update.lock', 'lookup.geo', 'release.json'])

    @patch.object(geo.urllib.request, 'urlopen')
    def test_legacy_conversion_failure_never_downloads_again(self, network):
        import datetime as dt
        self.local.directory.mkdir()
        path = self.local.directory / 'lookup.sqlite'
        with contextlib.closing(sqlite3.connect(path)) as db:
            db.executescript('PRAGMA user_version=1; CREATE TABLE city(version,start,end,country,region,city); '
                             'CREATE TABLE asn(version,start,end,number,org); CREATE TABLE metadata(release);')
            db.execute('INSERT INTO metadata VALUES(?)', (dt.datetime.now(dt.timezone.utc).strftime('%Y-%m'),))
            for kind, data in (('city', CITY), ('asn', ASN)):
                compressed = self.local.directory / (kind + '.gz')
                compressed.write_bytes(gzip.compress(data.encode()))
                geo.import_csv(db, kind, compressed, lambda: None)
                compressed.unlink()
            db.commit()
        with patch.object(geo, 'build', side_effect=OSError('conversion interrupted')):
            with self.assertRaises(OSError):
                self.local.update()
        network.assert_not_called()
        self.assertTrue(path.exists())



if __name__ == '__main__':
    unittest.main()
