"""Indexed, independently zlib-compressed IP blocks; standard library only.

File: magic, compressed blocks, UTF-8 JSON index, index offset + magic.
Each block: count/dictionary-size (two uint32), fixed-size start/end/id
records, JSON dictionary. Index and addresses use network byte order.
"""
from bisect import bisect_right
from collections import OrderedDict
import json
import struct
import zlib

MAGIC = b'F2GEO001'
FOOTER = struct.Struct('>Q8s')
HEADER = struct.Struct('>II')
BLOCK_ROWS = 1024
MAX_BLOCK = 4 * 1024 * 1024


class Reader:
    def __init__(self, path):
        self.file = open(path, 'rb')
        self.cache = OrderedDict()
        try:
            self.file.seek(0, 2)
            size = self.file.tell()
            if size < 24:
                raise ValueError('压缩 IP 库文件过短')
            self.file.seek(-FOOTER.size, 2)
            offset, magic = FOOTER.unpack(self.file.read(FOOTER.size))
            if magic != MAGIC or not 8 <= offset < size - FOOTER.size or size - FOOTER.size - offset > 8 * 1024 * 1024:
                raise ValueError('压缩 IP 库索引无效')
            self.file.seek(0)
            if self.file.read(8) != MAGIC:
                raise ValueError('压缩 IP 库版本错误')
            self.file.seek(offset)
            metadata = json.loads(self.file.read(size - FOOTER.size - offset))
            self.release = metadata['release']
            self.index = metadata['index']
            self.starts = {}
            previous_end = 8
            for kind in ('city', 'asn'):
                for version in (4, 6):
                    key = kind + str(version)
                    entries = self.index[key]
                    if not entries or len(entries) > 100000:
                        raise ValueError('压缩 IP 库缺少地址族或索引过大')
                    last_ip = None
                    width = 4 if version == 4 else 16
                    for first, last, position, length, count in entries:
                        first, last = bytes.fromhex(first), bytes.fromhex(last)
                        if (len(first) != width or len(last) != width or first > last or
                                (last_ip is not None and first <= last_ip) or
                                position < previous_end or length <= 0 or length > MAX_BLOCK or
                                position + length > offset or not 1 <= count <= BLOCK_ROWS):
                            raise ValueError('压缩 IP 库索引范围错误')
                        previous_end = position + length
                        last_ip = last
                    self.starts[key] = [bytes.fromhex(entry[0]) for entry in entries]
        except (KeyError, TypeError, IndexError, struct.error, UnicodeError) as error:
            self.file.close()
            raise ValueError('压缩 IP 库索引损坏') from error
        except Exception:
            self.file.close()
            raise

    def close(self):
        self.cache.clear()
        self.file.close()

    def block(self, key, number):
        cache_key = (key, number)
        if cache_key in self.cache:
            self.cache.move_to_end(cache_key)
            return self.cache[cache_key]
        first, last, position, length, count = self.index[key][number]
        self.file.seek(position)
        compressed = self.file.read(length)
        try:
            decoder = zlib.decompressobj()
            raw = decoder.decompress(compressed, MAX_BLOCK + 1)
            if len(raw) > MAX_BLOCK or not decoder.eof or decoder.unused_data:
                raise ValueError('压缩 IP 块大小或校验错误')
            rows, dictionary_size = HEADER.unpack_from(raw)
            width = 4 if key.endswith('4') else 16
            record_size = 2 * width + 4
            dictionary_start = HEADER.size + rows * record_size
            if rows != count or dictionary_size != len(raw) - dictionary_start:
                raise ValueError('压缩 IP 块结构错误')
            dictionary = json.loads(raw[dictionary_start:])
            expected = 3 if key.startswith('city') else 2
            if (not isinstance(dictionary, list) or not 1 <= len(dictionary) <= rows or
                    any(not isinstance(item, list) or len(item) != expected or
                        any(not isinstance(value, str) for value in item) for item in dictionary)):
                raise ValueError('压缩 IP 块字典错误')
            previous = None
            for i in range(rows):
                start = HEADER.size + i * record_size
                low, high = raw[start:start + width], raw[start + width:start + 2 * width]
                ident = struct.unpack_from('>I', raw, start + 2 * width)[0]
                if low > high or (previous is not None and low <= previous) or ident >= len(dictionary):
                    raise ValueError('压缩 IP 块记录错误')
                previous = high
            if raw[HEADER.size:HEADER.size + width].hex() != first or previous.hex() != last:
                raise ValueError('压缩 IP 块与索引不符')
        except (zlib.error, struct.error, UnicodeError, IndexError, TypeError) as error:
            raise ValueError('压缩 IP 块损坏') from error
        result = (raw, dictionary, rows, width, record_size)
        self.cache[cache_key] = result
        if len(self.cache) > 8:
            self.cache.popitem(last=False)
        return result

    def lookup(self, kind, address):
        key = kind + str(address.version)
        ip = address.packed
        number = bisect_right(self.starts[key], ip) - 1
        if number < 0 or ip > bytes.fromhex(self.index[key][number][1]):
            return None
        raw, dictionary, rows, width, size = self.block(key, number)
        low, high = 0, rows
        while low < high:
            middle = (low + high) // 2
            offset = HEADER.size + middle * size
            if raw[offset:offset + width] <= ip:
                low = middle + 1
            else:
                high = middle
        if not low:
            return None
        offset = HEADER.size + (low - 1) * size
        if ip > raw[offset + width:offset + 2 * width]:
            return None
        return dictionary[struct.unpack_from('>I', raw, offset + 2 * width)[0]]

    def validate(self, progress=lambda: None):
        self.cache.clear()
        for key, entries in self.index.items():
            for number in range(len(entries)):
                self.block(key, number)
                progress()


def build(db, destination, progress=lambda: None):
    metadata = dict(release=db.execute('SELECT release FROM metadata').fetchone()[0], index={})
    with open(destination, 'wb') as file:
        file.write(MAGIC)
        for kind in ('city', 'asn'):
            for version in (4, 6):
                entries = metadata['index'][kind + str(version)] = []
                cursor = db.execute(f'SELECT * FROM {kind} WHERE version=? ORDER BY start', (version,))
                while True:
                    rows = cursor.fetchmany(BLOCK_ROWS)
                    if not rows:
                        break
                    dictionary, ids, records = [], {}, bytearray()
                    for row in rows:
                        payload = tuple(row[3:])
                        if payload not in ids:
                            ids[payload] = len(dictionary)
                            dictionary.append(payload)
                        records.extend(row[1])
                        records.extend(row[2])
                        records.extend(struct.pack('>I', ids[payload]))
                    text = json.dumps(dictionary, ensure_ascii=False, separators=(',', ':')).encode()
                    raw = HEADER.pack(len(rows), len(text)) + records + text
                    if len(raw) > MAX_BLOCK:
                        raise ValueError('压缩 IP 块过大')
                    compressed = zlib.compress(raw, 6)
                    entries.append([rows[0][1].hex(), rows[-1][2].hex(), file.tell(), len(compressed), len(rows)])
                    file.write(compressed)
                    progress()
        offset = file.tell()
        file.write(json.dumps(metadata, separators=(',', ':')).encode())
        file.write(FOOTER.pack(offset, MAGIC))
    check = Reader(destination)
    try:
        check.validate(progress)
    finally:
        check.close()
