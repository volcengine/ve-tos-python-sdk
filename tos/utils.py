import datetime
import errno
import os.path
import sys
import threading
import time
from urllib.parse import quote_plus, unquote_to_bytes

import crcmod as crcmod
import pytz
import six

from . import exceptions as exp
from .consts import (DEFAULT_MIMETYPE, GMT_DATE_FORMAT,
                     LAST_MODIFY_TIME_DATE_FORMAT)
from .enum import DataTransferType
from .mine_type import TYPES_MAP


def get_value(kv, key, handler=lambda x: x):
    if key in kv:
        return handler(kv[key])
    else:
        return None


def get_etag(kv):
    return get_value(kv, "ETag", lambda x: x.strip('"'))


def to_bytes(data):
    if six.PY2:
        if isinstance(data, unicode):
            return data.encode('utf-8')
    if six.PY3:
        if isinstance(data, str):
            return data.encode(encoding='utf-8')
    return data


def to_str(data):
    if six.PY2:
        if isinstance(data, unicode):
            return data.encode('utf-8')
    if six.PY3:
        if isinstance(data, bytes):
            return data.decode('utf-8')
    return data


def normalize_url_path(path):
    if not path:
        return '/'
    return remove_dot_segments(path)


def remove_dot_segments(url):
    if not url:
        return ''
    input_url = url.split('/')
    output_list = []
    for x in input_url:
        if x and x != '.':
            if x == '..':
                if output_list:
                    output_list.pop()
            else:
                output_list.append(x)

    if url[0] == '/':
        first = '/'
    else:
        first = ''
    if url[-1] == '/' and output_list:
        last = '/'
    else:
        last = ''
    return first + '/'.join(output_list) + last


def parse_modify_time_to_utc_datetime(value):
    return datetime.datetime.strptime(value, LAST_MODIFY_TIME_DATE_FORMAT).replace(tzinfo=pytz.utc)


def parse_gmt_time_to_utc_datetime(value):
    return datetime.datetime.strptime(value, GMT_DATE_FORMAT).replace(tzinfo=pytz.utc)


def get_content_type(key):
    """根据文件名后缀，获取文件类型"""
    ext = os.path.splitext(key)[1].lower()
    return TYPES_MAP[ext] if ext in TYPES_MAP else DEFAULT_MIMETYPE


def _make_range_string(start, last):
    if start is None and last is None:
        return ''

    return 'bytes=' + _range(start, last)


def _range(start, last):
    def to_str(pos):
        if pos is None:
            return ''
        else:
            return str(pos)

    return to_str(start) + '-' + to_str(last)


def to_unicode(data):
    """把输入转换为unicode，要求输入是unicode或者utf-8编码的bytes。"""
    return to_str(data)


def is_utf8_with_trigger(s: bytes):
    i = 0
    while i < len(s):
        now = s[i]
        first = first_zero(s[i])
        if first == 0:
            if s[i] < 32 or s[i] == 127:
                return False
            i = i + 1
        elif 2 <= first <= 6:
            if i + first <= len(s):
                for j in range(i + 1, i + first):
                    if s[j] & 0xC0 != 0x80:
                        return False
                i += first
            else:
                return False
        else:
            return False
    return True


def first_zero(a):
    mask = 0x80
    i = 0
    while mask & a != 0:
        mask = mask >> 1
        i = i + 1
    return i


def generate_http_proxies(ip: str, port: int, user_name: str = None, password: str = None):
    # 未配置ip地址 返回空{}
    if ip is None or len(ip) == 0:
        return {}

    proxy = ""
    if user_name is None or len(user_name) == 0:
        # 返回 "http": "http://{ip}:port",
        proxy = 'http://{0}:{1}'.format(ip, port)

    else:
        # 返回  "http": "http://{user_name}:{password}@{ip}:{port}/"
        proxy = "http://{0}:{1}@{2}:{3}/".format(user_name, password, ip, port)

    return {'http': proxy}


def _make_copy_source(src_bucket, src_key, src_version_id):
    copy_source = {}
    if src_bucket:
        copy_source['Bucket'] = src_bucket

    if src_key:
        copy_source['Key'] = src_key

    if src_version_id:
        copy_source['VersionId'] = src_version_id

    return copy_source


_CHUNK = 8 * 1024


def _make_upload_part_file_content(file, offset, part_size, size):
    """创建 具备offset 和读取长度 file-object
    """
    if offset < 0 or part_size < -1:
        return None
    if offset > size:
        return None

    file.seek(offset, os.SEEK_SET)

    if part_size == -1 or (part_size + offset) >= size:
        return SizeAdapter(file, size - offset)
    else:
        return SizeAdapter(file, part_size)


class SizeAdapter(object):
    def __init__(self, file_object, size):
        self.file_object = file_object
        self.size = size
        self.offset = 0

    def read(self, amt=None):
        if self.offset >= self.size:
            return ''

        if (amt is None or amt < 0) or (amt + self.offset >= self.size):
            data = self.file_object.read(self.size - self.offset)
            self.offset = self.size
            return data

        self.offset += amt
        return self.file_object.read(amt)

    @property
    def len(self):
        return self.size


def meta_header_encode(query, doseq=False, safe='', encoding=None, errors=None,
                       quote_via=quote_plus):
    headers = {}
    if hasattr(query, "items"):
        query = query.items()
    else:
        # It's a bother at times that strings and string-like objects are
        # sequences.
        try:
            # non-sequence items should not work with len()
            # non-empty strings will fail this
            if len(query) and not isinstance(query[0], tuple):
                raise TypeError
            # Zero-length sequences of all types will get here and succeed,
            # but that's a minor nit.  Since the original implementation
            # allowed empty dicts that type of behavior probably should be
            # preserved for consistency
        except TypeError:
            ty, va, tb = sys.exc_info()
            raise TypeError("not a valid non-string sequence "
                            "or mapping object").with_traceback(tb)

    if not doseq:
        for k, v in query:
            if isinstance(k, bytes):
                k = quote_via(k, safe)
            else:
                k = quote_via(str(k), safe, encoding, errors)

            if isinstance(v, bytes):
                v = quote_via(v, safe)
            else:
                v = quote_via(str(v), safe, encoding, errors)
            headers[k] = v
    else:
        for k, v in query:
            if isinstance(k, bytes):
                k = quote_via(k, safe)
            else:
                k = quote_via(str(k), safe, encoding, errors)

            if isinstance(v, bytes):
                v = quote_via(v, safe)
                headers[k] = v
            elif isinstance(v, str):
                v = quote_via(v, safe, encoding, errors)
                headers[k] = v
            else:
                try:
                    # Is this a sufficient test for sequence-ness?
                    x = len(v)
                except TypeError:
                    # not a sequence
                    v = quote_via(str(v), safe, encoding, errors)
                    headers[k] = v
                else:
                    # loop over the sequence
                    for elt in v:
                        if isinstance(elt, bytes):
                            elt = quote_via(elt, safe)
                        else:
                            elt = quote_via(str(elt), safe, encoding, errors)
                        headers[k] = v
    return headers


def meta_header_decode(headers, encoding='utf-8', errors='replace'):
    decode_headers = {}
    if encoding is None:
        encoding = 'utf-8'
    if errors is None:
        errors = 'replace'

    for en in headers:
        k = en
        v = headers[en]
        if '%' in k:
            k = unquote_to_bytes(en).decode(encoding, errors)
        if '%' in v:
            v = unquote_to_bytes(headers[en]).decode(encoding, errors)
        decode_headers[k] = v
    return decode_headers


def makedir_p(dirpath):
    try:
        os.makedirs(dirpath)
    except os.error as e:
        if e.errno != errno.EEXIST:
            raise


def get_number(m, n):
    return (m + n - 1) // n


def file_bytes_to_read(fileobj):
    current = fileobj.tell()

    fileobj.seek(0, os.SEEK_END)
    end = fileobj.tell()
    fileobj.seek(current, os.SEEK_SET)

    return end - current


def get_parent_directory_from_File(absolute_path_to_file):
    arr = absolute_path_to_file.split(os.sep)[:-1]
    return os.sep.join(arr)


def _cal_progress_callback(progress_callback, consumed_bytes, total_bytes, rw_once_bytes,
                           type: DataTransferType):
    if progress_callback:
        progress_callback(consumed_bytes, total_bytes, rw_once_bytes, type)


def _cal_rate_limiter_callback(rate_limiter, want):
    if rate_limiter:
        while True:
            result = rate_limiter.acquire(want)
            if result.ok:
                return
            time.sleep(result.time_to_wait)


def _cal_crc_callback(crc_callback, content, discard=0):
    if crc_callback:
        crc_callback(content[discard:])


def _cal_upload_callback(upload_callback, upload_type, err, bucket, key, upload_id, checkpoint_file,
                         upload_part_info):
    if upload_callback:
        upload_callback(upload_type, err, bucket, key, upload_id, checkpoint_file, upload_part_info)


def _cal_download_callback(download_callback, event_type, err, bucket, key, version_id, file_path, checkpoint_file,
                           temp_filepath, download_part_info):
    if download_callback:
        download_callback(event_type, err, bucket, key, version_id, file_path, checkpoint_file, temp_filepath,
                          download_part_info)


class _ReaderAdapter(object):
    """
    通过adapter模式，实现进度条监控、客户端限速、上传crc计算
    """

    def __init__(self, data, progress_callback=None, size=None, crc_callback=None,
                 limiter_callback=None, download_operator=False):
        self.data = to_bytes(data)
        self.progress_callback = progress_callback
        self.size = size
        self.offset = 0
        self.download_operator = download_operator

        self.crc_callback = crc_callback
        self.limiter_callback = limiter_callback

    @property
    def len(self):
        return self.size

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        content = self.read(_CHUNK)

        if content:
            return content
        else:
            raise StopIteration

    def read(self, amt=None):
        if self.offset >= self.size:
            if self.download_operator:
                _cal_progress_callback(self.progress_callback, self.size, self.size, 0,
                                       DataTransferType.Data_Transfer_Succeed)
            return to_bytes('')
        if self.offset == 0:
            _cal_progress_callback(self.progress_callback, min(self.offset, self.size), self.size, 0,
                                   DataTransferType.Data_Transfer_Started)
        if amt is None or amt < 0:
            bytes_to_read = self.size - self.offset
        else:
            bytes_to_read = min(amt, self.size - self.offset)

        if isinstance(self.data, bytes):
            content = self.data[self.offset:self.offset + bytes_to_read]
        else:
            content = self.data.read(bytes_to_read)

        self.offset += bytes_to_read

        _cal_progress_callback(self.progress_callback, min(self.offset, self.size), self.size, bytes_to_read,
                               DataTransferType.Data_Transfer_RW)

        _cal_crc_callback(self.crc_callback, content)

        _cal_rate_limiter_callback(self.limiter_callback, 1)

        return content

    @property
    def crc(self):
        if self.crc_callback:
            return self.crc_callback.crc
        else:
            return 0


def add_progress_listener_func(data, progress_callback, size=None, download_operator=False):
    """
    向data添加进度条监控功能，通过adapter模式实现
    """
    data = to_bytes(data)

    if size is None:
        size = _get_size(data)

    return _ReaderAdapter(data=data, progress_callback=progress_callback, size=size,
                          download_operator=download_operator)


def add_rate_limiter_func(data, rate_limiter):
    """
    返回一个适配器，从而在读取、上传 'data'时，能够通过令牌桶算法进行限速
    """
    data = to_bytes(data)

    return _ReaderAdapter(data=data, limiter_callback=rate_limiter, size=_get_size(data))


def add_crc_func(data, init_crc=0, discard=0, size=None):
    """
    向data中添加crc计算功能，实现上传和下载对象后得到本地对象crc计算值
    """
    data = to_bytes(data)
    if size == None:
        size = _get_size(data)

    return _ReaderAdapter(data, size=size, crc_callback=Crc64(init_crc))


def _get_size(data):
    if hasattr(data, '__len__'):
        return len(data)

    if hasattr(data, 'len'):
        return data.len

    if hasattr(data, 'seek') and hasattr(data, 'tell'):
        return file_bytes_to_read(data)

    return None


class TokenBucketResult(object):
    def __init__(self, ok: bool, time_to_wait: int):
        self.ok = ok
        self.time_to_wait = time_to_wait


class RateLimiter(object):
    """
    令牌桶算法实现
    """

    # rate是令牌发放速度，capacity是桶的⼤⼩
    def __init__(self, rate, capacity):
        self._rate = rate
        self._capacity = capacity
        self._current_amount = 0
        self._demand_count = 0
        self._last_consume_time = int(time.time())
        self._lock = threading.Lock()

    # token_amount是发送数据需要的令牌数
    def acquire(self, want):
        with self._lock:
            increment = (int(time.time()) - self._last_consume_time) * self._rate  # 计算从上次发送到这次发送，新发放的令牌数量
            self._current_amount = min(
                increment + self._current_amount, self._capacity)  # 令牌数量不能超过桶的容量
            if want > self._current_amount:  # 如果没有⾜够的令牌，则不能发送数据
                self._demand_count += want
                time_to_wait = (self._demand_count - self._current_amount) / self._rate
                return TokenBucketResult(False, int(time_to_wait))
            self._last_consume_time = int(time.time())
            self._current_amount -= want
            self._demand_count = max(self._demand_count - want, 0)
            return TokenBucketResult(True, 0)


class Crc64(object):
    _POLY = 0x142F0E1EBA9EA3693
    _XOROUT = 0XFFFFFFFFFFFFFFFF

    def __init__(self, init_crc=0):
        init_crc = int(init_crc)
        self.crc64 = crcmod.Crc(self._POLY, initCrc=init_crc, rev=True, xorOut=self._XOROUT)

        self.crc64_combineFun = mkCombineFun(self._POLY, initCrc=init_crc, rev=True, xorOut=self._XOROUT)

    def __call__(self, data):
        self.update(data)

    def update(self, data):
        self.crc64.update(data)

    def combine(self, crc1, crc2, len2):
        crc2 = int(crc2)
        return self.crc64_combineFun(crc1, crc2, len2)

    @property
    def crc(self):
        return self.crc64.crcValue


def check_crc(operation, client_crc, tos_crc, request_id):
    tos_crc = int(tos_crc)
    if client_crc != tos_crc:
        raise exp.TosClientError(
            "Check CRC failed: req_id: {0}, operation: {1}, CRC checksum of client: {2} is mismatch "
            "with tos: {3}".format(request_id, operation, client_crc, tos_crc))


def rename_file(src, dst):
    os.rename(src, dst)


def cal_crc_from_parts(parts, init_crc=0):
    client_crc = 0
    crc_obj = Crc64(init_crc)
    for part in parts:
        if not part.part_crc or not part.size:
            return None
        client_crc = crc_obj.combine(client_crc, part.part_crc, part.size)
    return client_crc


def copy_and_verify_length(src, dst, expected_len,
                           chunk_size=16 * 1024,
                           request_id=''):
    num = 0

    while 1:
        buf = src.read(chunk_size)
        if not buf:
            break

        num += len(buf)
        dst.write(buf)

    if num != expected_len:
        raise exp.TosClientError("Some error from read source, request_id:{0}".format(request_id))


is_py3 = (sys.version_info[0] == 3)
if is_py3:
    xrange = range
    long = int
    sys.maxint = sys.maxsize


def mkCombineFun(poly, initCrc=~long(0), rev=True, xorOut=0):
    (sizeBits, initCrc, xorOut) = _verifyParams(poly, initCrc, xorOut)

    mask = (long(1) << sizeBits) - 1
    if rev:
        poly = _bitrev(long(poly) & mask, sizeBits)
    else:
        poly = long(poly) & mask

    if sizeBits == 64:
        fun = _combine64
    else:
        raise NotImplemented

    def combine_fun(crc1, crc2, len2):
        return fun(poly, initCrc ^ xorOut, rev, xorOut, crc1, crc2, len2)

    return combine_fun


GF2_DIM = 64


def gf2_matrix_square(square, mat):
    for n in xrange(GF2_DIM):
        square[n] = gf2_matrix_times(mat, mat[n])


def gf2_matrix_times(mat, vec):
    summary = 0
    mat_index = 0

    while vec:
        if vec & 1:
            summary ^= mat[mat_index]

        vec >>= 1
        mat_index += 1

    return summary


def _combine64(poly, initCrc, rev, xorOut, crc1, crc2, len2):
    if len2 == 0:
        return crc1

    even = [0] * GF2_DIM
    odd = [0] * GF2_DIM

    crc1 ^= initCrc ^ xorOut

    if (rev):
        # put operator for one zero bit in odd
        odd[0] = poly  # CRC-64 polynomial
        row = 1
        for n in xrange(1, GF2_DIM):
            odd[n] = row
            row <<= 1
    else:
        row = 2
        for n in xrange(0, GF2_DIM - 1):
            odd[n] = row
            row <<= 1
        odd[GF2_DIM - 1] = poly

    gf2_matrix_square(even, odd)

    gf2_matrix_square(odd, even)

    while True:
        gf2_matrix_square(even, odd)
        if len2 & long(1):
            crc1 = gf2_matrix_times(even, crc1)
        len2 >>= 1
        if len2 == 0:
            break

        gf2_matrix_square(odd, even)
        if len2 & long(1):
            crc1 = gf2_matrix_times(odd, crc1)
        len2 >>= 1

        if len2 == 0:
            break

    crc1 ^= crc2

    return crc1


def _verifyPoly(poly):
    msg = 'The degree of the polynomial must be 8, 16, 24, 32 or 64'
    poly = long(poly)  # Use a common representation for all operations
    for n in (8, 16, 24, 32, 64):
        low = long(1) << n
        high = low * 2
        if low <= poly < high:
            return n
    raise ValueError(msg)


def _bitrev(x, n):
    x = long(x)
    y = long(0)
    for i in xrange(n):
        y = (y << 1) | (x & long(1))
        x = x >> 1
    if ((long(1) << n) - 1) <= sys.maxint:
        return int(y)
    return y


def _verifyParams(poly, initCrc, xorOut):
    sizeBits = _verifyPoly(poly)

    mask = (long(1) << sizeBits) - 1

    initCrc = long(initCrc) & mask
    if mask <= sys.maxint:
        initCrc = int(initCrc)

    xorOut = long(xorOut) & mask
    if mask <= sys.maxint:
        xorOut = int(xorOut)

    return (sizeBits, initCrc, xorOut)
