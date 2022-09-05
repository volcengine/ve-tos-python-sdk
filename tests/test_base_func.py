import logging
import os
import time
import unittest
from io import StringIO

import requests
from requests.exceptions import RetryError
from urllib3.exceptions import NewConnectionError

import tos
from tos import DnsCacheService, RateLimiter
from tos.checkpoint import CancelHook
from tos.clientv2 import _handler_retry_policy, _is_wrapper_data, TosClientV2
from tos.exceptions import TosServerError, CancelNotWithAbortError, CancelWithAbortError
from tos.utils import SizeAdapter

tos.set_logger(level=logging.INFO)


class BaseFuncTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(BaseFuncTestCase, self).__init__(*args, **kwargs)
        self.ak = os.getenv('AK')
        self.sk = os.getenv('SK')
        self.endpoint = os.getenv('Endpoint')
        self.region = os.getenv('Region')

    def test_cache(self):
        expire = 2
        cache = DnsCacheService()
        port = 8080
        list_ip = [['1', 1], ['2', 2]]

        cache.add('baidu.com', port, list_ip, expire=int(time.time()) + expire)
        cache.add('baidu.com2', port, list_ip, expire=int(time.time()) + expire)
        entry = cache.get_ip_list('baidu.com', port)
        self.assertIsNotNone(entry)
        time.sleep(1)
        self.assertIsNotNone(cache.get_ip_list('baidu.com', port))
        time.sleep(2)
        self.assertIsNone(cache.get_ip_list('baidu.com', port))

    def test_retry(self):
        with open('out.txt', 'wb') as f:
            f.write(b'123')

        for t in [
            args('', 'GET', '', requests.Timeout(), None, True),
            args('', 'HEAD', '', requests.Timeout(), None, True),
            args('', 'HEAD', '', requests.ConnectionError(), None, True),
            args('', 'HEAD', '', RetryError(), None, True),
            args('', 'PUT', '', requests.Timeout(), None, True),
            args('', 'POST', '', RetryError(), None, True),
            args('', 'POST', '', RetryError(), None, True),
            args('', 'GET', '', NewConnectionError(None, None), None, True),
            args('', 'PUT', 'put_object_acl', None, TestException(429), True),
            args('', 'PUT', 'put_object_acl', None, TestException(501), True),
            args('', 'PUT', 'put_object_acl', None, TestException(301), False),
            args('', 'PUT', 'create_bucket', None, TestException(429), True),
            args('', 'PUT', 'create_bucket', None, TestException(301), False),
            args('', 'DELETE', 'delete_bucket', None, TestException(429), True),
            args('', 'DELETE', 'delete_bucket', None, TestException(301), False),
            args('123', 'PUT', 'create_bucket', None, TestException(429), True),
            args('123', 'PUT', 'upload_part', None, TestException(429), True),

            # 测试 字符串 reset
            args(wrapper_data(
                tos.utils.init_content(SizeAdapter(open('out.txt', 'rb'), 2, init_offset=1, can_reset=True)),
                True, True, True), 'PUT', 'create_bucket', None, TestException(429), True, expect_data=b'23'),

            args(wrapper_data(tos.utils.init_content('123'), True, False, False),
                 'PUT', 'create_bucket', None, TestException(429), True, expect_data=b'123'),

            args(wrapper_data(tos.utils.init_content('123'), False, True, False),
                 'PUT', 'create_bucket', None, TestException(429), True, expect_data=b'123'),

            args(wrapper_data(tos.utils.init_content('123'), False, False, True),
                 'PUT', 'create_bucket', None, TestException(429), True, expect_data=b'123'),

            args(wrapper_data(tos.utils.init_content('123'), True, True, True),
                 'PUT', 'create_bucket', None, TestException(429), True, expect_data=b'123'),

            args(wrapper_data(tos.utils.init_content('123'), False, True, True),
                 'PUT', 'create_bucket', None, TestException(429), True, expect_data=b'123'),

            # 测试 StringIO reset
            args(wrapper_data(tos.utils.init_content(StringIO('123'), init_offset=0), False, False, False),
                 'PUT', 'create_bucket', None, TestException(429), True, expect_data=b'123'),

            args(wrapper_data(tos.utils.init_content(StringIO('123'), init_offset=0), True, True, True),
                 'PUT', 'create_bucket', None, TestException(429), True, expect_data=b'123'),

            # 测试 StringIO reset 偏移
            args(wrapper_data(tos.utils.init_content(StringIO('123'), init_offset=1), False, False, False),
                 'PUT', 'create_bucket', None, TestException(429), True, expect_data=b'23'),

            args(wrapper_data(tos.utils.init_content(StringIO('123'), init_offset=1), True, True, True),
                 'PUT', 'create_bucket', None, TestException(429), True, expect_data=b'23'),
        ]:
            if _is_wrapper_data(data=t.body):
                self.assertTrue(t.body.read(1) != t.body.read(1))
                if t.body.crc_callback:
                    self.assertTrue(t.body.crc != 0)

            got = _handler_retry_policy(t.body, t.method, t.fun_name, t.client_exp, t.server_exp)
            self.assertEqual(t.want, got)

            if _is_wrapper_data(data=t.body):
                if t.body.crc_callback:
                    self.assertTrue(t.body.crc == 0)
            if t.expect_data and _is_wrapper_data(data=t.body):
                self.assertEqual(t.expect_data, t.body.read())
                if t.body.crc_callback:
                    self.assertTrue(t.body.crc != 0)

        os.remove('out.txt')

    def test_cancel_hook(self):
        cancle = CancelHook()
        cancle.cancel(False)
        with self.assertRaises(CancelNotWithAbortError):
            cancle.is_cancel()
        cancle.cancel(True)
        with self.assertRaises(CancelWithAbortError):
            cancle.is_cancel()
class args(object):
    def __init__(self, body, method, fun_name, client_exp, server_exp, want, expect_data=None):
        self.body = body
        self.method = method
        self.fun_name = fun_name
        self.client_exp = client_exp
        self.server_exp = server_exp
        self.want = want
        self.expect_data = expect_data


class TestException(TosServerError):
    def __init__(self, code):
        self.status_code = code

    def __str__(self):
        return str(self.status_code)


def wrapper_data(date, wrapper_progress, wrapper_limiter, wrapper_crc):
    def progress(consumed_bytes, total_bytes, rw_once_bytes,
                 type):
        print("consumed_bytes:{0},total_bytes{1}, rw_once_bytes:{2}, type:{3}".format(consumed_bytes, total_bytes,
                                                                                      rw_once_bytes, type))

    limiter = RateLimiter(1200, 10000)

    if wrapper_progress:
        date = tos.utils.add_progress_listener_func(date, progress_callback=progress)

    if wrapper_limiter:
        date = tos.utils.add_rate_limiter_func(date, rate_limiter=limiter)

    if wrapper_crc:
        date = tos.utils.add_crc_func(date, init_crc=0)

    return date


if __name__ == '__main__':
    unittest.main()
