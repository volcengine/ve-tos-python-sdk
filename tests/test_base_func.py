# -*- coding: utf-8 -*-
import datetime
import os
import time
import unittest
from io import StringIO
from unittest import mock
import requests
from requests.exceptions import RetryError
from urllib3.exceptions import NewConnectionError

import tos
from tos import DnsCacheService, RateLimiter, exceptions, utils, convert_storage_class_type, ACLType, convert_acl_type, \
    StorageClassType, MetadataDirectiveType, convert_metadata_directive_type, AzRedundancyType, \
    convert_az_redundancy_type, PermissionType, convert_permission_type, GranteeType, convert_grantee_type, \
    convert_canned_type, CannedType, RedirectType, convert_redirect_type, StatusType, convert_status_type, \
    StorageClassInheritDirectiveType, convert_storage_class_inherit_directive_type, VersioningStatusType, \
    convert_versioning_status_type, ProtocolType, convert_protocol_type, CertStatus, convert_cert_status, \
    StaticCredentialsProvider
from tos.auth import CredentialProviderAuth
from tos.checkpoint import CancelHook
from tos.clientv2 import _handler_retry_policy, _is_wrapper_data, _signed_req
from tos.exceptions import TosServerError, CancelNotWithAbortError, CancelWithAbortError
from tos.http import Response, Request
from tos.utils import SizeAdapter


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

    def test_stop_check(self):
        io = StringIO("123")
        req = TestResponse(4, io)
        with self.assertRaises(tos.exceptions.TosClientError):
            req.read()

        io = StringIO("123")
        req = TestResponse(4, io)
        with self.assertRaises(tos.exceptions.TosClientError):
            for content in req:
                print(content)

        io = StringIO("123")
        req = TestResponse(3, io)
        for content in req:
            print(content)

    def test_with_endpint(self):
        client = tos.TosClientV2(self.ak, self.sk, self.endpoint, self.region)
        self.assertEqual(client.endpoint, "https://" + self.endpoint)
        self.assertEqual(client.scheme, "https://")
        self.assertEqual(client.host, self.endpoint)

        client_2 = tos.TosClientV2(self.ak, self.sk, 'http://' + self.endpoint, self.region)
        self.assertEqual(client_2.endpoint, "http://" + self.endpoint)
        self.assertEqual(client_2.host, self.endpoint)
        self.assertEqual(client_2.scheme, "http://")

        client = tos.TosClientV2(self.ak, self.sk, "", "cn-beijing")
        self.assertEqual(client.endpoint, 'https://' + 'tos-cn-beijing.volces.com')
        self.assertEqual(client.host, 'tos-cn-beijing.volces.com')
        self.assertEqual(client.scheme, 'https://')

        client = tos.TosClientV2(self.ak, self.sk, "tos-cn-beijing.ivolces.com", "cn-beijing")
        self.assertEqual(client.endpoint, 'https://' + 'tos-cn-beijing.ivolces.com')
        self.assertEqual(client.host, 'tos-cn-beijing.ivolces.com')
        self.assertEqual(client.scheme, 'https://')

    def test_with_invalid_endpint(self):
        with self.assertRaises(tos.exceptions.TosClientError):
            tos.TosClientV2(self.ak, self.sk, 'tos-s3-cn-beijing.volces.com', self.region)

    def test_convert_enum_type(self):
        for t in ACLType:
            assert t == convert_acl_type(t.value)
        assert ACLType.ACL_Unknown == convert_acl_type('test')

        for t in StorageClassType:
            assert t == convert_storage_class_type(t.value)
        assert StorageClassType.Storage_Unknown == convert_storage_class_type('test')

        for t in MetadataDirectiveType:
            assert t == convert_metadata_directive_type(t.value)
        assert MetadataDirectiveType.Metadata_Directive_Unknown == convert_metadata_directive_type('test')

        for t in AzRedundancyType:
            assert t == convert_az_redundancy_type(t.value)
        assert AzRedundancyType.Az_Redundancy_Unknown == convert_az_redundancy_type('test')

        for t in PermissionType:
            assert t == convert_permission_type(t.value)
        assert PermissionType.Permission_Unknown == convert_permission_type('test')

        for t in GranteeType:
            assert t == convert_grantee_type(t.value)
        assert GranteeType.Grantee_Unknown == convert_grantee_type('test')

        for t in CannedType:
            assert t == convert_canned_type(t.value)
        assert CannedType.Canned_Unknown == convert_canned_type('test')

        for t in RedirectType:
            assert t == convert_redirect_type(t.value)
        assert RedirectType.Unknown == convert_redirect_type('test')

        for t in StatusType:
            assert t == convert_status_type(t.value)
        assert StatusType.Status_Unknown == convert_status_type('test')

        for t in StorageClassInheritDirectiveType:
            assert t == convert_storage_class_inherit_directive_type(t.value)
        assert StorageClassInheritDirectiveType.Storage_Class_Unknown == convert_storage_class_inherit_directive_type(
            'test')

        for t in VersioningStatusType:
            assert t == convert_versioning_status_type(t.value)
        assert VersioningStatusType.Versioning_Unknown == convert_versioning_status_type('test')

        for t in ProtocolType:
            assert t == convert_protocol_type(t.value)
        assert ProtocolType.Protocol_Unknown == convert_protocol_type('test')

        for t in CertStatus:
            assert t == convert_cert_status(t.value)
        assert CertStatus.Cert_Unknown == convert_cert_status('test')

    def test_sign_req(self):
        auth = CredentialProviderAuth(StaticCredentialsProvider('ak', 'sk', 'sts'), 'region')
        host = 'zzz.com'
        headers = {'content-type': 'application/json', 'Host': host}
        params = {'versionId': 'test'}

        req = Request('GET', 'http://zzz.com/key', 'key', 'zzz.com',
                      params=params,
                      headers=headers)

        datetime_mock = mock.Mock(wraps=datetime.datetime)
        datetime_mock.utcnow.return_value = datetime.datetime(2021, 1, 1)
        with mock.patch('datetime.datetime', new=datetime_mock):
            req = _signed_req(auth, req, host)
            self.assertEqual(req.headers['Authorization'],
                             'TOS4-HMAC-SHA256 Credential=ak/20210101/region/tos/request, '
                             'SignedHeaders=content-type;host;x-tos-date;x-tos-security-token, Signature=ca8eb8987663e61e740bc5be9078d6d4f716990573a56c86a6602d42faf3af7e')
            self.assertEqual(req.headers['Host'], host)
            self.assertEqual(req.headers['x-tos-date'], '20210101T000000Z')
            self.assertEqual(req.headers['x-tos-security-token'], 'sts')


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


class TestResponse(Response):
    def __init__(self, length, body):
        self.content_length = length
        self.resp = body
        self._all_read = False
        self.offset = 0

    def read(self, amt=None):
        if self._all_read:
            return b''

        if amt is None:
            content = self.resp.read()

            self._all_read = True
            if self.content_length and len(content) != self.content_length:
                raise tos.exceptions.TosClientError('IO Content not equal content-length')
            return content
        else:
            try:
                read = next(self.resp)
                self.offset += len(read)
                return read
            except StopIteration:
                if self.content_length and self.offset != self.content_length:
                    raise exceptions.TosClientError('IO Content not equal content-length')
                self._all_read = True
                return b''


if __name__ == '__main__':
    unittest.main()
