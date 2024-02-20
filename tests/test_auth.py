# -*- coding: utf-8 -*-

import datetime
import unittest
from unittest import mock

import tos
from tests.common import TosTestCase
from tos import HttpMethodType
from tos.models2 import PostSignatureCondition, ContentLengthRange


class TestAuth(TosTestCase):
    maxDiff = None

    def test_generate_presigned_url(self):
        datetime_mock = mock.Mock(wraps=datetime.datetime)
        datetime_mock.utcnow.return_value = datetime.datetime(2021, 1, 1)
        with mock.patch('datetime.datetime', new=datetime_mock):
            tos_cli = tos.TosClient(tos.Auth('ak', 'sk', 'beijing'), 'tos-cn-beijing.volces.com')
            url = tos_cli.generate_presigned_url(Method='GET', Bucket='bkt', Key='key', ExpiresIn=86400)
            self.assertEqual(url,
                             'https://bkt.tos-cn-beijing.volces.com/key?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Creden'
                             'tial=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Expires=8'
                             '6400&X-Tos-SignedHeaders=host&X-Tos-Signature=b87788cb98d1a5a91a046d20eb212ffc22cf7cd'
                             '4c1d4e9bd2d15a989afb97d2f')

            tos_cli = tos.TosClient(tos.Auth('ak', 'sk', 'beijing', sts='sts'), 'tos-cn-beijing.volces.com')
            url = tos_cli.generate_presigned_url(Method='PUT', Bucket='bkt', Key='key')
            self.assertEqual(url,
                             'https://bkt.tos-cn-beijing.volces.com/key?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Credentia'
                             'l=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Expires=36'
                             '00&X-Tos-Security-Token=sts&X-Tos-SignedHeaders=host&X-Tos-Signature=3041fb481e31ec25f'
                             'e7a1be44cafe25caf1cd97228710ee440b2ca1bd49bc563')

            url = tos_cli.generate_presigned_url(Method='PUT', Bucket='bkt', Key='key', Params={'acl': ''})
            self.assertEqual(url,
                             'https://bkt.tos-cn-beijing.volces.com/key?acl&X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-C'
                             'redential=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Exp'
                             'ires=3600&X-Tos-Security-Token=sts&X-Tos-SignedHeaders=host&X-Tos-Signature=51c89070206'
                             'dd438fd8be1ed201a77335af80e33cad5fd408841590b99aa93d3')

    def test_client2_presigned_url(self):
        datetime_mock = mock.Mock(wraps=datetime.datetime)
        datetime_mock.utcnow.return_value = datetime.datetime(2021, 1, 1)
        with mock.patch('datetime.datetime', new=datetime_mock):
            tos_cli = tos.TosClientV2(ak='ak', sk='sk', endpoint='tos-cn-beijing.volces.com', region='beijing')
            url = tos_cli.pre_signed_url(http_method=HttpMethodType.Http_Method_Get, bucket='bkt', key='key',
                                         expires=704800)
            print(url.signed_url)
            self.assertEqual(url.signed_url,
                             'https://bkt.tos-cn-beijing.volces.com/key?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Credential=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Expires=704800&X-Tos-SignedHeaders=host&X-Tos-Signature=087f3eb174b6accb37178630ba5890d7d8bc8a33495e25959dc359dc4b0f1170')
            'https://bkt.tos-cn-beijing.volces.com/key?X-Tos-Expires=86400&X-Tos-SignedHeaders=host&X-Tos-Credential=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Signature=b87788cb98d1a5a91a046d20eb212ffc22cf7cd4c1d4e9bd2d15a989afb97d2f&X-Tos-Algorithm=TOS4-HMAC-SHA256'

            tos_cli = tos.TosClientV2(ak='ak', sk='sk', endpoint='tos-cn-beijing.volces.com1', region='beijing')
            url = tos_cli.pre_signed_url(http_method=HttpMethodType.Http_Method_Get, bucket='bkt', key='key',
                                         expires=86400, alternative_endpoint='tos-cn-beijing.volces.com')
            self.assertEqual(url.signed_url,
                             'https://bkt.tos-cn-beijing.volces.com/key?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Creden'
                             'tial=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Expires=8'
                             '6400&X-Tos-SignedHeaders=host&X-Tos-Signature=b87788cb98d1a5a91a046d20eb212ffc22cf7cd'
                             '4c1d4e9bd2d15a989afb97d2f')

            tos_cli = tos.TosClientV2(ak='ak', sk='sk', endpoint='tos-cn-beijing.volces.com', region='beijing',
                                      security_token='sts')
            url = tos_cli.pre_signed_url(http_method=HttpMethodType.Http_Method_Put, bucket='bkt', key='key',
                                         query={'acl': ''})

            self.assertEqual(url.signed_url,
                             'https://bkt.tos-cn-beijing.volces.com/key?acl&X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-C'
                             'redential=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Exp'
                             'ires=3600&X-Tos-Security-Token=sts&X-Tos-SignedHeaders=host&X-Tos-Signature=51c89070206'
                             'dd438fd8be1ed201a77335af80e33cad5fd408841590b99aa93d3')

            url = tos_cli.pre_signed_url(http_method=HttpMethodType.Http_Method_Put, bucket='bkt', key='key')
            self.assertEqual(url.signed_url,
                             'https://bkt.tos-cn-beijing.volces.com/key?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Credentia'
                             'l=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Expires=36'
                             '00&X-Tos-Security-Token=sts&X-Tos-SignedHeaders=host&X-Tos-Signature=3041fb481e31ec25f'
                             'e7a1be44cafe25caf1cd97228710ee440b2ca1bd49bc563')
            url = tos_cli.pre_signed_url(http_method=HttpMethodType.Http_Method_Put, bucket='bkt', key='key',
                                         expires=1234, header={'contentLength': 1000})
            self.assertTrue('1234' in url.signed_url)
            self.assertTrue('contentlength' not in url.signed_url)

            self.anonymousCli = tos.TosClientV2(ak='', sk='', endpoint='tos-cn-beijing.volces.com', region='beijing')
            url = self.anonymousCli.pre_signed_url(http_method=HttpMethodType.Http_Method_Put, bucket='bkt', key='key',
                                                   header={'contentLength': 1000}, query={'t1': 't1'})
            self.assertEqual(url.signed_url, 'https://bkt.tos-cn-beijing.volces.com/key?t1=t1')

            url = self.anonymousCli.pre_signed_url(http_method=HttpMethodType.Http_Method_Put, bucket='bkt', key='key')
            self.assertEqual(url.signed_url, 'https://bkt.tos-cn-beijing.volces.com/key?')

    def test_pre_signed_post_signature(self):
        datetime_mock = mock.Mock(wraps=datetime.datetime)
        datetime_mock.utcnow.return_value = datetime.datetime(2022, 1, 1)
        with mock.patch('datetime.datetime', new=datetime_mock):
            tos_cli = tos.TosClientV2(ak='ak', sk='sk', endpoint='tos-cn-beijing.volces.com', region='beijing')
            conditions = [PostSignatureCondition(key='acl', value='public-read'),
                          PostSignatureCondition(key='Content-Type', value='image/', operator='starts-with')]
            # conditions.append(PostSignatureCondition(key="key", value="example", operator="starts-with"))
            content_length_range = ContentLengthRange(range_start=1023, range_end=10000)
            out = tos_cli.pre_signed_post_signature(bucket='testBucket', key='test_object', conditions=conditions,
                                                    expires=704800, content_length_range=content_length_range)

    def test_pre_signed_policy_url(self):
        datetime_mock = mock.Mock(wraps=datetime.datetime)
        datetime_mock.utcnow.return_value = datetime.datetime(2022, 1, 1)
        with mock.patch('datetime.datetime', new=datetime_mock):
            tos_cli = tos.TosClientV2(ak='ak', sk='sk', endpoint='tos-cn-beijing.volces.com', region='beijing')
            conditions = [PostSignatureCondition(key='bucket', value='examplebucket'),
                          PostSignatureCondition(key='key', value='abc/', operator='starts-with'),
                          PostSignatureCondition(key='key', value='aaa/abc/', operator='starts-with'),
                          PostSignatureCondition(key='key', value='exampleobject', operator='eq'),
                          PostSignatureCondition(key='key', value='exampleobject1', operator='eq')]
            out = tos_cli.pre_signed_policy_url(bucket='test', conditions=conditions, expires=704800)
            list_1 = out.get_signed_url_for_list({'k1': 'v1', 'k2': 'v2'})
            self.assertEqual(list_1,
                             'https://test.tos-cn-beijing.volces.com?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Credential=ak%2F20220101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20220101T000000Z&X-Tos-Expires=704800&X-Tos-Policy=eyJjb25kaXRpb25zIjogW3siYnVja2V0IjogImV4YW1wbGVidWNrZXQifSwgWyJzdGFydHMtd2l0aCIsICIka2V5IiwgImFiYy8iXSwgWyJzdGFydHMtd2l0aCIsICIka2V5IiwgImFhYS9hYmMvIl0sIFsiZXEiLCAiJGtleSIsICJleGFtcGxlb2JqZWN0Il0sIFsiZXEiLCAiJGtleSIsICJleGFtcGxlb2JqZWN0MSJdLCB7ImJ1Y2tldCI6ICJ0ZXN0In1dfQ%3D%3D&X-Tos-Signature=869b9e678a6a69ce4a1cd02c7c0e333cb8e7a312a1078563dd2619d3daa9f5ee&k1=v1&k2=v2')
            get = out.get_signed_url_for_get_or_head(key='exampleobject', additional_query={'k1': 'v1', 'k2': 'v2'})
            self.assertEqual(get,
                             'https://test.tos-cn-beijing.volces.com/exampleobject?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Credential=ak%2F20220101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20220101T000000Z&X-Tos-Expires=704800&X-Tos-Policy=eyJjb25kaXRpb25zIjogW3siYnVja2V0IjogImV4YW1wbGVidWNrZXQifSwgWyJzdGFydHMtd2l0aCIsICIka2V5IiwgImFiYy8iXSwgWyJzdGFydHMtd2l0aCIsICIka2V5IiwgImFhYS9hYmMvIl0sIFsiZXEiLCAiJGtleSIsICJleGFtcGxlb2JqZWN0Il0sIFsiZXEiLCAiJGtleSIsICJleGFtcGxlb2JqZWN0MSJdLCB7ImJ1Y2tldCI6ICJ0ZXN0In1dfQ%3D%3D&X-Tos-Signature=869b9e678a6a69ce4a1cd02c7c0e333cb8e7a312a1078563dd2619d3daa9f5ee&k1=v1&k2=v2')

            anonymous_cli = tos.TosClientV2(ak='', sk='', endpoint='tos-cn-beijing.volces.com', region='beijing')
            out = anonymous_cli.pre_signed_policy_url(bucket='test', conditions=conditions)
            list_1 = out.get_signed_url_for_list({'k1': 'v1', 'k2': 'v2'})
            self.assertEqual(list_1,
                             'https://test.tos-cn-beijing.volces.com?X-Tos-Policy=eyJjb25kaXRpb25zIjogW3siYnVja2V0IjogImV4YW1wbGVidWNrZXQifSwgWyJzdGFydHMtd2l0aCIsICIka2V5IiwgImFiYy8iXSwgWyJzdGFydHMtd2l0aCIsICIka2V5IiwgImFhYS9hYmMvIl0sIFsiZXEiLCAiJGtleSIsICJleGFtcGxlb2JqZWN0Il0sIFsiZXEiLCAiJGtleSIsICJleGFtcGxlb2JqZWN0MSJdLCB7ImJ1Y2tldCI6ICJ0ZXN0In0sIHsiYnVja2V0IjogInRlc3QifV19&k1=v1&k2=v2')
            get = out.get_signed_url_for_get_or_head(key='exampleobject', additional_query={'k1': 'v1', 'k2': 'v2'})
            self.assertEqual(get,
                             'https://test.tos-cn-beijing.volces.com/exampleobject?X-Tos-Policy=eyJjb25kaXRpb25zIjogW3siYnVja2V0IjogImV4YW1wbGVidWNrZXQifSwgWyJzdGFydHMtd2l0aCIsICIka2V5IiwgImFiYy8iXSwgWyJzdGFydHMtd2l0aCIsICIka2V5IiwgImFhYS9hYmMvIl0sIFsiZXEiLCAiJGtleSIsICJleGFtcGxlb2JqZWN0Il0sIFsiZXEiLCAiJGtleSIsICJleGFtcGxlb2JqZWN0MSJdLCB7ImJ1Y2tldCI6ICJ0ZXN0In0sIHsiYnVja2V0IjogInRlc3QifV19&k1=v1&k2=v2')


if __name__ == '__main__':
    unittest.main()
