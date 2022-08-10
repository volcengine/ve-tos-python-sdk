# -*- coding: utf-8 -*-

import datetime
import logging
import unittest
from unittest import mock

import tos
from tests.common import TosTestCase
from tos import HttpMethodType

tos.set_logger(level=logging.DEBUG)


class TestAuth(TosTestCase):
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
                             '00&X-Tos-SignedHeaders=host&X-Tos-Security-Token=sts&X-Tos-Signature=3041fb481e31ec25f'
                             'e7a1be44cafe25caf1cd97228710ee440b2ca1bd49bc563')

            url = tos_cli.generate_presigned_url(Method='PUT', Bucket='bkt', Key='key', Params={'acl': ''})
            self.assertEqual(url,
                             'https://bkt.tos-cn-beijing.volces.com/key?acl&X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-C'
                             'redential=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Exp'
                             'ires=3600&X-Tos-SignedHeaders=host&X-Tos-Security-Token=sts&X-Tos-Signature=51c89070206'
                             'dd438fd8be1ed201a77335af80e33cad5fd408841590b99aa93d3')

    def test_client2_presigned_url(self):
        datetime_mock = mock.Mock(wraps=datetime.datetime)
        datetime_mock.utcnow.return_value = datetime.datetime(2021, 1, 1)
        with mock.patch('datetime.datetime', new=datetime_mock):
            tos_cli = tos.TosClientV2(ak='ak', sk='sk', endpoint='tos-cn-beijing.volces.com', region='beijing')
            url = tos_cli.pre_signed_url(http_method=HttpMethodType.Http_Method_Get, bucket='bkt', key='key',
                                         expires=86400)
            self.assertEqual(url.signed_url,
                             'https://bkt.tos-cn-beijing.volces.com/key?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Creden'
                             'tial=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Expires=8'
                             '6400&X-Tos-SignedHeaders=host&X-Tos-Signature=b87788cb98d1a5a91a046d20eb212ffc22cf7cd'
                             '4c1d4e9bd2d15a989afb97d2f')

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
                             'ires=3600&X-Tos-SignedHeaders=host&X-Tos-Security-Token=sts&X-Tos-Signature=51c89070206'
                             'dd438fd8be1ed201a77335af80e33cad5fd408841590b99aa93d3')

            url = tos_cli.pre_signed_url(http_method=HttpMethodType.Http_Method_Put, bucket='bkt', key='key')
            self.assertEqual(url.signed_url,
                             'https://bkt.tos-cn-beijing.volces.com/key?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Credentia'
                             'l=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Expires=36'
                             '00&X-Tos-SignedHeaders=host&X-Tos-Security-Token=sts&X-Tos-Signature=3041fb481e31ec25f'
                             'e7a1be44cafe25caf1cd97228710ee440b2ca1bd49bc563')


if __name__ == '__main__':
    unittest.main()
