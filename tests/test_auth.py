# -*- coding: utf-8 -*-

import tos
import pytz
import datetime
from unittest import mock
from .common import *

class TestAuth(TosTestCase):
    def test_generate_presigned_url(self):
        datetime_mock = mock.Mock(wraps=datetime.datetime)
        datetime_mock.utcnow.return_value = datetime.datetime(2021, 1, 1)
        with mock.patch('datetime.datetime', new=datetime_mock):
            tos_cli = tos.TosClient(tos.Auth('ak', 'sk', 'beijing'), 'tos-cn-beijing.volces.com')
            url = tos_cli.generate_presigned_url(Method='GET', Bucket='bkt', Key='key', ExpiresIn=86400)
            self.assertEqual(url,
                             'http://bkt.tos-cn-beijing.volces.com/key?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Credential=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Expires=86400&X-Tos-SignedHeaders=host&X-Tos-Signature=b87788cb98d1a5a91a046d20eb212ffc22cf7cd4c1d4e9bd2d15a989afb97d2f')

            tos_cli = tos.TosClient(tos.Auth('ak', 'sk', 'beijing', sts='sts'), 'tos-cn-beijing.volces.com')
            url = tos_cli.generate_presigned_url(Method='PUT', Bucket='bkt', Key='key')
            self.assertEqual(url,
                             'http://bkt.tos-cn-beijing.volces.com/key?X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Credential=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Expires=3600&X-Tos-SignedHeaders=host&X-Tos-Security-Token=sts&X-Tos-Signature=3041fb481e31ec25fe7a1be44cafe25caf1cd97228710ee440b2ca1bd49bc563')

            url = tos_cli.generate_presigned_url(Method='PUT', Bucket='bkt', Key='key', Params={'acl':''})
            self.assertEqual(url,
                             'http://bkt.tos-cn-beijing.volces.com/key?acl&X-Tos-Algorithm=TOS4-HMAC-SHA256&X-Tos-Credential=ak%2F20210101%2Fbeijing%2Ftos%2Frequest&X-Tos-Date=20210101T000000Z&X-Tos-Expires=3600&X-Tos-SignedHeaders=host&X-Tos-Security-Token=sts&X-Tos-Signature=51c89070206dd438fd8be1ed201a77335af80e33cad5fd408841590b99aa93d3')


if __name__ == '__main__':
    unittest.main()