import unittest

from tests.test_v2_bucker import random_string
from tos import TosClientV2
from tos.exceptions import TosClientError
from tos.utils import generate_http_proxies


class TestFunction(unittest.TestCase):
    def test_generate_proxies(self):
        proxy = generate_http_proxies("10.10.1.10", 3128)
        self.assertEqual("http://10.10.1.10:3128", proxy['http'])
        proxy = generate_http_proxies(None, None)
        self.assertEqual({}, proxy)
        proxy = generate_http_proxies("10.10.1.10", 3128, 'jason', '123456')
        self.assertEqual("http://jason:123456@10.10.1.10:3128/", proxy['http'])


class TestNoTosFunction(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestNoTosFunction, self).__init__(*args, **kwargs)
        self.ak = "***REMOVED***"
        self.sk = "***REMOVED***"
        self.endpoint = "boe-official-test.volces.com"
        self.region = "cn-north-3"
        self.bucket_name = "sun-" + random_string(10)
        self.object_name = "test_object" + random_string(10)
        self.prefix = random_string(12)
        self.key_list = []

    def test_timeout(self):
        client = TosClientV2(self.ak, self.sk, self.endpoint, self.region, connection_time=0.01)
        with self.assertRaises(TosClientError):
            client.create_bucket(bucket=self.bucket_name)



