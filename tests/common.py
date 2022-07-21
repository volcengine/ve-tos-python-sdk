# -*- coding: utf-8 -*-

import tos
import unittest

from requests.structures import CaseInsensitiveDict

from tests.test_v2_bucker import random_string


class TosTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TosTestCase, self).__init__(*args, **kwargs)
        self.bucket_name = 'test_bucket'
        self.key_name = 'test_key'
        self.location = 'cn-beijing'
        self.region = 'beijing'
        self.date = '2021-01-01T00:00:00.000Z'

    def setUp(self):
        self.client = tos.TosClient(tos.Auth('ak', 'sk', 'beijing'), 'tos-cn-beijing.volces.com')


class MockResponse():
    def __init__(self, status_code=200, headers={}, body=None):
        self.status_code = status_code
        self.headers = CaseInsensitiveDict({'x-tos-request-id': '021633693288'})
        self.body = b'{}'
        if isinstance(body, str):
            self.body = body.encode(encoding='utf-8')
        if headers:
            self.headers.update(headers)

    def __iter__(self):
        return self.iter_content(128)

    def iter_content(self, chunk_size=1, decode_unicode=False):
        def generate():
            yield self.body
        return generate()


def random_bytes(n):
    return to_bytes(random_string(n))


def to_bytes(data):
    """若输入为str（即unicode），则转为utf-8编码的bytes；其他则原样返回"""
    if isinstance(data, str):
        return data.encode(encoding='utf-8')
    else:
        return data


