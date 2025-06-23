# -*- coding: utf-8 -*-
import base64
import errno
import hashlib
import json
import os
import random
import re
import string
import time
import unittest

from requests.structures import CaseInsensitiveDict

import tos
from tos import TosClientV2
from tos.credential import StaticCredentialsProvider


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


class TosTestBase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TosTestBase, self).__init__(*args, **kwargs)
        self.ak = os.getenv('AK')
        self.sk = os.getenv('SK')
        self.endpoint = os.getenv('Endpoint')
        self.endpoint2 = os.getenv('Endpoint2')
        self.region = os.getenv('Region')
        self.region2 = os.getenv('Region2')
        self.bucket_name = "sun-" + random_string(10)

        self.mq_instance_id = os.getenv('MqInstanceId')
        self.account_id = os.getenv('AccountId')
        self.mq_role_name = os.getenv('MqRoleName')
        self.mq_access_key_id = os.getenv('MqAccessKeyId')
        self.callback = os.getenv('Callback')
        self.callback_var = os.getenv('CallbackVar')
        self.object_name = "test_object" + random_string(10)
        self.prefix = random_string(12)
        self.bucket_delete = []
        self.temp_files = []
        self.sseKey = "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M="
        self.sseKeyMd5 = "ACdH+Fu9K3HlXdIUBu8GdA=="
        self.sseAlg = "AES256"
        self.callback_url = os.getenv('CallbackUrl')
        self.cloud_function = os.getenv('CloudFunction')

    def setUp(self):
        self.client = TosClientV2(self.ak, self.sk, self.endpoint, self.region, enable_crc=True, max_retry_count=2)
        self.version_client = TestClient2(self.ak, self.sk, self.endpoint, self.region,
                                          max_retry_count=2)
        self.client2 = TosClientV2(endpoint=self.endpoint2, region=self.region2, enable_crc=True, max_retry_count=2,
                                   credentials_provider=StaticCredentialsProvider(self.ak, self.sk))

    def tearDown(self):
        for file in self.temp_files:
            try:
                os.remove(file)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise
        for bkt in self.bucket_delete:
            clean_and_delete_bucket(self.client, bkt)
            clean_and_delete_bucket(self.client2, bkt)

        self.client.close()
        self.client2.close()

    def assertFileContent(self, filename, content):
        with open(filename, 'rb') as f:
            read = f.read()
            self.assertEqual(len(read), len(content))
            self.assertEqual(read, content)

    def assertObjectContent(self, bucket, key, content):
        out = self.client.get_object(bucket=bucket, key=key)
        self.assertEqual(out.read(), content)

    def assertDownloadUploadFile(self, upload, download):
        with open(upload, 'rb') as fu:
            with open(download, 'rb') as fd:
                up = fu.read()
                down = fd.read()
                self.assertEqual(len(up), len(down))
                self.assertEqual(up, down)

    def random_key(self, suffix=''):
        key = self.prefix + random_string(12) + suffix
        return key

    def random_filename(self):
        filename = random_string(16)
        self.temp_files.append(filename)

        return filename


def random_string(n):
    return ''.join(random.choice(string.ascii_lowercase) for i in range(n))


def to_bytes(data):
    """若输入为str（即unicode），则转为utf-8编码的bytes；其他则原样返回"""
    if isinstance(data, str):
        return data.encode(encoding='utf-8')
    else:
        return data


def calculate_md5(content):
    md5 = hashlib.md5()
    buf = content.read()
    md5.update(buf)
    return base64.b64encode(md5.digest())


def random_bytes(n):
    return to_bytes(random_string(n))


class TestClient2(TosClientV2):

    def put_bucket_versioning(self, bucket, enable=False):
        data = {}
        if enable:
            data['Status'] = 'Enabled'
        else:
            data['Status'] = 'Suspended'

        query = {}
        params = {'versioning': ''}
        data = json.dumps(data)
        resp = super(TestClient2, self)._req(bucket=bucket, method='PUT', data=data, params=params)
        return resp


def clean_and_delete_bucket(tos_client: tos.TosClientV2, bucket: str, retry_times=3):
    for i in range(retry_times):
        try:
            tos_client.head_bucket(bucket=bucket)
        except tos.exceptions.TosServerError as e:
            status = e.status_code
            if status == 404:
                return

        try:
            truncated = True

            while truncated:
                rsp = tos_client.list_objects(bucket=bucket)
                truncated = rsp.is_truncated

                for obj in rsp.contents:
                    tos_client.delete_object(bucket=bucket, key=obj.key)

            truncated = True
            while truncated:
                rsp = tos_client.list_object_versions(bucket=bucket)
                truncated = rsp.is_truncated

                for obj in rsp.versions:
                    tos_client.delete_object(bucket, obj.key, obj.version_id)

                for obj in rsp.delete_markers:
                    tos_client.delete_object(bucket=bucket, key=obj.key, version_id=obj.version_id)

            truncated = True
            while truncated:
                rsp = tos_client.list_multipart_uploads(bucket=bucket)
                truncated = rsp.is_truncated

                for upload in rsp.uploads:
                    tos_client.abort_multipart_upload(bucket=bucket, key=upload.key, upload_id=upload.upload_id)

            tos_client.delete_bucket(bucket=bucket)
            return
        except tos.exceptions.TosServerError as e:
            print(e)


def clean_and_delete_bucket_with_prefix(tos_client: tos.TosClientV2, prefix: str):
    l = tos_client.list_buckets()

    for bkc in l.buckets:
        bkc_name = bkc.name
        if re.match('^{}'.format(prefix), bkc_name):
            clean_and_delete_bucket(tos_client=tos_client, bucket=bkc_name)
