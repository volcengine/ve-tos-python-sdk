import os
import random
import re
import string
import time as tim
import unittest

from tos.clientv2 import TosClientV2
from tos.enum import StorageClassType, ACLType
from tos.exceptions import TosClientError, TosServerError


def random_string(n):
    return ''.join(random.choice(string.ascii_lowercase) for i in range(n))


class TestBucket(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestBucket, self).__init__(*args, **kwargs)
        self.ak = os.getenv('AK')
        self.sk = os.getenv('SK')
        self.endpoint = os.getenv('Endpoint')
        self.region = os.getenv('Region')
        self.bucket_name = "sun-" + random_string(2)
        self.object_name = "test_object" + random_string(10)

    def setUp(self):
        # 本地测试
        # self.client = TosClientV2(self.ak, self.sk, self.endpoint, self.region, proxy_host='127.0.0.1', proxy_port=7428,
        #                           enable_crc=False)

        self.client = TosClientV2(self.ak, self.sk, self.endpoint, self.region)

    def test_bucket(self):
        bucket_name = self.bucket_name + "basic"

        create_bucket_out = self.client.create_bucket(bucket_name)
        self.retry_assert(lambda: self.bucket_name + "basic" in
                                  (b.name for b in
                                   self.client.list_buckets().buckets))

        key = 'a.txt'
        put_object_out = self.client.put_object(bucket_name, key=key, content="contenet")

        with self.assertRaises(TosServerError):
            self.client.delete_bucket(bucket_name)

        delete_object_out = self.client.delete_object(bucket_name, key)
        delete_bucket_out = self.client.delete_bucket(bucket_name)

    def test_bucket_with_storage_class(self):
        bucket_name = self.bucket_name + "storage-class"

        create_bucket_out = self.client.create_bucket(bucket_name,
                                                      storage_class=StorageClassType.Storage_Class_Ia)
        self.retry_assert(lambda: bucket_name in
                                  (b.name for b in
                                   self.client.list_buckets().buckets))

        key = 'a.txt'
        put_object_out = self.client.put_object(bucket_name, key=key, content="content")

        head_bucket_out = self.client.head_bucket(bucket_name)
        self.assertEqual(head_bucket_out.storage_class, StorageClassType.Storage_Class_Ia)
        self.assertIsNotNone(head_bucket_out.region)

        with self.assertRaises(TosServerError):
            self.client.delete_bucket(bucket_name)

        list_objects_out = self.client.list_objects(bucket_name)
        self.assertEqual(1, len(list_objects_out.contents))

        self.assertEqual(list_objects_out.contents[0].storage_class.value, StorageClassType.Storage_Class_Ia.value)

        with self.assertRaises(TosServerError):
            self.client.delete_bucket(bucket_name)

        delete_object_out = self.client.delete_object(bucket_name, key)
        delete_bucket_out = self.client.delete_bucket(bucket_name)

        with self.assertRaises(TosServerError):
            self.client.head_bucket(bucket_name + "-")

    def test_create_bucket_with_illegal_name(self):
        # 测试桶名在3-63个字符内
        with self.assertRaises(TosClientError):
            name = ""
            for i in range(64):
                name = name + '1'
            self.client.create_bucket(name)
        with self.assertRaises(TosClientError):
            self.client.create_bucket("12")

        with self.assertRaises(TosClientError):
            self.client.create_bucket("12A3")
        with self.assertRaises(TosClientError):
            self.client.create_bucket("12_3")

        with self.assertRaises(TosClientError):
            self.client.create_bucket("_123")

        with self.assertRaises(TosClientError):
            self.client.create_bucket("123_")

    def test_bucket_info(self):
        bucket_name = self.bucket_name + "-info"
        with self.assertRaises(TosServerError):
            self.client.head_bucket(bucket_name)

        create_bucket_out = self.client.create_bucket(bucket_name,
                                                      storage_class=StorageClassType.Storage_Class_Ia)
        self.retry_assert(lambda: bucket_name in
                                  (b.name for b in
                                   self.client.list_buckets().buckets))

        list_bucket_out = self.client.list_buckets()
        self.assertTrue(len(list_bucket_out.buckets) >= 1)
        self.assertTrue(len(list_bucket_out.owner.id) > 0)
        self.assertTrue(len(list_bucket_out.id2) > 0)
        self.assertTrue(len(list_bucket_out.request_id) > 0)
        self.assertTrue(list_bucket_out.status_code == 200)

        bucket = list_bucket_out.buckets[0]
        self.assertTrue(len(bucket.name) > 0)
        self.assertTrue(len(bucket.location) > 0)
        self.assertTrue(len(bucket.creation_date) > 0)
        self.assertTrue(len(bucket.extranet_endpoint) > 0)
        self.assertTrue(len(bucket.intranet_endpoint) > 0)
        owner = list_bucket_out.owner
        self.assertTrue(len(owner.id) > 0)

    def test_bucket_with_acl(self):
        bucket_name = self.bucket_name + "-acl"
        create_bucket_acl_out = self.client.create_bucket(bucket_name, acl=ACLType.ACL_Bucket_Owner_Full_Control)
        self.retry_assert(lambda: bucket_name in
                                  (b.name for b in
                                   self.client.list_buckets().buckets))

        self.client.delete_bucket(bucket_name)

    def test_delete_all(self):
        list_out = self.client.list_buckets()
        for bkc in list_out.buckets:
            bkc_name = bkc.name
            n = re.match('^sun-', bkc_name)
            if not n:
                continue
            else:
                objects = self.client.list_objects(bkc.name)
                for obj in objects.contents:
                    if obj.key == None:
                        print(obj)
                        print(bkc)
                    self.client.delete_object(bkc.name, obj.key)
                try:
                    self.client.delete_bucket(bkc_name)
                except Exception as e:
                    print(e)

    def retry_assert(self, func):
        for i in range(5):
            if func():
                return
            else:
                tim.sleep(i + 2)

        self.assertTrue(False)
