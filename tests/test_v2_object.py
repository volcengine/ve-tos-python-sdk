# -*- coding: utf-8 -*-

import datetime
import os
import unittest
from io import StringIO

import requests

import tos.models2
from tests.common import TosTestBase, random_string, random_bytes, calculate_md5
from tos.enum import (ACLType, AzRedundancyType, DataTransferType,
                      GranteeType, MetadataDirectiveType, PermissionType,
                      StorageClassType)
from tos.exceptions import TosClientError, TosServerError
from tos.models2 import Deleted, Grant, Grantee, ListObjectsOutput, Owner, ObjectTobeDeleted, Tag, \
    PostSignatureCondition
from tos.utils import RateLimiter


class TestObject(TosTestBase):
    def test_object(self):
        bucket_name = self.bucket_name + '-test-object'
        self.bucket_delete.append(bucket_name)
        key = self.random_key('.js')
        content = random_bytes(1024)

        self.client.create_bucket(bucket_name)
        put_object_out = self.client.put_object(bucket_name, key=key, content=content)
        self.assertTrue(len(put_object_out.etag) > 0)
        self.assertTrue(len(put_object_out.id2) > 0)
        self.assertTrue(put_object_out.hash_crc64_ecma > 0)

        head_object_out = self.client.head_object(bucket_name, key)
        self.assertTrue(len(head_object_out.etag) > 0)
        self.assertTrue(head_object_out.hash_crc64_ecma > 0)
        self.assertTrue(len(head_object_out.meta) == 0)
        self.assertTrue(len(head_object_out.object_type) > 0)
        self.assertTrue(head_object_out.last_modified is not None)
        self.assertTrue(head_object_out.object_type == 'Normal')
        self.assertTrue(head_object_out.delete_marker is False)
        self.assertTrue(head_object_out.content_length == 1024)

        get_object_out = self.client.get_object(bucket_name, key)
        res = b''
        for chuck in get_object_out:
            res = res + chuck

        self.assertEqual(res, content)

        range_out = self.client.get_object(bucket_name, key, range_start=1, range_end=100)
        read_content = range_out.read()
        self.assertEqual(read_content, content[1:101])

    def test_put_with_meta(self):
        bucket_name = self.bucket_name + '-put-object-with-meta'
        key = "张三.txt"
        content = random_string(123)

        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        meta = {'name': '张三', 'age': '12'}
        self.client.put_object(bucket_name, key, content=b'')
        self.client.put_object(bucket_name, key=key,
                               content=content,
                               meta=meta
                               )
        get_object_out = self.client.get_object(bucket_name, key)
        m = get_object_out.meta
        self.assertEqual(m['name'], meta['name'])
        self.assertEqual(m['age'], meta['age'])

        meta['name'] = '李四'
        self.client.set_object_meta(bucket_name, key, meta=meta)
        head_out = self.client.head_object(bucket_name, key)
        m = head_out.meta
        self.assertEqual(m['name'], meta['name'])
        self.assertEqual(m['age'], meta['age'])

    def test_with_string_io(self):
        io = StringIO('a')
        io.seek(0)
        bucket_name = self.bucket_name + 'string-io'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        self.client.put_object(bucket=bucket_name, key="2", content=io)
        out = self.client.get_object(bucket=bucket_name, key='2')
        self.assertEqual(out.read(), b'a')
        self.client.put_object(bucket=bucket_name, key='4', content=b'')

    def test_put_with_options(self):
        bucket_name = self.bucket_name + '-put-with-options'
        key = self.random_key()
        content = random_bytes(123)

        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        self.client.put_object(bucket_name, key=key,
                               content=content,
                               cache_control='CacheControl',
                               acl=ACLType.ACL_Private,
                               content_encoding='utf-8',
                               content_disposition='attachment; filename=张123.txt',
                               content_length=123,
                               content_language='english',
                               expires=datetime.datetime(2023, 1, 29),
                               website_redirect_location='/test',
                               )
        get_object_out = self.client.get_object(bucket_name, key)
        self.assertTrue(len(get_object_out.cache_control) > 0)
        self.assertEqual(get_object_out.content_encoding, 'utf-8')
        self.assertEqual(get_object_out.content_disposition, 'attachment; filename=张123.txt')
        self.assertEqual(get_object_out.content_language, 'english')
        self.assertEqual(get_object_out.website_redirect_location, '/test')

    def test_put_with_cryptography(self):
        bucket_name = self.bucket_name + '-put-object-with-test-put-with-cryptography'
        key = self.random_key()
        content = random_bytes(100)

        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        with self.assertRaises(TosServerError):
            self.client.put_object(bucket_name, key=key, content=content, content_md5=random_bytes(20))

        with self.assertRaises(TosServerError):
            self.client.put_object(bucket_name, key=key, content=content, ssec_algorithm="DEC")

    def test_put_with_empty_content(self):
        bucket_name = self.bucket_name + '-put-empty-object'
        key = self.random_key()
        content = b''

        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        self.client.put_object(bucket_name, key=key, content=content)
        get_object_out = self.client.get_object(bucket_name, key)
        self.assertEqual(get_object_out.client_crc, 0)
        self.assertEqual(get_object_out.hash_crc64_ecma, 0)

    def test_put_with_illegal_name(self):
        bucket_name = self.bucket_name + '-put-object-with-illegal-name'
        key = random_bytes(1003)
        content = random_bytes(100)

        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        with self.assertRaises(TosClientError):
            self.client.put_object(bucket_name, key, content=content)

        key = '/+'
        with self.assertRaises(TosClientError):
            self.client.put_object(bucket_name, key, content=content)

        key = '\\+123'
        with self.assertRaises(TosClientError):
            self.client.put_object(bucket_name, key, content=content)

        key = '.'
        with self.assertRaises(TosClientError):
            self.client.put_object(bucket_name, key, content=content)

        with self.assertRaises(TosClientError):
            self.client.get_object(bucket_name, key)

        key = "中文测试"
        self.client.put_object(bucket_name, key, content=content)
        self.client.delete_object(bucket_name, key)

        key = '%1 ? # *'
        self.client.put_object(bucket_name, key, content=content)
        self.client.get_object(bucket_name, key)
        self.client.delete_object(bucket_name, key)

    def test_put_with_server_encryption(self):
        bucket_name = self.bucket_name + '-put-object-with-server-encryption'
        key = self.random_key('.js')
        content = random_bytes(100)
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        self.client.put_object(bucket_name, key, content=content, server_side_encryption="AES256")
        self.client.get_object(bucket_name, key)

        self.client.delete_object(bucket_name, key)

        key = self.random_key(".js")
        with self.assertRaises(TosServerError):
            self.client.put_object(bucket_name, key, content=content, ssec_algorithm="AES256")

    def test_put_with_data_transfer_listener(self):
        bucket_name = self.bucket_name + '-put-object-with-transfer-listener'
        key = self.random_key('.js')
        content = random_bytes(1024 * 100)
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        def progress(consumed_bytes, total_bytes, rw_once_bytes,
                     data_type: DataTransferType):
            print("consumed_bytes:{0},total_bytes{1}, rw_once_bytes:{2}, type:{3}".format(consumed_bytes, total_bytes,
                                                                                          rw_once_bytes, data_type))

        self.client.put_object(bucket_name, key, content=content, data_transfer_listener=progress)

        out = self.client.get_object(bucket_name, key, data_transfer_listener=progress)

        read_info = bytes()
        for buf in out.content:
            read_info = read_info + buf

    def test_object_from_file(self):
        bucket_name = self.bucket_name + '-put-object-from-file'
        key = self.random_key('.js')
        file_name = self.random_filename()
        content = random_bytes(100)
        with open(file_name, 'wb') as fw:
            fw.write(content)

        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        limiter = RateLimiter(8 * 1024, 20 * 1024)
        self.client.put_object_from_file(bucket=bucket_name, key=key, file_path=file_name, rate_limiter=limiter)

        get_file_name = self.random_filename()
        self.client.get_object_to_file(bucket_name, key, get_file_name)
        self.assertFileContent(get_file_name, content)
        self.assertObjectContent(bucket_name, key, content)

    def test_delete_multi_objects(self):
        bucket_name = self.bucket_name + "-delete-multi-objects"
        key_1 = self.random_key('.js')
        key_2 = self.random_key('.js')
        content = random_bytes(20)

        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        self.client.put_object(bucket=bucket_name, key=key_1, content=content)
        self.client.put_object(bucket=bucket_name, key=key_2, content=content)
        self.client.head_object(bucket_name, key_1)
        object = []
        object.append(ObjectTobeDeleted(key_1))
        object.append(ObjectTobeDeleted(key_1))
        self.client.delete_multi_objects(bucket=bucket_name, objects=object, quiet=False)

    def test_copy_object(self):
        bucket_name_1 = self.bucket_name + '-copy-object1'
        bucket_name_2 = self.bucket_name + '-copy-object2'
        key = self.random_key(".java")
        content = random_bytes(100)
        self.client.create_bucket(bucket_name_1)
        self.bucket_delete.append(bucket_name_1)
        self.client.create_bucket(bucket_name_2)
        self.bucket_delete.append(bucket_name_2)
        self.client.put_object(bucket_name_1, key, content=content)
        self.client.copy_object(bucket_name_2, key, bucket_name_1, key)
        self.client.head_object(bucket_name_2, key)
        self.client.get_object(bucket_name_2, key)

        self.client.delete_object(bucket_name_1, key)

        with self.assertRaises(TosServerError):
            self.client.copy_object(bucket_name_2, key, bucket_name_1, key)

    def test_copy_object_options(self):
        bucket_name_1 = self.bucket_name + '-copy-object1'
        bucket_name_2 = self.bucket_name + '-copy-object2'
        key = self.random_key(".java")
        content = random_bytes(100)
        self.client.create_bucket(bucket_name_1)
        self.bucket_delete.append(bucket_name_1)
        self.client.create_bucket(bucket_name_2)
        self.bucket_delete.append(bucket_name_2)
        meta = {'姓名': '张三'}
        self.client.put_object(bucket_name_1, key=key,
                               content=content,
                               cache_control='CacheControl',
                               acl=ACLType.ACL_Private,
                               content_encoding='utf-8',
                               content_disposition='/sunyushantest',
                               content_length=100,
                               content_language='english',
                               expires=datetime.datetime(2023, 1, 29),
                               website_redirect_location='/test',
                               meta=meta
                               )

        out = self.client.copy_object(bucket_name_2, key, src_bucket=bucket_name_1, src_key=key,
                                      metadata_directive=MetadataDirectiveType.Metadata_Directive_Copy)
        self.client.head_object(bucket_name_2, key)
        get_object_out = self.client.get_object(bucket_name_2, key)

        self.assertTrue(len(get_object_out.cache_control) > 0)
        self.assertEqual(get_object_out.content_encoding, 'utf-8')
        self.assertEqual(get_object_out.content_disposition, '/sunyushantest')
        self.assertEqual(get_object_out.content_language, 'english')
        self.assertEqual(get_object_out.meta['姓名'], meta['姓名'])
        self.assertEqual(get_object_out.read(), content)

    def test_copy_with_set_option(self):
        bucket_name_1 = self.bucket_name + '-copy-object1'
        bucket_name_2 = self.bucket_name + '-copy-object2'
        key = self.random_key(".java")
        content = random_bytes(100)
        self.client.create_bucket(bucket_name_1)
        self.bucket_delete.append(bucket_name_1)
        self.client.create_bucket(bucket_name_2)
        self.bucket_delete.append(bucket_name_2)
        meta = {'姓名': '张三'}
        self.client.put_object(bucket_name_1, key=key,
                               content=content)

        self.client.copy_object(bucket_name_2, key, src_bucket=bucket_name_1, src_key=key,
                                cache_control='CacheControl',
                                acl=ACLType.ACL_Private,
                                content_encoding='utf-8',
                                content_disposition='/sunyushantest',
                                content_language='english',
                                expires=datetime.datetime(2023, 1, 29),
                                website_redirect_location='/test',
                                meta=meta,
                                storage_class=StorageClassType.Storage_Class_Ia,
                                metadata_directive=MetadataDirectiveType.Metadata_Directive_Replace
                                )

        self.client.head_object(bucket_name_2, key)
        get_object_out = self.client.get_object(bucket_name_2, key)

        self.assertTrue(len(get_object_out.cache_control) > 0)
        self.assertEqual(get_object_out.content_encoding, 'utf-8')
        self.assertEqual(get_object_out.content_disposition, '/sunyushantest')
        self.assertEqual(get_object_out.content_language, 'english')
        self.assertEqual(get_object_out.meta['姓名'], meta['姓名'])

        self.assertEqual(get_object_out.read(), content)

    # # 目前不知道如何开启多版本, 后续补充测试
    # def test_mult_version(self):
    #     bucket_name = self.bucket_name + '-test-mult-object'
    #     key = self.random_key('.js')
    #     content = random_bytes(1024)
    #     self.client.create_bucket(bucket_name)
    #     self.bucket_delete.append(bucket_name)
    #     out = self.version_client.put_bucket_versioning(bucket_name, enable=True)
    #
    #     time.sleep(30)
    #     put_object_out_v1 = self.client.put_object(bucket_name, key=key, content=content)
    #     version_1 = put_object_out_v1.version_id
    #     content = random_bytes(2048)
    #     put_object_out_v2 = self.client.put_object(bucket_name, key=key, content=content)
    #     version_2 = put_object_out_v2.version_id
    #     get_out = self.client.get_object(bucket_name, key)
    #     self.assertEqual(get_out.version_id, version_2)

    # def test_list_object_version(self):
    #     bucket_name = self.bucket_name + '-test-list-version'
    #     self.client.create_bucket(bucket_name)
    #     self.bucket_delete.append(bucket_name)
    #
    #     self.version_client.put_bucket_versioning(bucket_name, enable=True)
    #     for i in range(100):
    #         key = self.random_key('.js')
    #         content = random_bytes(1)
    #         self.client.put_object(bucket_name, key=key, content=content)
    #         self.client.put_object(bucket_name, key=key, content=random_bytes(1))
    #
    #     for i in range(10):
    #         self.client.put_object(bucket_name, key=str(i), content=random_bytes(1))
    #         self.client.put_object(bucket_name, key=str(i), content=random_bytes(1))
    #
    #     list_object_out = self.client.list_object_versions(bucket_name, max_keys=50, prefix=self.prefix)
    #     self.assertEqual(self.prefix, list_object_out.prefix)
    #     self.assertEqual(list_object_out.max_keys, 50)
    #     self.assertTrue(list_object_out.is_truncated)

    def test_append(self):
        bucket_name = self.bucket_name + '-test-append-object'
        key = self.random_key('.js')
        content = random_bytes(1024)

        self.client.create_bucket(bucket_name, az_redundancy=AzRedundancyType.Az_Redundancy_Multi_Az)
        self.bucket_delete.append(bucket_name)
        append_object_out = self.client.append_object(bucket_name, key, 0, content=content)
        self.assertTrue(append_object_out.hash_crc64_ecma > 0)
        self.assertEqual(append_object_out.next_append_offset, 1024)
        self.client.delete_object(bucket_name, key)

        key = self.random_key('.js')
        append_out_1 = self.client.append_object(bucket_name, key, 0, content=content[0:100], pre_hash_crc64_ecma=0)

        self.client.append_object(bucket_name, key, 100, content=content[100:],
                                  pre_hash_crc64_ecma=append_out_1.hash_crc64_ecma)

        get_out = self.client.get_object(bucket_name, key)
        self.assertEqual(get_out.read(), content)

    def test_append_with_options(self):
        bucket_name = self.bucket_name + '-test-append-with-options'
        key = self.random_key('.js')
        content = random_bytes(1024)

        def progress(consumed_bytes, total_bytes, rw_once_bytes,
                     type):
            print("consumed_bytes:{0},total_bytes{1}, rw_once_bytes:{2}, type:{3}".format(consumed_bytes, total_bytes,
                                                                                          rw_once_bytes, type))

        limiter = RateLimiter(5 * 1024 * 1024, 20 * 1024 * 1024)

        self.client.create_bucket(bucket_name, az_redundancy=AzRedundancyType.Az_Redundancy_Multi_Az)
        self.bucket_delete.append(bucket_name)
        meta = {'name': '张三', 'age': '13'}
        append_object_out = self.client.append_object(bucket_name, key, 0,
                                                      content=content,
                                                      content_length=1024,
                                                      cache_control="Cache-Control",
                                                      content_disposition="utf-8",

                                                      content_language="english",
                                                      content_encoding="utf-8",

                                                      expires=datetime.datetime.now(),
                                                      acl=ACLType.ACL_Private,
                                                      meta=meta,
                                                      website_redirect_location='/test',
                                                      data_transfer_listener=progress,
                                                      rate_limiter=limiter
                                                      )
        self.assertTrue(append_object_out.hash_crc64_ecma > 0)
        self.assertEqual(append_object_out.next_append_offset, 1024)
        get_object_out = self.client.get_object(bucket_name, key)
        self.assertTrue(get_object_out.object_type == 'Appendable')

    def test_list_object_info(self):
        bucket_name = self.bucket_name + '-test-list-object'
        key = self.random_key('.js')
        content = random_bytes(1024)

        self.client.create_bucket(bucket_name, az_redundancy=AzRedundancyType.Az_Redundancy_Multi_Az)
        self.bucket_delete.append(bucket_name)
        self.client.put_object(bucket_name, key=key, content=content)
        list_object_out = self.client.list_objects(bucket_name)
        self.assertEqual(list_object_out.name, bucket_name)
        self.assertFalse(list_object_out.is_truncated)
        self.assertTrue(len(list_object_out.contents) > 0)

        object = list_object_out.contents[0]
        self.assertTrue(len(object.etag) > 0)
        self.assertTrue(len(object.key) > 0)
        self.assertTrue(object.last_modified is not None)
        self.assertTrue(object.size == 1024)
        self.assertTrue(len(object.owner.id) > 0)

    def test_list_object_full_func(self):
        bucket_name = self.bucket_name + '-test-list-object'
        self.client.create_bucket(bucket_name, az_redundancy=AzRedundancyType.Az_Redundancy_Multi_Az)
        self.bucket_delete.append(bucket_name)

        for i in range(100):
            key = self.random_key('.js')
            content = random_bytes(1)
            self.client.put_object(bucket_name, key=key, content=content)

        for i in range(10):
            self.client.put_object(bucket_name, key=str(i), content=random_bytes(1))

        list_object_out = self.client.list_objects(bucket_name, max_keys=50, prefix=self.prefix)
        self.assertEqual(self.prefix, list_object_out.prefix)
        self.assertEqual(list_object_out.max_keys, 50)
        self.assertTrue(list_object_out.is_truncated)

        list_object_out_v2 = self.client.list_objects(bucket_name, max_keys=51, prefix=self.prefix,
                                                      marker=list_object_out.next_marker, delimiter=self.prefix,
                                                      reverse=False)
        self.assertEqual(len(list_object_out_v2.contents), 50)
        self.assertFalse(list_object_out_v2.is_truncated)

    def test_list_object_with_case(self):
        bucket_name = self.bucket_name + '-test-list-object-with-case'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        for i in range(100):
            key = self.random_key('.js')
            content = random_string(1000)
            self.client.put_object(bucket_name, key, content=content)

        is_truncated = True
        count = 0
        object_count = 0
        marker = ''
        while is_truncated:
            if count > 10:
                break
            count += 1
            list_out = self.client.list_objects(bucket_name, max_keys=10, marker=marker)
            is_truncated = list_out.is_truncated
            marker = list_out.next_marker
            object_count += len(list_out.contents)
        self.assertEqual(count, 10)
        self.assertEqual(object_count, 100)

        deletes = []
        for i in range(3):
            for j in range(3):
                for k in range(3):
                    path = '{}/{}/{}'.format(i, j, k)
                    deletes.append(Deleted(key=path))
                    self.client.put_object(bucket_name, path, content=b'')

        self.client.list_objects(bucket_name, prefix='0')
        self.client.list_objects(bucket_name, prefix='1')
        self.client.list_objects(bucket_name, prefix='0/1')

        out4 = self.client.list_objects(bucket_name, delimiter='/')

        def dfs(list_out: ListObjectsOutput):
            if len(list_out.common_prefixes) == 0:
                for e in list_out.contents:
                    print(e)
                return len(list_out.contents)
            else:
                a = 0
                for prefix in list_out.common_prefixes:
                    a += dfs(self.client.list_objects(bucket_name, delimiter='/', prefix=prefix.prefix))
                return a

        count = dfs(out4)
        self.assertEqual(count, 27)

        self.client.delete_multi_objects(bucket_name, deletes)

        out5 = self.client.list_objects(bucket_name, delimiter='/')
        self.assertEqual(len(out5.common_prefixes), 0)

    def test_set_object_meta(self):
        bucket_name = self.bucket_name + '-test-set-object-meta'
        key = self.random_key('.js')
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        meta = {'name': 'sunyushan', 'age': '10'}
        self.client.put_object(bucket_name, key=key, content=random_bytes(10), meta=meta)
        meta['name'] = '张三'
        self.client.set_object_meta(bucket_name, key, meta=meta)

        get_object_out = self.client.get_object(bucket_name, key=key)
        self.assertEqual(meta['name'], get_object_out.meta['name'])

    def test_get_object_meta(self):
        bucket_name = self.bucket_name + '-test-get-object-meta'
        key = self.random_key('.js')
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        meta = {'name': 'jason', 'age': '10'}
        self.client.put_object(bucket_name, key=key, content=random_bytes(10), meta=meta)

        self.client.get_object(bucket_name, key=key)

    def test_get_object_with_data_transfer_listener(self):
        bucket_name = self.bucket_name + '-test-with-transfer-listener'
        key = self.random_key('.js')
        content = random_bytes(1025 * 1024)
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        def progress(consumed_bytes, total_bytes, rw_once_bytes,
                     type: DataTransferType):
            print(
                "consumed_bytes:{0},total_bytes{1}, rw_once_bytes:{2}, type:{3}".format(consumed_bytes, total_bytes,
                                                                                        rw_once_bytes, type))

        self.client.put_object(bucket_name, key=key, content=content)

        get_object_out = self.client.get_object(bucket_name, key=key, data_transfer_listener=progress,
                                                rate_limiter=RateLimiter(1024 * 1024 * 5, 1024 * 1024 * 20))
        self.assertEqual(get_object_out.read(), content)
        self.assertEqual(get_object_out.hash_crc64_ecma, get_object_out.client_crc)

    def test_with_rate_limiter(self):
        bucket_name = self.bucket_name + '-test-with-rate-limiter'
        key = self.random_key('.js')
        content = random_bytes(1024 * 1024)
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        def progress(consumed_bytes, total_bytes, rw_once_bytes,
                     type: DataTransferType):
            print(
                "consumed_bytes:{0},total_bytes{1}, rw_once_bytes:{2}, type:{3}".format(consumed_bytes, total_bytes,
                                                                                        rw_once_bytes, type))

        limiter = RateLimiter(1024 * 1024 * 5, 1024 * 1024 * 20)
        self.client.put_object(bucket_name, key=key, content=content, data_transfer_listener=progress,
                               rate_limiter=limiter)

        get_object_out = self.client.get_object(bucket_name, key=key, data_transfer_listener=progress)
        self.assertEqual(get_object_out.read(), content)

    def test_put_object_acl(self):
        bucket_name = self.bucket_name + '-test-put-object-acl'
        key = self.random_key('.js')
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        self.client.put_object(bucket_name, key, content=random_bytes(5))
        grants = []
        grantee = Grantee(id="123", display_name="123", type=GranteeType.Grantee_User)
        grant = Grant(grantee, permission=PermissionType.Permission_Full_Control)
        grants.append(grant)
        # self.client.put_object_acl(bucket_name, key, acl=ACLType.ACL_Bucket_Owner_Full_Control)
        # self.client.get_object_acl(bucket_name, key)
        self.client.put_object_acl(bucket_name, key, owner=Owner("123", "test"), grants=grants)

        out = self.client.get_object_acl(bucket_name, key)

    def test_put_with_md5(self):
        bucket_name = self.bucket_name + '-put-with-md5'
        self.bucket_delete.append(bucket_name)
        key = self.random_key('.js')
        content = random_bytes(100)
        file_name = random_string(5)
        with open(file_name, 'wb') as f:
            f.write(content)

        md5 = 0
        with open(file_name, 'rb') as f:
            md5 = calculate_md5(f)

        self.client.create_bucket(bucket_name)

        self.client.put_object_from_file(bucket_name, key, file_name, content_md5=md5.decode('utf-8'))

        with self.assertRaises(TosServerError):
            self.client.put_object_from_file(bucket_name, key, file_name, content_md5='test_error')
        os.remove(path=file_name)

    def test_tagging(self):
        bucket_name = self.bucket_name + 'tagging'
        key = self.random_key('.js')
        content = random_bytes(100)
        self.client.create_bucket(bucket_name)
        self.client.put_object(bucket=bucket_name, key=key, content=content)
        tag_set = []
        tag_set.append(Tag(
            key='1',
            value='1'
        ))
        put_out = self.client.put_object_tagging(bucket=bucket_name, key=key, tag_set=tag_set)
        self.assertIsNone(put_out.version_id)

        get_out = self.client.get_object_tagging(bucket=bucket_name, key=key)
        get_set = get_out.tag_set
        self.assertTrue(len(get_set) == 1)
        self.assertEqual(get_set[0].key, '1')
        self.assertEqual(get_set[0].key, '1')

        delete_out = self.client.delete_object_tagging(bucket=bucket_name, key=key)
        self.assertIsNone(delete_out.version_id)
        get_out_2 = self.client.get_object_tagging(bucket=bucket_name, key=key)
        self.assertTrue(len(get_out_2.tag_set) == 0)

        self.client.delete_object(bucket=bucket_name, key=key)
        self.client.delete_bucket(bucket_name)

    def test_list_object_v2(self):
        bucket_name = self.bucket_name + '-test-list-object-with-case'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        for i in range(3):
            for j in range(3):
                for k in range(3):
                    path = '{}/{}/{}'.format(i, j, k)
                    self.client.put_object(bucket_name, path, content=b'1')

        out_2 = self.client.list_objects_type2(bucket=bucket_name, prefix='0', start_after='0/1', max_keys=2)
        out_2_reverse = self.client.list_objects_type2(bucket=bucket_name, prefix='0', start_after='0/1', max_keys=2,
                                                       reverse=True)
        out_3 = self.client.list_objects_type2(bucket=bucket_name, prefix='0', start_after='0/1', max_keys=2,
                                               delimiter='/', continuation_token=out_2.next_continuation_token)

        continuation_token = None
        is_truncated = True
        count = 0
        while is_truncated:
            out = self.client.list_objects_type2(bucket_name, continuation_token=continuation_token)
            is_truncated = out.is_truncated
            count += len(out.contents)
        self.assertEqual(count, 27)

    def test_fetch_object(self):
        bucket_name = self.bucket_name + '-fetch-object'
        bucket_fetch = self.bucket_name + '-fetch-test'
        self.bucket_delete.append(bucket_name)
        self.bucket_delete.append(bucket_fetch)
        object_name = 'test.txt'
        self.client.create_bucket(bucket_fetch)
        self.client.put_object(bucket_fetch, object_name)
        self.client.put_object_acl(bucket=bucket_fetch, key=object_name, acl=ACLType.ACL_Public_Read_Write)
        key = self.random_key('.js')
        self.client.create_bucket(bucket=bucket_name)
        meta = {'姓名': '张三'}
        fetch_out = self.client.fetch_object(bucket=bucket_name, key=key,
                                             url="https://{}.{}".format(bucket_fetch,
                                                                        self.endpoint) + '/' + object_name,
                                             meta=meta)
        out = self.client.get_object(bucket=bucket_name, key=key)
        get_out = self.client.get_object(bucket=bucket_name, key=key)
        get_out.meta['姓名'] = meta['姓名']

    def test_fetch_task_object(self):
        bucket_name = self.bucket_name + '-fetch-object'
        self.bucket_delete.append(bucket_name)
        bucket_fetch = self.bucket_name + '-fetch-task-test'
        self.bucket_delete.append(bucket_fetch)

        key = self.random_key('123')

        self.client.create_bucket(bucket=bucket_fetch)
        self.client.put_object(bucket=bucket_fetch, key=key, acl=ACLType.ACL_Public_Read_Write)
        url = 'http://{}.{}'.format(bucket_fetch, self.endpoint) + '/' + key
        self.client.create_bucket(bucket=bucket_name)
        out = self.client.put_fetch_task(bucket=bucket_name, key=key,
                                         url=url)

    def test_post_object(self):
        bucket_name = self.bucket_name + '-post-object'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        file_name = self.random_filename()
        content = random_bytes(1024)
        with open(file_name, 'wb+') as f:
            f.write(content)
        key = self.random_key()
        out = self.client.pre_signed_post_signature(bucket=bucket_name, key=key, conditions=[])
        form = {'key': key, 'x-tos-algorithm': out.algorithm, 'bucket': bucket_name, 'x-tos-date': out.date,
                'policy': out.policy, 'x-tos-signature': out.signature, 'x-tos-credential': out.credential}
        resp = requests.post(url=self.client._make_virtual_host_url(bucket_name, key),
                             files={"upload_file": open(file_name, 'rb')},
                             data=form)
        self.assertEqual(resp.status_code, 204)

        condition = [PostSignatureCondition(key='x-tos-acl', value='private')]
        out2 = self.client.pre_signed_post_signature(conditions=condition, bucket=bucket_name, key=key)
        form2 = {'key': key, 'x-tos-algorithm': out2.algorithm, 'bucket': bucket_name, 'x-tos-date': out2.date,
                 'policy': out2.policy, 'x-tos-signature': out2.signature, 'x-tos-credential': out2.credential,
                 'x-tos-acl': 'private'}
        resp = requests.post(url=self.client._make_virtual_host_url(bucket_name),
                             files={"upload_file": open(file_name, 'rb')},
                             data=form2)

        self.assertEqual(resp.status_code, 204)

        form2['x-tos-acl'] = 'public-read'
        resp = requests.post(url=self.client._make_virtual_host_url(bucket_name),
                             files={"upload_file": open(file_name, 'rb')},
                             data=form2)
        self.assertEqual(resp.status_code, 403)

    def random_key(self, suffix=''):
        key = self.prefix + random_string(12) + suffix
        return key


if __name__ == '__main__':
    unittest.main()
