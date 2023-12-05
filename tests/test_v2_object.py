# -*- coding: utf-8 -*-
import base64
import datetime
import http
import http.client as httplib
import os
import time
import unittest
from io import StringIO, BytesIO

import requests

import tos
from tests.common import TosTestBase, random_string, random_bytes, calculate_md5
from tos import TosClientV2
from tos.consts import MIN_TRAFFIC_LIMIT
from tos.enum import (ACLType, AzRedundancyType, DataTransferType,
                      GranteeType, MetadataDirectiveType, PermissionType,
                      StorageClassType, VersioningStatusType, TierType, CopyEventType, HttpMethodType)
from tos.exceptions import TosClientError, TosServerError
from tos.models2 import Deleted, Grant, Grantee, ListObjectsOutput, Owner, ObjectTobeDeleted, Tag, \
    PostSignatureCondition, UploadedPart, PolicySignatureCondition, RestoreJobParameters
from tos.utils import RateLimiter


def get_socket_io():
    conn = http.client.HTTPConnection('tos-cn-beijing.volces.com', 80)
    conn.request('GET', '/')
    content = conn.getresponse()
    return content


def _get_host_schema(endpoint):
    if endpoint.startswith('http://'):
        return 'http://', endpoint[7:]
    if endpoint.startswith('https://'):
        return 'https://', endpoint[8:]
    return 'http://', endpoint


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
        conn = httplib.HTTPConnection('tos-cn-beijing.volces.com', 80)
        conn.request('GET', '/')
        content_io = conn.getresponse()
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        for i in range(2):
            raw = "!@#$%^&*()_+-=[]{}|;':\",./<>?中文测试编码%20%%%^&abcd /\\"
            meta = {'name': ' %张/三%', 'age': '12', 'special': raw, raw: raw}
            self.client.put_object(bucket_name, key=key,
                                   content=content,
                                   meta=meta
                                   )
            get_object_out = self.client.get_object(bucket_name, key)
            m = get_object_out.meta
            self.assertEqual(m['name'], meta['name'])
            self.assertEqual(m['age'], meta['age'])
            self.assertEqual(m['special'], meta['special'])
            self.assertEqual(m[raw], meta[raw])

            meta['name'] = '李四'
            self.client.set_object_meta(bucket_name, key, meta=meta)
            head_out = self.client.head_object(bucket_name, key)
            m = head_out.meta
            self.assertEqual(m['name'], meta['name'])
            self.assertEqual(m['age'], meta['age'])
            self.assertEqual(m['special'], meta['special'])
            self.assertEqual(m[raw], meta[raw])
            key = '李四.txt'
            content = content_io

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

        with self.assertRaises(TosServerError) as cm:
            self.client.put_object(bucket_name, key=key, content=content, content_sha256=random_string(10))

        with self.assertRaises(TosServerError):
            self.client.put_object(bucket_name, key=key, content=content, ssec_algorithm="DEC")

    def test_put_with_empty_content(self):
        bucket_name = self.bucket_name + '-put-empty-object'
        key = self.random_key()
        conn = httplib.HTTPConnection('tos-cn-beijing.volces.com', 80)
        conn.request('GET', '/')
        content_io = conn.getresponse()
        content = b''

        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        for i in range(2):
            self.client.put_object(bucket_name, key=key, content=content)
            get_object_out = self.client.get_object(bucket_name, key)
            if self.client.enable_crc:
                self.assertEqual(get_object_out.client_crc, 0)
            self.assertEqual(get_object_out.hash_crc64_ecma, 0)
            content = content_io
            content.read()
            key = self.random_key()
        self.client.put_object(bucket_name, key)
        conn.close()

    def test_put_with_illegal_name(self):
        bucket_name = self.bucket_name + '-put-object-with-illegal-name'
        key = random_bytes(1003)
        content = random_bytes(100)

        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        with self.assertRaises(TosClientError):
            self.client.put_object(bucket_name, key, content=content)

        key = '/+'
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
        self.client.enable_crc = False
        bucket_name = self.bucket_name + '-put-object-with-transfer-listener'
        key = self.random_key('.js')
        key_2 = self.random_key('.js')
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
        self.assertEqual(read_info, content)

        out = self.client.get_object(bucket_name, key)
        self.client.put_object(bucket_name, key_2, content=out, data_transfer_listener=progress)
        get_out = self.client.get_object(bucket_name, key_2, data_transfer_listener=progress)
        read_info = bytes()
        for buf in get_out.content:
            read_info = read_info + buf
        self.assertEqual(read_info, content)

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

    def test_object_from_file_with_large_file(self):
        bucket_name = self.bucket_name + '-put-object-from-file'
        key = self.random_key('.js')
        file_name = self.random_filename()
        content = random_bytes(1024 * 1024 * 10)
        with open(file_name, 'wb') as fw:
            fw.write(content)

        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        self.client.put_object_from_file(bucket=bucket_name, key=key, file_path=file_name)
        get_file_name = self.random_filename()
        self.client.get_object_to_file(bucket_name, key, get_file_name)
        object_out = self.client.get_object(bucket_name, key)
        while True:
            if not object_out.read(64 * 1024):
                break
        # assert object_out.client_crc == object_out.hash_crc64_ecma
        self.assertFileContent(get_file_name, content)
        self.assertObjectContent(bucket_name, key, content)

    def test_object_with_io(self):
        bucket_name = self.bucket_name + '-put-object-from-file'
        key = self.random_key('.js')
        file_name = self.random_filename()
        content = random_bytes(1024 * 1024)
        with open(file_name, 'wb') as fw:
            fw.write(content)
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        self.client.put_object_from_file(bucket=bucket_name, key=key, file_path=file_name)
        input = self.client.get_object(bucket_name, key)
        self.client.put_object(bucket_name, key + '1', content=input)
        self.assertObjectContent(bucket_name, key + '1', content)

    def test_with_stream(self):
        bucket_name = self.bucket_name + 'test-with-stream'
        key = self.random_key('.js')
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        conn = http.client.HTTPConnection('www.volcengine.com', 80)
        conn.request('GET', '/')
        content = conn.getresponse()

        def generator():
            var1 = "5\r\n"
            var2 = "x=FOO\r\n"
            var3 = "0\r\n\r\n"
            x = var1.encode('utf8')
            y = var2.encode('utf8')
            z = var3.encode('utf8')
            yield x
            yield y
            yield z

        self.client.close()
        self.client.put_object(bucket_name, key, content=generator())
        out = self.client.create_multipart_upload(bucket_name, key)
        self.client.upload_part(bucket_name, key, content=generator(), upload_id=out.upload_id, part_number=1)
        out = self.client.get_object(bucket_name, key)
        buf = b''
        for i in generator():
            buf += i
        self.assertEqual(out.read(), buf)

        self.client.put_object(bucket_name, key, content=content)
        out = self.client.get_object(bucket_name, key)
        conn = http.client.HTTPConnection('www.volcengine.com', 80)
        conn.request('GET', '/')
        content = conn.getresponse()
        buf = b''
        for chuck in content:
            buf += chuck
        self.assertEqual(len(buf), len(out.read()))

        input = requests.get('https://www.volcengine.com')
        self.client.put_object(bucket_name, key, content=input)
        out = self.client.get_object(bucket_name, key)
        self.assertEqual(len(out.read()), len(requests.get('https://www.volcengine.com').text))
        conn.close()

    def test_object_with_iterm(self):
        bucket_name = self.bucket_name + '-with-itern'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        class Crc64IO(object):
            def __init__(self, data: BytesIO):
                self.data = data
                self.crc64 = tos.utils.Crc64()

            def __iter__(self):
                return self

            def __next__(self):
                return self.next()

            def next(self):
                content = self.data.read(1)
                if content:
                    self.crc64.update(content)
                    return content
                raise StopIteration

        io = BytesIO(b'123')
        io.seek(0)
        self.client.put_object(bucket=bucket_name, key='1234', content=Crc64IO(io))
        self.assertEqual(self.client.get_object(bucket_name, key='1234').read(), b'123')

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
        content = random_bytes(1024 * 1024 * 5)
        self.client.create_bucket(bucket_name_1)
        self.bucket_delete.append(bucket_name_1)
        self.client.create_bucket(bucket_name_2)
        self.bucket_delete.append(bucket_name_2)
        self.client.put_object(bucket_name_1, key, content=content)
        self.client.copy_object(bucket_name_2, key, bucket_name_1, key)
        self.client.head_object(bucket_name_2, key)
        self.assertObjectContent(bucket_name_2, key, content)

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
        self.assertEqual(list_object_out.max_keys, 1000)
        self.assertTrue(len(list_object_out.contents) > 0)

        object = list_object_out.contents[0]
        self.assertTrue(len(object.etag) > 0)
        self.assertTrue(len(object.key) > 0)
        self.assertTrue(object.last_modified is not None)
        self.assertTrue(object.size == 1024)
        self.assertTrue(len(object.owner.id) > 0)
        self.assertTrue(object.storage_class, StorageClassType.Storage_Class_Standard)

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

    def test_list(self):
        bucket_name = self.bucket_name + '-test-list-object'
        self.client.create_bucket(bucket_name, az_redundancy=AzRedundancyType.Az_Redundancy_Multi_Az)
        self.bucket_delete.append(bucket_name)
        self.client.put_object(bucket_name, 'test/')
        self.client.put_object(bucket_name, 'test/test')
        out = self.client.list_objects(bucket_name, prefix='test/', max_keys=1)

    def test_empty(self):
        bucket_name = self.bucket_name + '-test-empty'
        file_name = self.random_filename()
        self.client.create_bucket(bucket_name, acl=tos.ACLType.ACL_Public_Read_Write)
        self.bucket_delete.append(bucket_name)

        def percentage(consumed_bytes, total_bytes, rw_once_bytes,
                       type: DataTransferType):
            if total_bytes:
                rate = int(100 * float(consumed_bytes) / float(total_bytes))
                print("rate:{}, consumed_bytes:{},total_bytes{}, rw_once_bytes:{}, type:{}".format(rate, consumed_bytes,
                                                                                                   total_bytes,
                                                                                                   rw_once_bytes, type))

        rate_limiter = RateLimiter(rate=5 * 1024 * 1024, capacity=10 * 1024 * 1024)

        with open(file_name, 'wb+') as f:
            pass

        with open(file_name, 'rb+') as f:
            self.client.put_object(bucket_name, 'test', content=f, data_transfer_listener=percentage,
                                   rate_limiter=rate_limiter)
            self.assertEqual(self.client.get_object(bucket_name, 'test').read(), b'')

        rate_limiter = RateLimiter(rate=5 * 1024 * 1024, capacity=10 * 1024 * 1024)
        self.client.put_object(bucket_name, 'test123', content=StringIO(""))
        self.assertEqual(self.client.get_object(bucket_name, 'test123').read(), b'')
        self.client.put_object(bucket_name, 'test', content=BytesIO(b""))
        self.assertEqual(self.client.get_object(bucket_name, 'test').read(), b'')
        self.client.put_object(bucket_name, 'test', content="")
        self.assertEqual(self.client.get_object(bucket_name, 'test').read(), b'')
        self.client.put_object(bucket_name, 'test', content=b'')
        self.assertEqual(self.client.get_object(bucket_name, 'test').read(), b'')
        self.client.put_object_from_file(bucket_name, 'test', file_name, data_transfer_listener=percentage,
                                         rate_limiter=rate_limiter)
        self.assertEqual(self.client.get_object(bucket_name, 'test').read(), b'')
        self.client.upload_file(bucket_name, 'test', file_name, data_transfer_listener=percentage,
                                rate_limiter=rate_limiter)
        self.assertEqual(self.client.get_object(bucket_name, 'test').read(), b'')
        with self.assertRaises(TosClientError):
            out = self.client.append_object(bucket_name, 'test456', 0, StringIO(""))

        create_out = self.client.create_multipart_upload(bucket_name, 'test789')
        self.client.upload_part(bucket_name, 'test789', upload_id=create_out.upload_id, part_number=1,
                                content=StringIO(''))
        self.client.upload_part(bucket_name, 'test789', upload_id=create_out.upload_id, part_number=1,
                                content=BytesIO(b''))
        self.client.upload_part_from_file(bucket_name, 'test789', upload_id=create_out.upload_id, part_number=1,
                                          file_path=file_name)

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
        # self.assertEqual(get_object_out.hash_crc64_ecma, get_object_out.client_crc)

    def test_get_object_to_file(self):
        bucket_name = self.bucket_name + 'download-dir'
        cwd = os.getcwd()
        key = self.random_key('.txt')
        content = random_bytes(1024 * 1024 * 5)
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        file_name = self.random_filename()
        with open(file_name, 'wb') as f:
            f.write(content)
        self.client.put_object_from_file(bucket_name, key, file_name)
        self.client.get_object_to_file(bucket_name, key, cwd + '/test.txt')
        self.assertFileContent(cwd + '/test.txt', content)

        content = content + b'1'
        self.client.put_object(bucket_name, key, content=content)
        self.client.get_object_to_file(bucket_name, key, cwd + '/test.txt')
        self.assertFileContent(cwd + '/test.txt', content)
        os.remove(cwd + '/test.txt')

        self.client.get_object_to_file(bucket_name, key, cwd + '/test/f1')
        self.assertFileContent(cwd + '/test/f1', content)

        self.client.get_object_to_file(bucket_name, key, cwd + '/dir1/')
        self.assertFileContent(cwd + '/dir1/' + key, content)
        os.remove(cwd + '/dir1/' + key)

        key = key + '/'
        self.client.put_object(bucket_name, key, content=content)
        self.client.get_object_to_file(bucket_name, key, cwd + '/dir3/')
        self.assertTrue(os.path.isdir(cwd + '/dir3/' + key))

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
        self.client.put_object(bucket_name, key=key, content=content)

        get_object_out = self.client.get_object(bucket_name, key=key)

        self.client.put_object(bucket_name, key + '1', content=get_object_out, data_transfer_listener=progress,
                               rate_limiter=limiter)
        get_object_out = self.client.get_object(bucket_name, key=key, data_transfer_listener=progress,
                                                rate_limiter=limiter)
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

    def test_put_with_chunked_invalid_length(self):
        bucket_name = self.bucket_name + '-put-with-chunked-invalid-length'
        key = self.random_key('.js')
        data = random_bytes(5)
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        self.client.put_object(bucket_name, key, content=data)

        get_out = self.client.get_object(bucket_name, key)
        key2 = self.random_key('.js')
        self.client.put_object(bucket_name, key2, content=get_out.content)

        get_out = self.client.get_object(bucket_name, key)
        self.client.put_object(bucket_name, key2, content=get_out.content, content_length=get_out.content_length)

        get_out = self.client.get_object(bucket_name, key2)
        self.assertEqual(get_out.read(), data)

        get_out = self.client.get_object(bucket_name, key2)
        create_out = self.client.create_multipart_upload(bucket_name, key2)
        self.client.upload_part(bucket_name, key2, upload_id=create_out.upload_id, part_number=1,
                                content=get_out.content, content_length=get_out.content_length)

        get_out = self.client.get_object(bucket_name, key2)
        self.client.upload_part(bucket_name, key2, upload_id=create_out.upload_id, part_number=2,
                                content=get_out.content)

    def test_anonymous(self):
        bucket_name = self.bucket_name + '-anonymous'
        key = self.random_key('.js')
        data = random_bytes(5)
        self.client.create_bucket(bucket_name, acl=ACLType.ACL_Public_Read_Write)
        self.client.put_object(bucket_name, key, acl=ACLType.ACL_Public_Read_Write, content=data)

        client = TosClientV2("", "", self.endpoint, self.region)
        out = client.get_object(bucket_name, key)
        self.assertEqual(out.read(), data)

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
            value='2'
        ))
        tag_set.append(Tag(
            key='3',
            value='4'
        ))
        put_out = self.client.put_object_tagging(bucket=bucket_name, key=key, tag_set=tag_set)
        self.assertIsNone(put_out.version_id)

        get_out = self.client.get_object_tagging(bucket=bucket_name, key=key)
        self.assertIsNotNone(get_out.request_id)
        get_set = get_out.tag_set
        self.assertTrue(len(get_set) == 2)
        self.assertEqual(get_set[0].key, '1')
        self.assertEqual(get_set[0].value, '2')

        self.assertEqual(get_set[1].key, '3')
        self.assertEqual(get_set[1].value, '4')

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
        self.client.put_object(bucket_name, 'key')

        # out_2 = self.client.list_objects_type2(bucket=bucket_name, prefix='0', start_after='0/1', max_keys=2)
        # out_2_reverse = self.client.list_objects_type2(bucket=bucket_name, prefix='0', start_after='0/1', max_keys=2)
        # out_3 = self.client.list_objects_type2(bucket=bucket_name, prefix='0', start_after='0/1', max_keys=2,
        #                                        delimiter='/', continuation_token=out_2.next_continuation_token)
        #

        out_base = self.client.list_objects_type2(bucket_name, delimiter='/', max_keys=1)
        self.assertEqual(out_base.name, bucket_name)
        self.assertIsNotNone(out_base.request_id)
        self.assertTrue(out_base.is_truncated)
        self.assertEqual(out_base.delimiter, '/')
        self.assertEqual(out_base.max_keys, 1)
        self.assertIsNotNone(out_base.next_continuation_token)
        out_base_2 = self.client.list_objects_type2(bucket_name, continuation_token=out_base.next_continuation_token)
        self.assertIsNotNone(out_base_2.continuation_token)

        out_base_3 = self.client.list_objects_type2(bucket_name, prefix='0', max_keys=1)
        self.assertEqual(out_base_3.prefix, '0')

        continuation_token = None
        is_truncated = True
        count = 0
        while is_truncated:
            out = self.client.list_objects_type2(bucket_name, continuation_token=continuation_token, max_keys=2,
                                                 delimiter='/')
            is_truncated = out.is_truncated
            continuation_token = out.next_continuation_token
            keycount = len(out.contents) + len(out.common_prefixes)
            self.assertEqual(keycount, out.key_count)
            count += keycount
            if is_truncated:
                self.assertIsNotNone(continuation_token)
        self.assertEqual(count, 4)

        continuation_token = None
        is_truncated = True
        count = 0
        while is_truncated:
            out = self.client.list_objects_type2(bucket_name, continuation_token=continuation_token, max_keys=2)
            is_truncated = out.is_truncated
            continuation_token = out.next_continuation_token
            keycount = len(out.contents) + len(out.common_prefixes)
            self.assertEqual(keycount, out.key_count)
            self.assertIsNotNone(out.contents)
            for c in out.contents:
                self.assertTrue(c.owner.id)
                self.assertTrue(c.owner.display_name)
            count += keycount
            if is_truncated:
                self.assertIsNotNone(continuation_token)
        self.assertEqual(count, 28)

        continuation_token = None
        is_truncated = True
        count = 0
        while is_truncated:
            out = self.client.list_objects_type2(bucket_name, continuation_token=continuation_token)
            is_truncated = out.is_truncated
            continuation_token = out.next_continuation_token
            keycount = len(out.contents) + len(out.common_prefixes)
            self.assertEqual(keycount, out.key_count)
            count += keycount
            if is_truncated:
                self.assertIsNotNone(continuation_token)
        self.assertEqual(count, 28)

        continuation_token = None
        is_truncated = True
        count = 0
        while is_truncated:
            out = self.client.list_objects_type2(bucket_name, continuation_token=continuation_token,
                                                 delimiter='/')
            is_truncated = out.is_truncated
            continuation_token = out.next_continuation_token
            keycount = len(out.contents) + len(out.common_prefixes)
            self.assertEqual(keycount, out.key_count)
            count += keycount
            if is_truncated:
                self.assertIsNotNone(continuation_token)
        self.assertEqual(count, 4)

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
                                             meta=meta, acl=ACLType.ACL_Public_Read)
        out = self.client.get_object(bucket=bucket_name, key=key)
        acl_out = self.client.get_object_acl(bucket_name, key)
        self.assertEqual(acl_out.grants[0].permission, PermissionType.Permission_Read)
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
        out = self.client.put_fetch_task(bucket=bucket_name, key=key, url=url)
        self.assertIsNotNone(out.task_id)
        time.sleep(10)

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
        resp.close()

        condition = [PostSignatureCondition(key='x-tos-acl', value='private', operator='eq')]
        out2 = self.client.pre_signed_post_signature(conditions=condition, bucket=bucket_name, key=key)
        form2 = {'key': key, 'x-tos-algorithm': out2.algorithm, 'bucket': bucket_name, 'x-tos-date': out2.date,
                 'policy': out2.policy, 'x-tos-signature': out2.signature, 'x-tos-credential': out2.credential,
                 'x-tos-acl': 'private'}
        resp = requests.post(url=self.client._make_virtual_host_url(bucket_name),
                             files={"upload_file": open(file_name, 'rb')},
                             data=form2)
        resp.close()

        self.assertEqual(resp.status_code, 204)

        form2['x-tos-acl'] = 'public-read'
        resp = requests.post(url=self.client._make_virtual_host_url(bucket_name),
                             files={"upload_file": open(file_name, 'rb')},
                             data=form2)
        resp.close()
        self.assertEqual(resp.status_code, 403)

    def test_pre_signed_policy_url(self):
        bucket_name = self.bucket_name + 'test-policy-url'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        self.client.put_bucket_versioning(bucket_name, VersioningStatusType.Versioning_Status_Enabled)
        time.sleep(60)
        self.client.put_object(bucket_name, 'abc/')
        self.client.put_object(bucket_name, 'abc/abc/')
        out_v1 = self.client.put_object(bucket_name, 'exampleobject', content=b'1')
        out_v2 = self.client.put_object(bucket_name, 'exampleobject', content=b'3')
        self.client.put_object(bucket_name, 'exampleobject1', content=b'2')
        conditions = [PolicySignatureCondition(key='key', value='abc/', operator='starts-with'),
                      # PostSignatureCondition(key='key', value='abc/abc/', operator='starts-with'),
                      PolicySignatureCondition(key='key', value='exampleobject', operator='eq'),
                      PolicySignatureCondition(key='key', value='exampleobject1')]
        out = self.client.pre_signed_policy_url(bucket_name, conditions)
        o1_2 = out.get_signed_url_for_list()
        o2_2 = out.get_signed_url_for_get_or_head('test')
        list_url = out.get_signed_url_for_list({'prefix': 'abc/abc/'})
        get_url = out.get_signed_url_for_get_or_head(key='exampleobject',
                                                     additional_query={'versionId': out_v1.version_id})
        list_ans = requests.get(list_url)
        self.assertTrue(b'abc/' in list_ans.content)
        get_out = requests.get(get_url)
        self.assertEqual(b'1', get_out.content)

        out_1 = self.client.pre_signed_policy_url(bucket_name, conditions,
                                                  alternative_endpoint='tos-cn-beijing.volces.com')
        self.assertEqual(out_1._host, 'tos-cn-beijing.volces.com')
        self.assertEqual(out_1._scheme, 'https://')
        out_11 = self.client.pre_signed_policy_url(bucket_name, conditions,
                                                   alternative_endpoint='tos-cn-beijing.volces.com',
                                                   is_custom_domain=True)
        self.assertIsNone(out_11._bucket)
        out_2 = self.client.pre_signed_policy_url(bucket_name, conditions,
                                                  alternative_endpoint='http://tos-cn-beijing.volces.com')
        self.assertEqual(out_2._host, 'tos-cn-beijing.volces.com')
        self.assertEqual(out_2._scheme, 'http://')
        out_3 = self.client.pre_signed_policy_url(bucket_name, conditions,
                                                  alternative_endpoint='https://tos-cn-beijing.volces.com')
        self.assertEqual(out_3._host, 'tos-cn-beijing.volces.com')
        self.assertEqual(out_3._scheme, 'https://')

    def test_wrapper_socket_io(self):
        bucket_name = self.bucket_name + 'test-wrapper-crc'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        case = [True, False]
        for i in case:
            for j in case:
                for k in case:
                    print('init:{}, crc:{} use_data_transfer_listener: {}, ues_limiter: {}'.format("yes", i, j, k))
                    self.wrapper_socket_io(True, i, j, k, bucket_name)

    def test_wrapper(self):
        bucket_name = self.bucket_name + 'test-wrapper-crc'
        content = random_bytes(1024 * 1024 * 6)
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        case = [True, False]
        # for i in case:
        #     for j in case:
        #         for k in case:
        #             print('init:{}, crc:{} use_data_transfer_listener: {}, ues_limiter: {}'.format("yes", i, j, k))
        #             self.wappper(True, i, j, k, bucket_name, content, reset_content=content)

        file_name = self.random_filename()
        with open(file_name, 'wb') as f:
            f.write(content)
        with open(file_name, 'rb') as f:
            size = os.path.getsize(file_name)
            body = tos.utils._make_upload_part_file_content(f, offset=1024, part_size=1024, size=size)
            for i in case:
                for j in case:
                    for k in case:
                        print('init:{}, crc:{} use_data_transfer_listener: {}, ues_limiter: {}'.format("yes", i, j, k))
                        self.wappper(True, i, j, k, bucket_name, content[1024:2048], reset_content=content[1024:2048])

    def test_get_object_range(self):
        bucket_name = self.bucket_name + 'object-range'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        key = self.random_key('.js')
        key_copy = self.random_key('.js')
        content = random_bytes(1024 * 1024)
        self.client.put_object(bucket_name, key, content=content)
        out = self.client.get_object(bucket_name, key, range='bytes=0-1023')
        self.assertEqual(out.read(), content[0:1024])
        out_2 = self.client.get_object(bucket_name, key, range='bytes=1024-')
        self.assertEqual(out_2.read(), content[1024:])

    def test_copy_object_range(self):
        src_bucket_name = self.bucket_name + 'copy-object-range'
        key = self.random_key('.js')
        save_bucket_name = 'save'
        content = random_bytes(1024)
        self.client.create_bucket(src_bucket_name)
        self.client.create_bucket(save_bucket_name)
        self.bucket_delete.append(save_bucket_name)
        self.bucket_delete.append(src_bucket_name)

        self.client.put_object(bucket=src_bucket_name, key=key, content=content)

        out = self.client.create_multipart_upload(save_bucket_name, key)
        parts = []
        part_copy_1 = self.client.upload_part_copy(out.bucket, out.key, out.upload_id, part_number=1,
                                                   src_bucket=src_bucket_name, src_key=key,
                                                   copy_source_range='bytes=0-100')

        parts.append(UploadedPart(1, part_copy_1.etag))

        self.client.complete_multipart_upload(save_bucket_name, key, out.upload_id, parts)

        out = self.client.get_object(bucket=save_bucket_name, key=key)
        self.assertEqual(out.read(), content[0:101])

    def test_non_file(self):
        bucket_name = self.bucket_name + 'non-file'
        key = self.random_key('.js')
        file_name = self.random_filename()
        download_file_1 = self.random_filename()
        download_file_2 = self.random_filename()
        with open(file_name, 'wb+') as f:
            pass
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        self.client.put_object_from_file(bucket_name, key, file_name)
        self.client.head_object(bucket_name, key)
        self.client.get_object_to_file(bucket_name, key, download_file_1)

        self.client.delete_object(bucket_name, key)
        self.client.upload_file(bucket_name, key, file_name)

        self.client.head_object(bucket_name, key)
        self.client.download_file(bucket_name, key, download_file_2)

        # 创建 TosClientV2 对象，对桶和对象的操作都通过 TosClientV2 实现
        def copy_event(copy_event_type: CopyEventType, err, bucket, key, upload_id, src_bucket, src_key, src_version_id,
                       checkpoint, copy_part):
            print(copy_event_type, err, bucket, key, upload_id, src_bucket, src_key, src_version_id, checkpoint,
                  copy_part)

        resumable_copy_object = self.client.resumable_copy_object(bucket_name, key + '1', bucket_name, key,
                                                                  copy_event_listener=copy_event)
        head_out = self.client.head_object(bucket=bucket_name, key=key + '1')
        get_out = self.client.get_object(bucket=bucket_name, key=key + '1')
        assert get_out.read() == b''
        self.client.copy_object(bucket_name, key + '1', bucket_name, key)

        out = self.client.create_multipart_upload(bucket_name, key + '2')
        part = self.client.upload_part_from_file(bucket_name, key + '2', upload_id=out.upload_id, part_number=1,
                                                 file_path=file_name)
        self.client.complete_multipart_upload(bucket_name, key + '2', upload_id=out.upload_id, parts=[part])
        self.client.head_object(bucket_name, key + '2')

    def test_restore_object(self):
        bucket_name = self.bucket_name + 'coldarchive'
        content = random_bytes(1024)
        key = self.random_key('.js')
        self.client.create_bucket(bucket=bucket_name, storage_class=StorageClassType.Storage_Class_Cold_Archive)
        self.bucket_delete.append(bucket_name)

        head_cold = self.client.head_bucket(bucket_name)
        self.assertEqual(head_cold.storage_class, StorageClassType.Storage_Class_Cold_Archive)

        obj = self.client.put_object(bucket=bucket_name, key=key)
        head_1 = self.client.head_object(bucket=bucket_name, key=key)
        self.assertEqual(head_1.storage_class, StorageClassType.Storage_Class_Cold_Archive)

        self.client.put_object(bucket=bucket_name, key=key, content=content)
        resp = self.client.restore_object(bucket=bucket_name, key=key, days=1,
                                          restore_job_parameters=RestoreJobParameters(TierType.Tier_Expedited))

        head_2 = self.client.head_object(bucket=bucket_name, key=key)
        self.assertEqual(head_2.storage_class, StorageClassType.Storage_Class_Cold_Archive)
        head_2.restore = 'ongoing-request="true"'
        head_2.restore_tier = TierType.Tier_Standard
        head_2.restore_expiry_days = 1
        time.sleep(60 * 5)

        out = self.client.get_object(bucket=bucket_name, key=key)
        self.assertEqual(out.read(), content)
        assert 'ongoing-request="false"' in out.restore

        self.client.put_object(bucket_name, key, storage_class=StorageClassType.Storage_Class_Archive)
        head_out = self.client.head_object(bucket_name, key)
        assert head_out.storage_class == StorageClassType.Storage_Class_Archive

    def test_traffic_limit(self):
        bucket_name = self.bucket_name + 'test-traffic-limit'
        content = random_bytes(MIN_TRAFFIC_LIMIT * 5)
        key = self.random_key('.js')
        self.client.create_bucket(bucket_name)
        start = time.time()
        self.client.put_object(bucket_name, key, content=content, traffic_limit=MIN_TRAFFIC_LIMIT)
        end = time.time()
        assert end - start > 5

    def test_rename_object(self):
        bucket_name = self.bucket_name + '-rename'
        content = random_bytes(1024)
        key = self.random_key('.js')
        self.client.create_bucket(bucket=bucket_name)
        self.bucket_delete.append(bucket_name)

        self.client.put_bucket_rename(bucket=bucket_name, rename_enable=True)
        time.sleep(30)
        bucket_rename_output = self.client.get_bucket_rename(bucket=bucket_name)
        self.assertEqual(bucket_rename_output.rename_enable, True)

        new_key = self.random_key('.js')
        self.client.put_object(bucket=bucket_name, key=key, content=content)
        self.client.rename_object(bucket=bucket_name, key=key, new_key=new_key)
        with self.assertRaises(TosServerError) as cm:
            self.client.get_object(bucket=bucket_name, key=key)
        self.assertEqual(cm.exception.status_code, 404)

        get_object_out = self.client.get_object(bucket=bucket_name, key=new_key)
        self.assertEqual(get_object_out.read(), content)

        self.client.delete_bucket_rename(bucket=bucket_name)
        bucket_rename_output = self.client.get_bucket_rename(bucket=bucket_name)
        self.assertEqual(bucket_rename_output.rename_enable, False)

    def test_callback(self):
        bucket_name = self.bucket_name + '-callback'
        content = random_bytes(1024)
        key = self.random_key('.js')
        self.client.create_bucket(bucket=bucket_name)
        self.bucket_delete.append(bucket_name)

        callback_url = '{"callbackUrl" : "http://www.test.xxx.com"}'
        callback = base64.b64encode(callback_url.encode('utf-8')).decode('utf-8')
        with self.assertRaises(TosServerError) as cm:
            self.client.put_object(bucket=bucket_name, key=key, content=content, callback=callback)
        self.assertEqual(cm.exception.status_code, 203)

        callback = base64.b64encode(self.callback.encode('utf-8')).decode('utf-8')
        callback_var = base64.b64encode(self.callback_var.encode('utf-8')).decode('utf-8')
        out = self.client.put_object(bucket=bucket_name, key=key, content=content, callback=callback,
                                     callback_var=callback_var)
        self.assertEqual(out.callback_result, '{"msg":"ok"}')

    def test_custom_domain(self):
        bucket_name = self.bucket_name + '-custom-domain'
        self.client.create_bucket(bucket=bucket_name)
        self.bucket_delete.append(bucket_name)
        content = random_bytes(100)
        key = self.random_key('.js')
        schema, host = _get_host_schema(self.endpoint)
        endpoint = schema + bucket_name + '.' + host

        client = TosClientV2(self.ak, self.sk, endpoint, self.region, enable_crc=True, max_retry_count=2,
                             is_custom_domain=True)
        client.put_object(bucket=bucket_name, key=key, content=content)
        get_out = self.client.get_object(bucket=bucket_name, key=key)
        self.assertTrue(get_out.read(), content)

        signed_url_out = client.pre_signed_url(HttpMethodType.Http_Method_Get, bucket=bucket_name, key=key)
        rsp = requests.get(signed_url_out.signed_url)
        self.assertEqual(rsp.content, content)

        client = TosClientV2(self.ak, self.sk, endpoint, self.region, enable_crc=True, max_retry_count=2)
        signed_url_out = client.pre_signed_url(HttpMethodType.Http_Method_Get, bucket=bucket_name, key=key,
                                               is_custom_domain=True)
        rsp = requests.get(signed_url_out.signed_url)
        self.assertEqual(rsp.content, content)

    def wrapper_socket_io(self, init, crc, use_data_transfer_listener, ues_limiter, bucket_name):
        def progress(consumed_bytes, total_bytes, rw_once_bytes,
                     data_type: DataTransferType):
            print("consumed_bytes:{0},total_bytes{1}, rw_once_bytes:{2}, type:{3}".format(consumed_bytes, total_bytes,
                                                                                          rw_once_bytes, data_type))

        data_transfer_listener = None
        limiter = None
        if use_data_transfer_listener:
            data_transfer_listener = progress
        if ues_limiter:
            limiter = RateLimiter(1024 * 1024, 1024 * 1024 * 5)
        if crc:
            client = tos.TosClientV2(self.ak, self.sk, self.endpoint, self.region)
        else:
            client = tos.TosClientV2(self.ak, self.sk, self.endpoint, self.region, enable_crc=False)
        key = self.random_key('.js')
        content = get_socket_io()
        if init:
            content = tos.utils.init_content(content)
            self.assertTrue(isinstance(content, tos.utils._IterableAdapter))
        if data_transfer_listener:
            content = tos.utils.add_progress_listener_func(content, data_transfer_listener)
            self.assertTrue(isinstance(content, tos.utils._IterableAdapter))
        if limiter:
            content = tos.utils.add_rate_limiter_func(content, limiter)
            self.assertTrue(isinstance(content, tos.utils._IterableAdapter))
        if crc:
            content = tos.utils.add_crc_func(content)
            self.assertTrue(isinstance(content, tos.utils._IterableAdapter))

        self.assertTrue(hasattr(content, 'can_reset'))
        self.assertEqual(content.can_reset, False)
        out = client.put_object(bucket_name, key=key, content=content)
        if crc:
            self.assertEqual(out.hash_crc64_ecma, content.crc)
        # self.assertObjectContent(bucket_name, key, get_socket_io().read())

    def wappper(self, init, crc, use_data_transfer_listener, ues_limiter, bucket_name, content, reset_content=None):

        def progress(consumed_bytes, total_bytes, rw_once_bytes,
                     data_type: DataTransferType):
            print("consumed_bytes:{0},total_bytes{1}, rw_once_bytes:{2}, type:{3}".format(consumed_bytes, total_bytes,
                                                                                          rw_once_bytes, data_type))

        origin = content
        data_transfer_listener = None
        limiter = None
        if use_data_transfer_listener:
            data_transfer_listener = progress
        if ues_limiter:
            limiter = RateLimiter(1024 * 1024 * 3, 1024 * 1024 * 10)
        if crc:
            client = tos.TosClientV2(self.ak, self.sk, self.endpoint, self.region)
        else:
            client = tos.TosClientV2(self.ak, self.sk, self.endpoint, self.region, enable_crc=False)
        key = self.random_key('.js')
        if init:
            content = tos.utils.init_content(content)
            self.assertTrue(isinstance(content, tos.utils._ReaderAdapter))
            self.assertEqual(content.can_reset, True)
        if data_transfer_listener:
            content = tos.utils.add_progress_listener_func(content, data_transfer_listener)
            self.assertTrue(isinstance(content, tos.utils._ReaderAdapter))
            self.assertEqual(content.can_reset, True)
        if limiter:
            content = tos.utils.add_rate_limiter_func(content, limiter)
            self.assertTrue(isinstance(content, tos.utils._ReaderAdapter))
            self.assertEqual(content.can_reset, True)
        if crc:
            content = tos.utils.add_crc_func(content)
            self.assertTrue(isinstance(content, tos.utils._ReaderAdapter))
            self.assertEqual(content.can_reset, True)

        self.assertTrue(hasattr(content, 'can_reset'))
        self.assertEqual(content.can_reset, True)
        out = client.put_object(bucket_name, key=key, content=content)
        if limiter:
            self.assertTrue(limiter._current_amount > 0)
        if crc:
            self.assertEqual(out.hash_crc64_ecma, content.crc)
        self.assertObjectContent(bucket_name, key, origin)

        if reset_content:
            content.reset()
            client.put_object(bucket_name, key, content=content)
            if crc:
                self.assertEqual(out.hash_crc64_ecma, content.crc)
            self.assertObjectContent(bucket_name, key, reset_content)

    def random_key(self, suffix=''):
        key = self.prefix + random_string(12) + suffix
        return key


if __name__ == '__main__':
    unittest.main()
