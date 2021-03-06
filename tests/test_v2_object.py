import base64
import datetime
import hashlib
import os
import unittest
from io import StringIO

from tests.common import random_bytes
from tests.test_v2_bucker import random_string
from tos.checkpoint import CancelHook
from tos.clientv2 import TosClientV2
from tos.enum import AzRedundancyType, ACLType, GranteeType, CannedType, PermissionType, \
    DataTransferType, StorageClassType, MetadataDirectiveType
from tos.exceptions import TosServerError, TosClientError
from tos.models2 import Delete, Grantee, Grant, ListObjectsOutput, Owner
from tos.utils import RateLimiter


def calculate_md5(content):
    md5 = hashlib.md5()
    buf = content.read()
    md5.update(buf)
    return base64.b64encode(md5.digest())


class TestObject(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestObject, self).__init__(*args, **kwargs)
        self.ak = os.getenv('AK')
        self.sk = os.getenv('SK')
        self.endpoint = os.getenv('Endpoint')
        self.region = os.getenv('Region')
        self.bucket_name = "sun-" + random_string(10)
        self.object_name = "test_object" + random_string(10)
        self.prefix = random_string(12)

    def setUp(self):
        self.client = TosClientV2(self.ak, self.sk, self.endpoint, self.region, enable_crc=True)

    def test_object(self):
        bucket_name = self.bucket_name + '-test-object'
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
        self.assertTrue(head_object_out.delete_marker == False)
        self.assertTrue(head_object_out.content_length == 1024)

        get_object_out = self.client.get_object(bucket_name, key)
        self.assertEqual(get_object_out.content.read(), content)

        range_out = self.client.get_object(bucket_name, key, range_start=1, range_end=100)
        read_content = range_out.read()
        self.assertEqual(read_content, content[1:101])

        self.client.delete_object(bucket_name, key=key)

        self.client.delete_bucket(bucket_name)

    def test_put_with_meta(self):
        bucket_name = self.bucket_name + '-put-object-with-meta'
        key = "??????.txt"
        content = random_string(123)

        self.client.create_bucket(bucket_name)

        meta = {'name': '??????', 'age': '12'}
        self.client.put_object(bucket_name, key, content=b'')
        put_object_out = self.client.put_object(bucket_name, key=key,
                                                content=content,
                                                meta=meta
                                                )
        get_object_out = self.client.get_object(bucket_name, key)
        m = get_object_out.meta
        self.assertEqual(m['name'], meta['name'])
        self.assertEqual(m['age'], meta['age'])

        meta['name'] = '??????'
        self.client.set_object_meta(bucket_name, key, meta=meta)
        head_out = self.client.head_object(bucket_name, key)
        m = head_out.meta
        self.assertEqual(m['name'], meta['name'])
        self.assertEqual(m['age'], meta['age'])

        self.client.delete_object(bucket_name, key)
        self.client.delete_bucket(bucket_name)

    def test_with_string_io(self):
        io = StringIO('a')
        io.seek(0)
        self.client.create_bucket("string-io")
        self.client.put_object(bucket='string-io', key="2", content=io)
        self.client.delete_object(bucket='string-io', key="2")
        self.client.delete_bucket(bucket='string-io')

    def test_put_with_options(self):
        bucket_name = self.bucket_name + '-put-with-options'
        key = self.random_key()
        content = random_bytes(123)

        self.client.create_bucket(bucket_name)

        put_object_out = self.client.put_object(bucket_name, key=key,
                                                content=content,
                                                cache_control='CacheControl',
                                                acl=ACLType.ACL_Private,
                                                content_encoding='utf-8',
                                                content_disposition='attachment; filename=???123.txt',
                                                content_length='123',
                                                content_language='english',
                                                expires=datetime.date(2023, 1, 29),
                                                website_redirect_location='/test',
                                                )
        get_object_out = self.client.get_object(bucket_name, key)
        self.assertTrue(len(get_object_out.cache_control) > 0)
        self.assertEqual(get_object_out.content_encoding, 'utf-8')
        self.assertEqual(get_object_out.content_disposition, 'attachment; filename=???123.txt')
        self.assertEqual(get_object_out.content_language, 'english')
        self.assertEqual(get_object_out.website_redirect_location, '/test')

        self.client.delete_object(bucket_name, key)
        self.client.delete_bucket(bucket_name)

    def test_put_with_cryptography(self):
        bucket_name = self.bucket_name + '-put-object-with-test-put-with-cryptography'
        key = self.random_key()
        content = random_bytes(100)

        self.client.create_bucket(bucket_name)
        with self.assertRaises(TosServerError):
            self.client.put_object(bucket_name, key=key, content=content, content_md5=random_bytes(20))

        with self.assertRaises(TosServerError):
            self.client.put_object(bucket_name, key=key, content=content, ssec_algorithm="DEC")

        self.client.delete_bucket(bucket_name)

    def test_put_with_empty_content(self):
        bucket_name = self.bucket_name + '-put-empty-object'
        key = self.random_key()
        content = b''

        self.client.create_bucket(bucket_name)
        put_object_out = self.client.put_object(bucket_name, key=key, content=content)
        get_object_out = self.client.get_object(bucket_name, key)
        # self.assertEqual(get_object_out.client_crc, 0)
        self.assertEqual(get_object_out.hash_crc64_ecma, 0)

        self.client.delete_object(bucket_name, key)
        self.client.delete_bucket(bucket_name)

    def test_put_with_illegal_name(self):
        bucket_name = self.bucket_name + '-put-object-with-illegal-name'
        key = random_bytes(1003)
        content = random_bytes(100)

        self.client.create_bucket(bucket_name)
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

        key = "????????????"
        self.client.put_object(bucket_name, key, content=content)
        self.client.delete_object(bucket_name, key)

        key = '%1 ? # *'
        self.client.put_object(bucket_name, key, content=content)
        self.client.get_object(bucket_name, key)
        self.client.delete_object(bucket_name, key)

        self.client.delete_bucket(bucket_name)

    def test_put_with_server_encryption(self):
        bucket_name = self.bucket_name + '-put-object-with-server-encryption'
        key = self.random_key('.js')
        content = random_bytes(100)
        self.client.create_bucket(bucket_name)

        self.client.put_object(bucket_name, key, content=content, server_side_encryption="AES256")
        self.client.get_object(bucket_name, key)

        self.client.delete_object(bucket_name, key)

        key = self.random_key(".js")
        with self.assertRaises(TosServerError):
            self.client.put_object(bucket_name, key, content=content, ssec_algorithm="AES256")

        self.client.delete_bucket(bucket_name)

    def test_put_with_client_encryption(self):
        bucket_name = self.bucket_name + '-put-object-with-client-encryption'
        key = self.random_key('.js')
        content = random_bytes(100)
        pass

    def test_put_with_data_transfer_listener(self):
        bucket_name = self.bucket_name + '-put-object-with-transfer-listener'
        key = self.random_key('.js')
        content = random_bytes(1024 * 1024 * 10)
        self.client.create_bucket(bucket_name)

        def progress(consumed_bytes, total_bytes, rw_once_bytes,
                     type: DataTransferType):
            print("consumed_bytes:{0},total_bytes{1}, rw_once_bytes:{2}, type:{3}".format(consumed_bytes, total_bytes,
                                                                                          rw_once_bytes, type))

        self.client.put_object(bucket_name, key, content=content)

        out = self.client.get_object(bucket_name, key, data_transfer_listener=progress)

        read_info = bytes()
        for buf in out.content:
            read_info = read_info + buf

        self.client.delete_object(bucket_name, key)

        self.client.delete_bucket(bucket_name)

    def test_object_from_file(self):
        bucket_name = self.bucket_name + '-put-object-from-file'
        key = self.random_key('.js')
        file_name = random_string(10)
        content = random_bytes(100)
        with open(file_name, 'wb') as fw:
            fw.write(content)

        self.client.create_bucket(bucket_name)

        put_file_out = self.client.put_object_from_file(bucket=bucket_name, key=key, file_path=file_name)

        out_file_name = self.client.get_object_to_file(bucket_name, key, "out.txt")

        with open('out.txt', 'rb') as wf:
            self.assertEqual(wf.read(), content)

        get_object_out = self.client.get_object(bucket=bucket_name, key=key)

        self.assertEqual(get_object_out.read(), content)

        self.client.delete_object(bucket_name, key)

        self.client.delete_bucket(bucket_name)
        os.remove(file_name)
        os.remove('out.txt')

    def test_upload_file(self):
        bucket_name = self.bucket_name + "test-put-file"
        key = self.random_key('.js')
        file_name = random_string(10)

        content = random_bytes(1024 * 1024 * 40)

        with open(file_name, "wb") as fw:
            fw.write(content)

        self.client.create_bucket(bucket_name)

        def upload_event_listener(upload_event_type, err, bucket, key, upload_id, checkpoint_file, upload_part_info):
            print(upload_event_type, err, bucket, key, upload_id, checkpoint_file, upload_part_info)

        class MyCancel(CancelHook):
            def cancel(self, is_abort: bool):
                super(MyCancel, self).cancel(is_abort=is_abort)
                print('some user define')

        cancel = MyCancel()

        upload_out = self.client.upload_file(bucket_name, key, file_path=file_name,
                                             upload_event_listener=upload_event_listener,
                                             cancel_hook=cancel)

        def process(type, err, bucket, key, version_id, file_path, checkpoint_file, temp_file, download_info):
            print(type, err, bucket, key, version_id, file_path, checkpoint_file, temp_file, download_info)

        """
        self.client.download_file(bucket=bucket_name, key=key,
                                  file_path="./file", task_num=3,
                                  part_size=1024 * 1024, download_event_listener=process)
        """

        self.client.delete_object(bucket_name, key)
        self.client.delete_bucket(bucket_name)

        os.remove(file_name)

    def test_upload_file_fuc(self):
        bucket_name = self.bucket_name + "sun-test-upload-file"
        key = "test.upload"
        file_name = random_string(10)

        content = random_bytes(1024 * 1024 * 40)

        with open(file_name, "wb") as fw:
            fw.write(content)

        self.client.create_bucket(bucket_name)
        self.client.upload_file(bucket_name, key, file_name)

        def process(type, err, bucket, key, version_id, file_path, checkpoint_file, temp_file, download_info):
            print(type, err, bucket, key, version_id, file_path, checkpoint_file, temp_file, download_info)

        """
                self.client.download_file(bucket=bucket_name, key=key,
                                  file_path="./file", task_num=3,
                                  part_size=1024 * 1024, download_event_listener=process)
        """

        self.client.delete_object(bucket_name, key)
        # os.remove('./file/test.upload')
        os.remove(file_name)

    """
    def test_download_file(self):
        bucket_name = self.bucket_name + "-download-file"
        key = self.random_key(".js")
        file_name = random_string(10)
        content = random_bytes(1024 * 1024 * 10)

        with open(file_name, "wb") as fw:
            fw.write(content)

        self.client.create_bucket(bucket_name)

        upload_out = self.client.upload_file(bucket_name, key, file_path=file_name, part_size=1024 * 1024 * 5)

        download_out = self.client.download_file(bucket=bucket_name, key=key, file_path='out.txt',
                                                 part_size=1024 * 1024)
        self.client.delete_object(bucket_name, key)
        self.client.delete_bucket(bucket_name)
        os.remove(file_name)
    """

    def test_delete_multi_objects(self):
        bucket_name = self.bucket_name + "-delete-multi-objects"
        key_1 = self.random_key('.js')
        key_2 = self.random_key('.js')
        content = random_bytes(20)

        self.client.create_bucket(bucket_name)
        self.client.put_object(bucket=bucket_name, key=key_1, content=content)
        self.client.put_object(bucket=bucket_name, key=key_2, content=content)
        self.client.head_object(bucket_name, key_1)
        object = []
        object.append(Delete(key_1, "", False, ""))
        object.append(Delete(key_1, "", False, ""))
        delete_out = self.client.delete_multi_objects(bucket=bucket_name, objects=object, quiet=False)

        self.client.delete_object(bucket_name, key_1)
        self.client.delete_object(bucket_name, key_2)
        self.client.delete_bucket(bucket_name)

    def test_copy_object(self):
        bucket_name_1 = self.bucket_name + '-copy-object1'
        bucket_name_2 = self.bucket_name + '-copy-object2'
        key = self.random_key(".java")
        content = random_bytes(100)
        self.client.create_bucket(bucket_name_1)
        self.client.create_bucket(bucket_name_2)
        put_out = self.client.put_object(bucket_name_1, key, content=content)
        copy_out = self.client.copy_object(bucket_name_2, key, bucket_name_1, key)
        head_out = self.client.head_object(bucket_name_2, key)
        get_out = self.client.get_object(bucket_name_2, key)

        self.client.delete_object(bucket_name_1, key)

        with self.assertRaises(TosServerError):
            self.client.copy_object(bucket_name_2, key, bucket_name_1, key)

        self.client.delete_object(bucket_name_2, key)
        self.client.delete_bucket(bucket_name_1)
        self.client.delete_bucket(bucket_name_2)

    def test_copy_object_options(self):
        bucket_name_1 = self.bucket_name + '-copy-object1'
        bucket_name_2 = self.bucket_name + '-copy-object2'
        key = self.random_key(".java")
        content = random_bytes(100)
        self.client.create_bucket(bucket_name_1)
        self.client.create_bucket(bucket_name_2)
        meta = {'??????': '??????'}
        put_object_out = self.client.put_object(bucket_name_1, key=key,
                                                content=content,
                                                cache_control='CacheControl',
                                                acl=ACLType.ACL_Private,
                                                content_encoding='utf-8',
                                                content_disposition='/sunyushantest',
                                                content_length='100',
                                                content_language='english',
                                                expires=datetime.date(2023, 1, 29),
                                                website_redirect_location='/test',
                                                meta=meta
                                                )

        copy_object_out = self.client.copy_object(bucket_name_2, key, src_bucket=bucket_name_1, src_key=key,
                                                  metadata_directive=MetadataDirectiveType.Metadata_Directive_Copy)
        head_out = self.client.head_object(bucket_name_2, key)
        get_object_out = self.client.get_object(bucket_name_2, key)

        self.assertTrue(len(get_object_out.cache_control) > 0)
        self.assertEqual(get_object_out.content_encoding, 'utf-8')
        self.assertEqual(get_object_out.content_disposition, '/sunyushantest')
        self.assertEqual(get_object_out.content_language, 'english')
        self.assertEqual(get_object_out.meta['??????'], meta['??????'])
        self.assertEqual(get_object_out.read(), content)
        # ??????????????????????????????
        # self.assertEqual(get_object_out.website_redirect_location, '/test')

        self.client.delete_object(bucket=bucket_name_1, key=key)
        self.client.delete_object(bucket=bucket_name_2, key=key)

        self.client.delete_bucket(bucket_name_1)
        self.client.delete_bucket(bucket_name_2)

    def test_copy_with_set_option(self):
        bucket_name_1 = self.bucket_name + '-copy-object1'
        bucket_name_2 = self.bucket_name + '-copy-object2'
        key = self.random_key(".java")
        content = random_bytes(100)
        self.client.create_bucket(bucket_name_1)
        self.client.create_bucket(bucket_name_2)
        meta = {'??????': '??????'}
        put_object_out = self.client.put_object(bucket_name_1, key=key,
                                                content=content)

        copy_object_out = self.client.copy_object(bucket_name_2, key, src_bucket=bucket_name_1, src_key=key,
                                                  cache_control='CacheControl',
                                                  acl=ACLType.ACL_Private,
                                                  content_encoding='utf-8',
                                                  content_disposition='/sunyushantest',
                                                  content_language='english',
                                                  expires=datetime.date(2023, 1, 29),
                                                  website_redirect_location='/test',
                                                  meta=meta,
                                                  storage_class=StorageClassType.Storage_Class_Ia,
                                                  metadata_directive=MetadataDirectiveType.Metadata_Directive_Replace
                                                  )

        head_out = self.client.head_object(bucket_name_2, key)
        get_object_out = self.client.get_object(bucket_name_2, key)

        self.assertTrue(len(get_object_out.cache_control) > 0)
        self.assertEqual(get_object_out.content_encoding, 'utf-8')
        self.assertEqual(get_object_out.content_disposition, '/sunyushantest')
        self.assertEqual(get_object_out.content_language, 'english')
        self.assertEqual(get_object_out.meta['??????'], meta['??????'])

        self.assertEqual(get_object_out.read(), content)
        # ??????????????????????????????
        # self.assertEqual(get_object_out.website_redirect_location, '/test')

        self.client.delete_object(bucket=bucket_name_1, key=key)
        self.client.delete_object(bucket=bucket_name_2, key=key)

        self.client.delete_bucket(bucket_name_1)
        self.client.delete_bucket(bucket_name_2)

    # ????????????????????????????????????, ??????????????????
    def test_mult_version(self):
        bucket_name = self.bucket_name + '-test-mult-object'
        key = self.random_key('.js')
        content = random_bytes(1024)
        self.client.create_bucket(bucket_name)
        # out = self.client.set_multi_version(bucket_name)

        # time.sleep(10)
        put_object_out_v1 = self.client.put_object(bucket_name, key=key, content=content)
        version_1 = put_object_out_v1.version_id
        content = random_bytes(2048)
        put_object_out_v2 = self.client.put_object(bucket_name, key=key, content=content)
        version_2 = put_object_out_v2.version_id

        out = self.client.get_object(bucket_name, key)
        list_out = self.client.list_object_versions(bucket_name)
        self.client.delete_object(bucket_name, key, version_id=version_1)
        self.client.delete_object(bucket_name, key, version_id=version_2)

        self.client.delete_bucket(bucket_name)

    # def test_create_mult_bucket(self):
    #     bucket_name = 'sun-mult-version-bucket'
    #     self.client.create_bucket(bucket_name)
    #     # self.client.set_multi_version(bucket_name)

    def test_append(self):
        bucket_name = self.bucket_name + '-test-append-object'
        key = self.random_key('.js')
        content = random_bytes(1024)

        self.client.create_bucket(bucket_name, az_redundancy=AzRedundancyType.Az_Redundancy_Multi_Az)
        append_object_out = self.client.append_object(bucket_name, key, 0, content=content)
        self.assertTrue(append_object_out.hash_crc64_ecma > 0)
        self.assertEqual(append_object_out.next_append_offset, 1024)
        self.client.delete_object(bucket_name, key)

        key = self.random_key('.js')
        append_out_1 = self.client.append_object(bucket_name, key, 0, content=content[0:100], pre_hash_crc64_ecma=0)

        append_out_2 = self.client.append_object(bucket_name, key, 100, content=content[100:],
                                                 pre_hash_crc64_ecma=append_out_1.hash_crc64_ecma)

        get_out = self.client.get_object(bucket_name, key)
        self.assertEqual(get_out.read(), content)

        self.client.delete_object(bucket_name, key)
        self.client.delete_bucket(bucket_name)

    def test_append_with_options(self):
        bucket_name = self.bucket_name + '-test-append-with-options'
        key = self.random_key('.js')
        content = random_bytes(1024)

        self.client.create_bucket(bucket_name, az_redundancy=AzRedundancyType.Az_Redundancy_Multi_Az)
        meta = {'name': '??????', 'age': '13'}
        append_object_out = self.client.append_object(bucket_name, key, 0,
                                                      content=content,
                                                      content_length="1024",
                                                      cache_control="Cache-Control",
                                                      content_disposition="utf-8",

                                                      content_language="english",
                                                      content_encoding="utf-8",

                                                      expires=datetime.date(2023, 1, 1),
                                                      acl=ACLType.ACL_Private,
                                                      meta=meta,
                                                      website_redirect_location='/test',
                                                      )
        self.assertTrue(append_object_out.hash_crc64_ecma > 0)
        self.assertEqual(append_object_out.next_append_offset, 1024)
        get_object_out = self.client.get_object(bucket_name, key)
        self.assertTrue(get_object_out.object_type == 'Appendable')

        self.client.delete_object(bucket_name, key)
        self.client.delete_bucket(bucket_name)

    def test_list_object_info(self):
        bucket_name = self.bucket_name + '-test-list-object'
        key = self.random_key('.js')
        content = random_bytes(1024)

        self.client.create_bucket(bucket_name, az_redundancy=AzRedundancyType.Az_Redundancy_Multi_Az)

        put_object_out_v1 = self.client.put_object(bucket_name, key=key, content=content)
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

        self.client.delete_object(bucket_name, key=key)
        self.client.delete_bucket(bucket_name)

    def test_list_object_full_func(self):
        bucket_name = self.bucket_name + '-test-list-object'
        self.client.create_bucket(bucket_name, az_redundancy=AzRedundancyType.Az_Redundancy_Multi_Az)
        for i in range(100):
            key = self.random_key('.js')
            content = random_bytes(1024)
            self.client.put_object(bucket_name, key=key, content=content)

        for i in range(10):
            self.client.put_object(bucket_name, key=str(i), content=random_bytes(10))

        list_object_out = self.client.list_objects(bucket_name, max_keys=50, prefix=self.prefix)
        self.assertEqual(self.prefix, list_object_out.prefix)
        self.assertEqual(list_object_out.max_keys, 50)
        self.assertTrue(list_object_out.is_truncated)

        list_object_out_v2 = self.client.list_objects(bucket_name, max_keys=51, prefix=self.prefix,
                                                      marker=list_object_out.next_marker, delimiter=self.prefix,
                                                      reverse=False)
        self.assertEqual(len(list_object_out_v2.contents), 50)
        self.assertFalse(list_object_out_v2.is_truncated)

        objects = self.client.list_objects(bucket_name)
        for obj in objects.contents:
            self.client.delete_object(bucket_name, obj.key)

        self.client.delete_bucket(bucket_name)

    def test_list_object_with_case(self):
        bucket_name = self.bucket_name + '-test-list-object-with-case'
        self.client.create_bucket(bucket_name)

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
                    deletes.append(Delete(key=path))
                    self.client.put_object(bucket_name, path, content=b'')

        out1 = self.client.list_objects(bucket_name, prefix='0')
        out2 = self.client.list_objects(bucket_name, prefix='1')
        out3 = self.client.list_objects(bucket_name, prefix='0/1')

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

        list_all = self.client.list_objects(bucket_name)
        for obj in list_all.contents:
            self.client.delete_object(bucket_name, obj.key)

        self.client.delete_bucket(bucket_name)

        # ?????????????????????????????????????????????????????????
        def test_list_objet_version(self):
            pass

    def test_set_object_meta(self):
        bucket_name = self.bucket_name + '-test-set-object-meta'
        key = self.random_key('.js')
        self.client.create_bucket(bucket_name)
        meta = {'name': 'sunyushan', 'age': '10'}
        self.client.put_object(bucket_name, key=key, content=random_bytes(10), meta=meta)
        meta['name'] = '??????'
        set_out = self.client.set_object_meta(bucket_name, key, meta=meta)

        get_object_out = self.client.get_object(bucket_name, key=key)
        self.assertEqual(meta['name'], get_object_out.meta['name'])
        self.client.delete_object(bucket_name, key=key)

        self.client.delete_bucket(bucket_name)

    def test_get_object_meta(self):
        bucket_name = self.bucket_name + '-test-get-object-meta'
        key = self.random_key('.js')
        self.client.create_bucket(bucket_name)
        meta = {'name': 'jason', 'age': '10'}
        self.client.put_object(bucket_name, key=key, content=random_bytes(10), meta=meta)

        get_object_out = self.client.get_object(bucket_name, key=key)
        self.client.delete_object(bucket_name, key=key)

        self.client.delete_bucket(bucket_name)

    def test_get_object_with_data_transfer_listener(self):
        bucket_name = self.bucket_name + '-test-with-transfer-listener'
        key = self.random_key('.js')
        content = random_bytes(1025 * 1024)
        self.client.create_bucket(bucket_name)

        def progress(consumed_bytes, total_bytes, rw_once_bytes,
                     type: DataTransferType):
            print(
                "consumed_bytes:{0},total_bytes{1}, rw_once_bytes:{2}, type:{3}".format(consumed_bytes, total_bytes,
                                                                                        rw_once_bytes, type))

        self.client.put_object(bucket_name, key=key, content=content)

        get_object_out = self.client.get_object(bucket_name, key=key, data_transfer_listener=progress,
                                                rate_limiter=RateLimiter(10, 100))
        self.assertEqual(get_object_out.read(), content)
        self.client.delete_object(bucket_name, key=key)

        self.client.delete_bucket(bucket_name)

    def test_with_rate_limiter(self):
        bucket_name = self.bucket_name + '-test-with-rate-limiter'
        key = self.random_key('.js')
        content = random_bytes(1024 * 1024)
        self.client.create_bucket(bucket_name)

        def progress(consumed_bytes, total_bytes, rw_once_bytes,
                     type: DataTransferType):
            print(
                "consumed_bytes:{0},total_bytes{1}, rw_once_bytes:{2}, type:{3}".format(consumed_bytes, total_bytes,
                                                                                        rw_once_bytes, type))

        limiter = RateLimiter(1200, 10000)
        put_out = self.client.put_object(bucket_name, key=key, content=content, data_transfer_listener=progress,
                                         rate_limiter=limiter)

        get_object_out = self.client.get_object(bucket_name, key=key, data_transfer_listener=progress)
        self.assertEqual(get_object_out.read(), content)
        self.client.delete_object(bucket_name, key=key)

        self.client.delete_bucket(bucket_name)

    def test_put_object_acl(self):
        bucket_name = self.bucket_name + '-test-put-object-acl'
        key = self.random_key('.js')
        self.client.create_bucket(bucket_name)
        self.client.put_object(bucket_name, key, content=random_bytes(5))
        grants = []
        grantee = Grantee("123", "123", type=GranteeType.Grantee_Group, canned=CannedType.Canned_All_Users)
        grant = Grant(grantee, permission=PermissionType.Permission_Full_Control)
        grants.append(grant)
        self.client.put_object_acl(bucket_name, key, acl=ACLType.ACL_Bucket_Owner_Full_Control)
        self.client.put_object_acl(bucket_name, key, owner=Owner("123", "test"), grants=grants)

        out = self.client.get_object_acl(bucket_name, key)

        self.client.delete_object(bucket_name, key)
        self.client.delete_bucket(bucket_name)

    def test_put_with_md5(self):
        bucket_name = self.bucket_name + '-put-with-md5'
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

        self.client.delete_object(bucket_name, key)
        self.client.delete_bucket(bucket_name)
        os.remove(path=file_name)

    def random_key(self, suffix=''):
        key = self.prefix + random_string(12) + suffix
        return key
