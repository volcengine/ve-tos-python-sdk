# -*- coding: utf-8 -*-
import base64
import datetime
import unittest

from tests.common import TosTestBase, random_bytes
from tos.enum import ACLType, StorageClassType
from tos.exceptions import TosServerError
from tos.models2 import UploadedPart


class TestMultipart(TosTestBase):
    def test_multipart(self):
        bucket_name = self.bucket_name + "-test-multipart"
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket_name)
        key = self.random_key('.js')
        mult_out = self.client.create_multipart_upload(bucket_name, key)
        parts = []
        content = random_bytes(5 * 1024 * 1024)
        for i in range(1, 3):
            upload_part_output = self.client.upload_part(bucket=bucket_name, key=key, upload_id=mult_out.upload_id,
                                                         part_number=i, content=content)
            parts.append(UploadedPart(i, upload_part_output.etag))

        list_parts = self.client.list_parts(bucket_name, key, mult_out.upload_id, max_parts=1)
        self.assertEqual(list_parts.bucket, bucket_name)
        self.assertEqual(list_parts.key, key)
        self.assertEqual(list_parts.upload_id, mult_out.upload_id)
        self.assertEqual(list_parts.max_parts, 1)
        self.assertEqual(list_parts.is_truncated, True)
        self.assertIsNotNone(list_parts.next_part_number_marker)
        self.assertEqual(list_parts.storage_class, StorageClassType.Storage_Class_Standard)
        self.assertTrue(list_parts.owner is not None)
        self.assertTrue(len(list_parts.parts), 1)

        part = list_parts.parts[0]
        self.assertTrue(part.part_number is not None)
        self.assertTrue(len(part.etag) > 0)
        self.assertTrue(part.size is not None)
        self.assertTrue(part.last_modified is not None)

        list_parts_2 = self.client.list_parts(bucket_name, key, mult_out.upload_id,
                                              part_number_marker=list_parts.next_part_number_marker)
        self.assertEqual(len(list_parts_2.parts), 1)
        self.assertEqual(list_parts_2.is_truncated, False)

        complete_out = self.client.complete_multipart_upload(bucket_name, key, mult_out.upload_id, parts=parts)
        self.assertEqual(complete_out.bucket, bucket_name)
        self.assertTrue(len(complete_out.key) > 0)
        self.assertTrue(len(complete_out.etag) > 0)
        self.assertTrue(complete_out.hash_crc64_ecma > 0)

        get_out = self.client.get_object(bucket_name, key)
        self.assertEqual(get_out.read(), content + content)
        self.assertEqual(True, get_out.expiration is None)

    def test_multipart_expires(self):
        bucket_name = self.bucket_name + "-test-multipart-expires"
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket_name)
        key = self.random_key('.js')
        mult_out = self.client.create_multipart_upload(bucket_name, key,object_expires=3)
        parts = []
        content = random_bytes(5 * 1024 * 1024)
        for i in range(1, 3):
            upload_part_output = self.client.upload_part(bucket=bucket_name, key=key, upload_id=mult_out.upload_id,
                                                         part_number=i, content=content)
            parts.append(UploadedPart(i, upload_part_output.etag))

        list_parts = self.client.list_parts(bucket_name, key, mult_out.upload_id, max_parts=1)
        self.assertEqual(list_parts.bucket, bucket_name)
        self.assertEqual(list_parts.key, key)
        self.assertEqual(list_parts.upload_id, mult_out.upload_id)
        self.assertEqual(list_parts.max_parts, 1)
        self.assertEqual(list_parts.is_truncated, True)
        self.assertIsNotNone(list_parts.next_part_number_marker)
        self.assertEqual(list_parts.storage_class, StorageClassType.Storage_Class_Standard)
        self.assertTrue(list_parts.owner is not None)
        self.assertTrue(len(list_parts.parts), 1)

        part = list_parts.parts[0]
        self.assertTrue(part.part_number is not None)
        self.assertTrue(len(part.etag) > 0)
        self.assertTrue(part.size is not None)
        self.assertTrue(part.last_modified is not None)

        list_parts_2 = self.client.list_parts(bucket_name, key, mult_out.upload_id,
                                              part_number_marker=list_parts.next_part_number_marker)
        self.assertEqual(len(list_parts_2.parts), 1)
        self.assertEqual(list_parts_2.is_truncated, False)

        complete_out = self.client.complete_multipart_upload(bucket_name, key, mult_out.upload_id, parts=parts)
        self.assertEqual(complete_out.bucket, bucket_name)
        self.assertTrue(len(complete_out.key) > 0)
        self.assertTrue(len(complete_out.etag) > 0)
        self.assertTrue(complete_out.hash_crc64_ecma > 0)

        get_out = self.client.get_object(bucket_name, key)
        self.assertEqual(get_out.read(), content + content)
        self.assertEqual(True, get_out.expiration is not None)


    def test_multipart_with_options(self):
        bucket_name = self.bucket_name + "-test-multipart-with-option"
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket_name)
        key = self.random_key('.js')
        meta = {'name': 'sunyushan'}
        mult_out = self.client.create_multipart_upload(bucket_name, key, cache_control="Cache-Control",
                                                       content_disposition="test", content_encoding="utf-8",
                                                       expires=datetime.datetime(2023, 1, 1),
                                                       content_language="english", content_type="text",
                                                       acl=ACLType.ACL_Bucket_Owner_Full_Control,
                                                       meta=meta,
                                                       storage_class=StorageClassType.Storage_Class_Ia
                                                       )
        parts = []
        content = random_bytes(5 * 1024 * 1024)
        for i in range(1, 3):
            upload_part_output = self.client.upload_part(bucket=bucket_name, key=key, upload_id=mult_out.upload_id,
                                                         part_number=i, content=content)
            parts.append(UploadedPart(i, upload_part_output.etag))

        self.client.list_parts(bucket_name, key, mult_out.upload_id)

        self.client.complete_multipart_upload(bucket_name, key, mult_out.upload_id, parts=parts)

        get_out = self.client.get_object(bucket_name, key)
        self.assertTrue(len(get_out.cache_control) > 0)
        self.assertEqual(get_out.content_disposition, "test")
        self.assertEqual(get_out.content_encoding, "utf-8")
        self.assertTrue(get_out.expires is not None)
        self.assertEqual(get_out.content_language, 'english')
        self.assertTrue(get_out.content_type, 'text')
        self.assertEqual(get_out.storage_class, StorageClassType.Storage_Class_Ia)

    def test_multipart_copy(self):
        src_bucket_name = self.bucket_name + "-test-multipart-copy"
        self.bucket_delete.append(src_bucket_name)
        self.client.create_bucket(src_bucket_name)
        key = self.random_key('.js')
        content = random_bytes(1024 * 1024 * 5)

        save_bucket_name = self.bucket_name + "test-multipart" + "v2"
        self.bucket_delete.append(save_bucket_name)
        self.client.create_bucket(save_bucket_name)

        self.client.put_object(src_bucket_name, key, content=content)

        out = self.client.create_multipart_upload(save_bucket_name, key)
        parts = []
        part_copy_1 = self.client.upload_part_copy(save_bucket_name, key, out.upload_id, part_number=1,
                                                   src_bucket=src_bucket_name, src_key=key)
        self.assertIsNotNone(part_copy_1.etag)
        self.assertIsNotNone(part_copy_1.last_modified)
        parts.append(UploadedPart(1, part_copy_1.etag))
        part_copy_2 = self.client.upload_part_copy(save_bucket_name, key, out.upload_id, part_number=2,
                                                   src_bucket=src_bucket_name, src_key=key)
        parts.append(UploadedPart(2, part_copy_2.etag))

        self.client.complete_multipart_upload(save_bucket_name, key, out.upload_id, parts)

        get_out = self.client.get_object(save_bucket_name, key)
        self.assertEqual(get_out.read(), content + content)

    def test_multipart_abort(self):
        bucket_name = self.bucket_name + "-test-multipart-abort"
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket_name)
        key = self.random_key('.js')
        mult_out = self.client.create_multipart_upload(bucket_name, key)
        parts = []
        content = random_bytes(5 * 1024 * 1024)
        for i in range(1, 3):
            upload_part_output = self.client.upload_part(bucket=bucket_name, key=key, upload_id=mult_out.upload_id,
                                                         part_number=i, content=content)
            parts.append(UploadedPart(i, upload_part_output.etag))

        self.client.abort_multipart_upload(bucket_name, key, mult_out.upload_id)
        with self.assertRaises(TosServerError):
            self.client.list_parts(bucket_name, key, mult_out.upload_id)

    def test_upload_part_from_file(self):
        bucket_name = self.bucket_name + "-test-multipart-file"
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket_name)
        key = self.random_key('.js')
        mult_out = self.client.create_multipart_upload(bucket_name, key)
        parts = []
        file_name = self.random_filename()
        content = random_bytes(1024 * 1024 * 10)
        with open(file_name, 'wb') as fw:
            fw.write(content)
        for i in range(1, 3):
            upload_part_output = self.client.upload_part_from_file(bucket=bucket_name, key=key,
                                                                   upload_id=mult_out.upload_id,
                                                                   part_number=i, file_path=file_name)
            parts.append(UploadedPart(i, upload_part_output.etag))

        list_parts = self.client.list_parts(bucket_name, key, mult_out.upload_id)
        self.assertEqual(list_parts.bucket, bucket_name)
        self.assertEqual(list_parts.key, key)
        self.assertEqual(list_parts.upload_id, mult_out.upload_id)
        self.assertEqual(list_parts.storage_class, StorageClassType.Storage_Class_Standard)
        self.assertTrue(list_parts.owner is not None)

        part = list_parts.parts[0]
        self.assertTrue(part.part_number is not None)
        self.assertTrue(len(part.etag) > 0)
        self.assertTrue(part.size is not None)
        self.assertTrue(part.last_modified is not None)

        complete_out = self.client.complete_multipart_upload(bucket_name, key, mult_out.upload_id, parts=parts)
        self.assertEqual(complete_out.bucket, bucket_name)
        self.assertTrue(len(complete_out.key) > 0)
        self.assertTrue(len(complete_out.etag) > 0)
        self.assertTrue(complete_out.hash_crc64_ecma > 0)

        self.assertObjectContent(bucket=bucket_name, key=key, content=content + content)

    def test_upload_part_from_file_with_offset(self):
        bucket_name = self.bucket_name + "-test-multipart-file"
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket_name)
        key = self.random_key('.js')
        mult_out = self.client.create_multipart_upload(bucket_name, key)
        parts = []
        file_name = self.random_filename()
        content = random_bytes(1024 * 13 * 1024)
        with open(file_name, 'wb') as fw:
            fw.write(content)
        for i in range(1, 4):
            upload_part_output = self.client.upload_part_from_file(bucket=bucket_name, key=key,
                                                                   upload_id=mult_out.upload_id,
                                                                   part_number=i, file_path=file_name,
                                                                   offset=5 * (i - 1) * 1024 * 1024,
                                                                   part_size=5 * 1024 * 1024)
            parts.append(UploadedPart(i, upload_part_output.etag))

        self.client.list_parts(bucket_name, key, mult_out.upload_id)
        self.client.complete_multipart_upload(bucket_name, key, mult_out.upload_id, parts=parts)
        self.assertObjectContent(bucket_name, key, content)

    def test_list_multipart_upload(self):
        bucket_name = self.bucket_name + '-test-list'
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket_name)
        self.client.create_multipart_upload(bucket_name, 'fun1')
        list_all = self.client.list_multipart_uploads(bucket_name)
        self.assertIsNotNone(list_all.encoding_type)
        self.assertTrue(len(list_all.uploads))
        self.assertEqual(list_all.max_uploads, 1000)
        self.assertEqual(list_all.uploads[0].storage_class, StorageClassType.Storage_Class_Standard)
        self.assertIsNotNone(list_all.uploads[0].upload_id)
        self.assertIsNotNone(list_all.uploads[0].owner.id)
        self.assertEqual(list_all.uploads[0].key, 'fun1')
        self.assertIsNotNone(list_all.uploads[0].initiated)

        self.client.create_multipart_upload(bucket_name, 'fun2/')
        self.client.create_multipart_upload(bucket_name, 'fun2/test')
        out_prefix = self.client.list_multipart_uploads(bucket_name, prefix='fun2')
        self.assertTrue(len(out_prefix.uploads), 2)
        self.assertEqual(out_prefix.prefix, 'fun2')

        out_max_keys = self.client.list_multipart_uploads(bucket_name, 'fun2', max_uploads=1)
        self.assertEqual(out_max_keys.max_uploads, 1)
        self.assertTrue(out_max_keys.is_truncated)
        self.assertIsNotNone(out_max_keys.next_key_marker)

        out_max_keys_2 = self.client.list_multipart_uploads(bucket_name, 'fun2/',
                                                            key_marker=out_max_keys.next_key_marker)
        self.assertEqual(out_max_keys_2.key_marker, out_max_keys.next_key_marker)
        self.assertEqual(out_max_keys_2.is_truncated, False)
        self.assertEqual(len(out_max_keys_2.uploads), 1)

        self.client.create_multipart_upload(bucket_name, 'fun3/')
        out_delimiter = self.client.list_multipart_uploads(bucket_name, delimiter='/')
        self.assertEqual(out_delimiter.delimiter, '/')
        self.assertEqual(len(out_delimiter.common_prefixes), 2)
        self.assertEqual(out_delimiter.common_prefixes[0].prefix, 'fun2/')
        self.assertEqual(out_delimiter.common_prefixes[1].prefix, 'fun3/')

    def test_list_part(self):
        bucket_name = self.bucket_name + "-test-list-part"
        key = self.random_key('.js')
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        out = self.client.create_multipart_upload(bucket_name, key).upload_id

    def test_complete_all(self):
        bucket_name = self.bucket_name + "-test-complete-all"
        key = self.random_key('.js')
        content = random_bytes(1024 * 1024 * 5)
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        self.client.put_object(bucket=bucket_name, key=key)
        with self.assertRaises(TosServerError):
            self.client.create_multipart_upload(bucket=bucket_name, key=key, forbid_overwrite=True)
        self.client.delete_object(bucket=bucket_name, key=key)

        resp = self.client.create_multipart_upload(bucket=bucket_name, key=key)
        for i in range(2):
            self.client.upload_part(bucket=bucket_name, key=key, upload_id=resp.upload_id, part_number=i + 1,
                                    content=content)
        complete_out = self.client.complete_multipart_upload(bucket_name, key, resp.upload_id, complete_all=True)
        assert len(complete_out.complete_parts) == 2
        out = self.client.get_object(bucket_name, key)
        assert out.read() == content + content


if __name__ == '__main__':
    unittest.main()
