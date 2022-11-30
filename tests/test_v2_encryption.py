# -*- coding: utf-8 -*-
import os
import unittest

from tests.common import TosTestBase, random_bytes
from tos.exceptions import TosServerError
from tos.models2 import UploadedPart


class TestEncryption(TosTestBase):
    def test_customer_encryption(self):
        bucket_name = self.bucket_name + '-put-object-with-customer-encryption'
        key = self.random_key('.js')

        dis_bucket = self.bucket_name + "-put-dist-bucket-name"
        file_name = self.random_filename()
        content = random_bytes(1024 * 1024 * 4)
        self.client.create_bucket(bucket_name)
        self.client.create_bucket(dis_bucket)
        self.bucket_delete.append(bucket_name)
        self.bucket_delete.append(dis_bucket)

        self.client.put_object(bucket_name, key, content=content, ssec_algorithm=self.sseAlg,
                               ssec_key=self.sseKey, ssec_key_md5=self.sseKeyMd5)

        with self.assertRaises(TosServerError):
            self.client.get_object(bucket_name, key)

        out = self.client.get_object(bucket_name, key, ssec_algorithm=self.sseAlg,
                                     ssec_key=self.sseKey, ssec_key_md5=self.sseKeyMd5)
        self.assertEqual(out.read(), content)

        with self.assertRaises(TosServerError):
            self.client.get_object_to_file(bucket_name, key, file_name)
        self.client.get_object_to_file(bucket_name, key, file_name, ssec_algorithm=self.sseAlg, ssec_key=self.sseKey,
                                       ssec_key_md5=self.sseKeyMd5)
        self.assertFileContent(file_name, content)

        self.client.head_object(bucket_name, key, ssec_algorithm=self.sseAlg, ssec_key=self.sseKey,
                                ssec_key_md5=self.sseKeyMd5)
        with self.assertRaises(TosServerError):
            self.client.head_object(bucket_name, key)

        with self.assertRaises(TosServerError):
            self.client.copy_object(dis_bucket, key, bucket_name, key)
        self.client.copy_object(dis_bucket, key, bucket_name, key, copy_source_ssec_algorithm=self.sseAlg,
                                copy_source_ssec_key=self.sseKey, copy_source_ssec_key_md5=self.sseKeyMd5)
        self.client.head_object(dis_bucket, key)
        self.assertObjectContent(dis_bucket, key, content)

    def test_file_operator(self):
        bucket_name = self.bucket_name + '-encryption-file'
        key = self.random_key('.js')
        self.client.create_bucket(bucket_name)
        file_name = self.random_filename()
        file_download = self.random_filename()
        content = random_bytes(1024 * 1024 * 6)
        with open(file_name, 'wb') as f:
            f.write(content)
        self.client.put_object_from_file(bucket_name, key, file_name, ssec_algorithm=self.sseAlg, ssec_key=self.sseKey,
                                         ssec_key_md5=self.sseKeyMd5)
        with self.assertRaises(TosServerError):
            self.client.head_object(bucket_name, key)
        self.client.head_object(bucket_name, key, ssec_algorithm=self.sseAlg, ssec_key=self.sseKey,
                                ssec_key_md5=self.sseKeyMd5)
        out = self.client.get_object_to_file(bucket_name, key, file_download, ssec_algorithm=self.sseAlg,
                                             ssec_key=self.sseKey,
                                             ssec_key_md5=self.sseKeyMd5)

        self.assertFileContent(file_download, content)

    def test_server_encryption(self):
        bucket_name = self.bucket_name + '-put-object-with-customer-encryption'
        key = self.random_key('.js')

        content = random_bytes(1024 * 1024 * 4)
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        self.client.put_object(bucket_name, key, content=content, server_side_encryption=self.sseAlg)
        out = self.client.get_object(bucket_name, key)

    def test_upload_download_with_encryption(self):
        bucket_name = self.bucket_name + '-upload-file-with-customer-encryption'
        key = self.random_key('.js')
        file_name = self.random_filename()
        file_download = self.random_filename()
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket_name)
        content = random_bytes(1024 * 1024 * 6)
        with open(file_name, 'wb') as f:
            f.write(content)

        self.client.upload_file(bucket_name, key, file_name, ssec_algorithm=self.sseAlg, ssec_key=self.sseKey,
                                ssec_key_md5=self.sseKeyMd5)
        with self.assertRaises(TosServerError):
            self.client.download_file(bucket_name, key, file_download)
        self.client.download_file(bucket_name, key, file_download, ssec_key=self.sseKey, ssec_algorithm=self.sseAlg,
                                  ssec_key_md5=self.sseKeyMd5)
        self.assertFileContent(file_download, content)

        with self.assertRaises(TosServerError):
            self.client.download_file(bucket_name, key, file_download)

    def test_multi_part(self):
        bucket_name = self.bucket_name + '-encryption'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        key = self.random_key('.js')
        out = self.client.create_multipart_upload(bucket_name, key, ssec_key=self.sseKey, ssec_algorithm=self.sseAlg,
                                                  ssec_key_md5=self.sseKeyMd5)
        part_info = self.client.upload_part(bucket_name, key, out.upload_id, 1, content=b'123', ssec_key=self.sseKey,
                                            ssec_algorithm=self.sseAlg, ssec_key_md5=self.sseKeyMd5)
        parts = []
        parts.append(UploadedPart(part_number=1, etag=part_info.etag))
        self.client.complete_multipart_upload(bucket_name, key, out.upload_id, parts=parts)

    def test_copy_object(self):
        bucket_name = self.bucket_name + '-copy-encryption'
        src_key = self.random_key('.js')
        key = self.random_key('.js')
        content = random_bytes(1024 * 1025)
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        self.client.put_object(bucket_name, src_key, content=content, ssec_algorithm=self.sseAlg, ssec_key=self.sseKey,
                               ssec_key_md5=self.sseKeyMd5)
        self.client.copy_object(bucket_name, key, bucket_name, src_key, copy_source_ssec_algorithm=self.sseAlg,
                                copy_source_ssec_key=self.sseKey, copy_source_ssec_key_md5=self.sseKeyMd5,
                                ssec_algorithm=self.sseAlg, ssec_key=self.sseKey, ssec_key_md5=self.sseKeyMd5)
        with self.assertRaises(TosServerError):
            self.client.head_object(bucket_name, key)
        self.client.head_object(bucket_name, key, ssec_key=self.sseKey, ssec_algorithm=self.sseAlg,
                                ssec_key_md5=self.sseKeyMd5)
        out = self.client.get_object(bucket_name, key, ssec_key=self.sseKey, ssec_algorithm=self.sseAlg,
                                     ssec_key_md5=self.sseKeyMd5)
        self.assertEqual(out.read(), content)

    def test_copy_part(self):
        bucket_name = self.bucket_name + '-upload-part-copy'
        src_key = self.random_key('.js')
        key = self.random_key('.js')
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket_name)
        content = random_bytes(1024 * 1024 * 6)
        self.client.put_object(bucket_name, src_key, content=content, ssec_algorithm=self.sseAlg, ssec_key=self.sseKey,
                               ssec_key_md5=self.sseKeyMd5)
        out = self.client.create_multipart_upload(bucket_name, key, ssec_key=self.sseKey, ssec_algorithm=self.sseAlg,
                                                  ssec_key_md5=self.sseKeyMd5)

        with self.assertRaises(TosServerError):
            self.client.upload_part_copy(out.bucket, out.key, out.upload_id, 1, bucket_name, src_key,
                                         copy_source_ssec_algorithm=self.sseAlg,
                                         copy_source_ssec_key=self.sseKey, copy_source_ssec_key_md5=self.sseKeyMd5)

        part = self.client.upload_part_copy(out.bucket, out.key, out.upload_id, 1, bucket_name, src_key,
                                            copy_source_ssec_algorithm=self.sseAlg,
                                            copy_source_ssec_key=self.sseKey, copy_source_ssec_key_md5=self.sseKeyMd5,
                                            ssec_algorithm=self.sseAlg, ssec_key=self.sseKey,
                                            ssec_key_md5=self.sseKeyMd5)
        part_2 = self.client.upload_part_copy(out.bucket, out.key, out.upload_id, 2, bucket_name, src_key,
                                              copy_source_ssec_algorithm=self.sseAlg,
                                              copy_source_ssec_key=self.sseKey, copy_source_ssec_key_md5=self.sseKeyMd5,
                                              ssec_algorithm=self.sseAlg, ssec_key=self.sseKey,
                                              ssec_key_md5=self.sseKeyMd5)
        self.client.complete_multipart_upload(bucket_name, key, out.upload_id, [part, part_2])
        with self.assertRaises(TosServerError):
            self.client.head_object(bucket_name, key)

        get_out = self.client.get_object(bucket_name, key, ssec_algorithm=self.sseAlg, ssec_key=self.sseKey,
                                         ssec_key_md5=self.sseKeyMd5)

        self.assertEqual(get_out.read(), content + content)

    def test_resumable_copy_object(self):
        bucket_name = self.bucket_name + '-upload-part-copy'
        src_key = self.random_key('.js')
        key = self.random_key('.js')
        path = '/tmp'
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket_name)
        content = random_bytes(1024 * 1024 * 6)
        self.client.put_object(bucket_name, src_key, content=content, ssec_algorithm=self.sseAlg, ssec_key=self.sseKey,
                               ssec_key_md5=self.sseKeyMd5)

        self.client.resumable_copy_object(bucket_name, key, src_bucket=bucket_name, src_key=src_key,
                                          copy_source_ssec_algorithm=self.sseAlg, copy_source_ssec_key=self.sseKey,
                                          copy_source_ssec_key_md5=self.sseKeyMd5, checkpoint_file=path)

        self.client.head_object(bucket_name, key)
        self.client.resumable_copy_object(bucket_name, key, src_bucket=bucket_name, src_key=src_key,
                                          copy_source_ssec_algorithm=self.sseAlg, copy_source_ssec_key=self.sseKey,
                                          copy_source_ssec_key_md5=self.sseKeyMd5, checkpoint_file=path,
                                          ssec_algorithm=self.sseAlg, ssec_key_md5=self.sseKeyMd5, ssec_key=self.sseKey)
        with self.assertRaises(TosServerError):
            self.client.head_object(bucket_name, key)

        self.client.head_object(bucket_name, key, ssec_key=self.sseKey, ssec_algorithm=self.sseAlg,
                                ssec_key_md5=self.sseKeyMd5)


if __name__ == '__main__':
    unittest.main()
