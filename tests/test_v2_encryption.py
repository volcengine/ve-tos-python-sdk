# -*- coding: utf-8 -*-
import os
import unittest

from tests.common import TosTestBase, random_bytes
from tos.exceptions import TosServerError


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
        self.client.download_file(bucket_name, key, file_download, ssec_key=self.sseKey, ssec_algorithm=self.sseAlg,
                                  ssec_key_md5=self.sseKeyMd5)
        self.assertFileContent(file_download, content)

        with self.assertRaises(TosServerError):
            self.client.download_file(bucket_name, key, file_download)


if __name__ == '__main__':
    unittest.main()
