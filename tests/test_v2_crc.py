# -*- coding: utf-8 -*-

import logging
import os
import unittest

import tos
from tests.common import TosTestBase, random_string, random_bytes

tos.set_logger(level=logging.DEBUG)


class TestObjectCrc(TosTestBase):
    def test_getobject_crc(self):
        client = tos.TosClientV2(self.ak, self.sk, self.endpoint, self.region, enable_crc=True)
        bucket = self.bucket_name + '-test-crc'
        client.create_bucket(bucket)
        self.bucket_delete.append(bucket)
        content = random_bytes(1024 * 1024 * 6)
        file_name = self.random_filename()
        with open(file_name, 'wb') as f:
            f.write(content)
        for i in range(2):
            key = self.random_key('.js')
            client.put_object(bucket, key, content=content)
            out = client.get_object(bucket, key)
            # 整个读取
            self.assertEqual(out.read(), content)
            out = client.get_object(bucket, key)

            # 不使用迭代器， chuck读取
            con = b''
            while True:
                buf = out.read(8 * 1024)
                if not buf:
                    break
                con += buf
            self.assertEqual(con, content)

            # 使用迭代器读取
            out = client.get_object(bucket, key)
            con = b''
            for buf in out:
                con += buf
            self.assertEqual(con, content)

            # 查询部分数据
            out = client.get_object(bucket, key, range_start=100, range_end=300)
            self.assertEqual(out.read(), content[100:301])

            out = client.get_object(bucket, key, range_start=100, range_end=300)
            con = b''
            while True:
                buf = out.read(8 * 1024)
                if not buf:
                    break
                con += buf
            self.assertEqual(con, content[100:301])

            out = client.get_object(bucket, key, range_start=100, range_end=300)
            con = b''
            for buf in out:
                con += buf
            self.assertEqual(con, content[100:301])

            client.put_object_from_file(bucket, key, file_name)
            cwd = os.getcwd()
            client.get_object_to_file(bucket, key, cwd)
            self.assertFileContent(cwd + '/' + key, content)
            client = tos.TosClientV2(self.ak, self.sk, self.endpoint, self.region, enable_crc=False)

    def random_key(self, suffix=''):
        key = self.prefix + random_string(12) + suffix
        return key


if __name__ == '__main__':
    unittest.main()
