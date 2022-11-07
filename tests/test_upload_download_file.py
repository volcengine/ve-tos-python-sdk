# -*- coding: utf-8 -*-
import logging
import os
import time
import unittest
from functools import partial
from unittest.mock import patch

import tos
from tests.common import TosTestBase, random_bytes
from tos import DataTransferType
from tos.checkpoint import CancelHook, CheckPointStore
from tos.utils import get_parent_directory_from_File


class NonlocalObject(object):
    def __init__(self, value):
        self.var = value


tos.set_logger(level=logging.INFO)


class TestUploadAndDownload(TosTestBase):

    # def test_upload_file_fuc(self):
    #     bucket_name = self.bucket_name + "sun-test-upload-file"
    #     key = "test.upload"
    #     file_name = self.random_filename()
    #
    #     content = random_bytes(1024 * 1024 * 40)
    #
    #     with open(file_name, "wb") as fw:
    #         fw.write(content)
    #
    #     self.client.create_bucket(bucket_name)
    #     self.bucket_delete.append(bucket_name)
    #     self.client.upload_file(bucket_name, key, file_name)
    #
    #     def process(type, err, bucket, key, version_id, file_path, checkpoint_file, temp_file, download_info):
    #         print(type, err, bucket, key, version_id, file_path, checkpoint_file, temp_file, download_info)
    #
    #     self.client.download_file(bucket=bucket_name, key=key,
    #                               file_path="./file", task_num=3,
    #                               part_size=1024 * 1024, download_event_listener=process)
    #
    #     os.remove('./file/test.upload')
    #     os.remove(file_name)

    # def test_download_file(self):
    #     bucket_name = self.bucket_name + "-download-file"
    #     key = self.random_key(".js")
    #     file_name = self.random_filename()
    #     content = random_bytes(1024 * 1024 * 9)
    #     with open(file_name, "wb") as fw:
    #         fw.write(content)
    #
    #     self.client.create_bucket(bucket_name)
    #     self.bucket_delete.append(bucket_name)
    #     upload_out = self.client.upload_file(bucket_name, key, file_path=file_name)
    #
    #     checkpont = '/Users/bytedance/Desktop/python/ve-tos-python-sdk/tests/checkpoint/test/'
    #     download_out = self.client.download_file(bucket=bucket_name, key=key,
    #                                              file_path='file/',
    #                                              part_size=1024 * 1024, checkpoint_file=checkpont)
    #     self.assertFileContent(
    #         'file/{}'.format(key), content)

    def test_small_file(self):
        bucket_name = self.bucket_name + 'upload-download-small-file'
        self.__test_normal(bucket_name, 1023)

    def test_large_file_with_single_threaded(self):
        bucket_name = self.bucket_name + 'upload-download-large-file-single-threaded'
        self.__test_normal(bucket_name, 10 * 1024 * 1024 + 3, thread_num=1)

    def test_large_file_with_multi_threaded(self):
        bucket_name = self.bucket_name + 'upload-download-large-file-multi-threaded'
        self.__test_normal(bucket_name, 51 * 1024 * 1023, thread_num=7)

    def test_threaded_larger_part_size(self):
        bucket_name = self.bucket_name + 'upload-threaded-larger-part-size'
        self.__test_normal(bucket_name, 50 * 1024 * 1023, thread_num=11)

    def test_download_fail_fist_part(self):
        bucket_name = self.bucket_name + 'download-fail-fist-part'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        key, content, filename_upload, filename_download = self.__prepare(40 * 1024 * 1025)
        self.__test_resume_upload(bucket_name, key, filename_upload, 40 * 1024 * 1025, content, [1])
        self.__test_resume_download(bucket_name, key, filename_download, 40 * 1024 * 1025, content, [1])

    def test_download_fail_last_part(self):
        bucket_name = self.bucket_name + 'download-fail-last-part'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        key, content, filename_upload, filename_download = self.__prepare(40 * 1024 * 1025)
        self.__test_resume_upload(bucket_name, key, filename_upload, 40 * 1024 * 1025, content, [3])
        self.__test_resume_download(bucket_name, key, filename_download, 40 * 1024 * 1025, content, [3])

    def test_download_fail_mid_part(self):
        bucket_name = self.bucket_name + 'download-fail-mid-part'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        key, content, filename_upload, filename_download = self.__prepare(40 * 1024 * 1025)
        self.__test_resume_upload(bucket_name, key, filename_upload, 40 * 1024 * 1025, content, [2])
        self.__test_resume_download(bucket_name, key, filename_download, 40 * 1024 * 1025, content, [2])

    def test_download(self):
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
        self.client.download_file(bucket_name, key, cwd + '/test.txt')
        self.assertFileContent(cwd + '/test.txt', content)

        content = content + b'1'
        self.client.put_object(bucket_name, key, content=content)
        self.client.download_file(bucket_name, key, cwd + '/test.txt')
        self.assertFileContent(cwd + '/test.txt', content)
        os.remove(cwd + '/test.txt')

        self.client.download_file(bucket_name, key, cwd + '/test/f1')
        self.assertFileContent(cwd + '/test/f1', content)

        self.client.download_file(bucket_name, key, cwd + '/dir1/')
        self.assertFileContent(cwd + '/dir1/' + key, content)
        os.remove(cwd + '/dir1/' + key)

        key = key + '/'
        self.client.put_object(bucket_name, key, content=content)
        self.client.download_file(bucket_name, key, cwd + '/dir3/')
        self.assertTrue(os.path.isdir(cwd + '/dir3/' + key))

    def __test_normal(self, bucket_name, file_size, part_size=5 * 1024 * 1024 + 1, thread_num=3):
        def percentage(consumed_bytes, total_bytes, rw_once_bytes,
                       type: DataTransferType):
            if total_bytes:
                rate = int(100 * float(consumed_bytes) / float(total_bytes))
                print("rate:{}, consumed_bytes:{},total_bytes{}, rw_once_bytes:{}, type:{}".format(rate, consumed_bytes,
                                                                                                   total_bytes,
                                                                                                   rw_once_bytes, type))

        self.client.create_bucket(bucket=bucket_name)
        self.bucket_delete.append(bucket_name)
        key, content, filename_upload, filename_download = self.__prepare(file_size)
        self.client.upload_file(bucket=bucket_name, key=key, file_path=filename_upload, part_size=part_size,
                                task_num=thread_num)

        self.client.download_file(bucket=bucket_name, key=key, file_path=filename_download, part_size=part_size,
                                  task_num=thread_num, data_transfer_listener=percentage)

        self.assertFileContent(filename_upload, content)
        self.assertFileContent(filename_download, content)

    def __test_resume_download(self, bucket_name, key, file_name, file_size, content, failed_parts):
        total = NonlocalObject(0)
        orig_download_part = tos.checkpoint._BreakpointDownloader._download_part

        def mock_download_part(self, part, failed_parts=None):
            if part.part_number in failed_parts:
                raise RuntimeError("Fail download_part for part: {0}".format(part.part_number))
            else:
                total.var += 1
                orig_download_part(self, part)

        self._test_resume(tos.checkpoint._BreakpointDownloader, '_download_part', mock_download_part, bucket_name, key,
                          file_name, file_size, content, failed_parts, 'download', self.client.download_file, total)

    def __test_resume_upload(self, bucket_name, key, file_name, file_size, content, failed_parts):
        total = NonlocalObject(0)
        orig_upload_part = tos.checkpoint._BreakpointUploader._upload_part

        def mock_upload_part(self, part, failed_parts=None):
            if part.part_number in failed_parts:
                raise RuntimeError("Fail upload_part for part: {0}".format(part.part_number))
            else:
                total.var += 1
                orig_upload_part(self, part)

        self._test_resume(tos.checkpoint._BreakpointUploader, '_upload_part', mock_upload_part, bucket_name, key,
                          file_name, file_size, content, failed_parts, 'upload', self.client.upload_file, total)

    def _test_resume(self, class_name, func_name, mock_func, bucket_name, key, file_name, file_size, content,
                     failed_parts, operation_type, api, total):
        bucket = bucket_name

        def percentage(consumed_bytes, total_bytes, rw_once_bytes,
                       type: DataTransferType):
            if total_bytes:
                rate = int(100 * float(consumed_bytes) / float(total_bytes))
                print("rate:{}, consumed_bytes:{},total_bytes{}, rw_once_bytes:{}, type:{}".format(rate, consumed_bytes,
                                                                                                   total_bytes,
                                                                                                   rw_once_bytes, type))

        with patch.object(class_name, func_name,
                          side_effect=partial(mock_func, failed_parts=failed_parts),
                          autospec=True):
            self.assertRaises(RuntimeError, api, bucket, key, file_name, data_transfer_listener=percentage, task_num=3)

        store = CheckPointStore(get_parent_directory_from_File(os.path.abspath(file_name)), file_name,
                                operation_type)
        if 1 not in failed_parts:
            self.assertTrue(os.path.exists(store.path(bucket, key)))
        if operation_type == 'download':
            self.assertTrue(os.path.exists(file_name + '.temp'))

        with patch.object(class_name, func_name,
                          side_effect=partial(mock_func, failed_parts=[]), autospec=True):
            api(bucket, key, file_name, data_transfer_listener=percentage, task_num=3)

        self.assertEqual(total.var, tos.utils.get_number(file_size, 20 * 1024 * 1024))
        self.assertFalse(os.path.exists(file_name + '.temp'))
        self.assertFalse(os.path.exists(store.path(bucket, key)))
        self.assertFileContent(file_name, content)

    def __prepare(self, file_size, suffix=''):
        content = random_bytes(file_size)
        key = self.random_key(suffix)
        filename_upload = self.random_filename()
        filename_download = self.random_filename()
        with open(filename_upload, 'wb+') as f:
            f.write(content)
        return key, content, filename_upload, filename_download


if __name__ == '__main__':
    unittest.main()
