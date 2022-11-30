# -*- coding: utf-8 -*-
import logging
import os
import tempfile
import time
import unittest
from functools import partial
from unittest.mock import patch

import tos
from tests.common import TosTestBase, random_bytes
from tos import DataTransferType
from tos.checkpoint import CancelHook, CheckPointStore
from tos.exceptions import TosClientError
from tos.utils import get_parent_directory_from_File


class NonlocalObject(object):
    def __init__(self, value):
        self.var = value


tos.set_logger(level=logging.INFO)


def upload_event(type, err, bucket, key, upload_id, file_path, checkpoint_file, part):
    print(type, err, bucket, key, upload_id, file_path, checkpoint_file, part)


def download_event(type, err, bucket, key, version_id, file_path, checkpint_file, tmp_file, download_part):
    print(type, err, bucket, key, version_id, file_path, checkpint_file, tmp_file, download_part)


def copy_event(type, err, bucket, key, upload_id, src_bucket, src_key, src_version_id, checkpoint_file,
               copy_part_info):
    print(type, err, bucket, key, upload_id, src_bucket, src_key, src_version_id, checkpoint_file, copy_part_info)


class TestUploadAndDownload(TosTestBase):
    def test_small_file(self):
        bucket_name = self.bucket_name + 'upload-download-small-file'
        self.__test_normal(bucket_name, 1023, upload_event=upload_event, download_event=download_event,
                           copy_event=copy_event)
        bucket_name = self.bucket_name + 'upload-download-small-file2'
        self.__test_normal(bucket_name, 1023)

    def test_large_file_with_single_threaded(self):
        bucket_name = self.bucket_name + 'upload-download-large-file-single-threaded'
        self.__test_normal(bucket_name, 10 * 1024 * 1024 + 3, thread_num=1, upload_event=upload_event,
                           download_event=download_event, copy_event=copy_event)
        bucket_name = self.bucket_name + 'upload-download-small-file2'
        self.__test_normal(bucket_name, 10 * 1024 * 1024 + 3, thread_num=1)

    def test_large_file_with_multi_threaded(self):
        bucket_name = self.bucket_name + 'upload-download-large-file-multi-threaded'
        self.__test_normal(bucket_name, 51 * 1024 * 1023, thread_num=7, upload_event=upload_event,
                           download_event=download_event, copy_event=copy_event)
        bucket_name = self.bucket_name + 'upload-download-small-file2'
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

    def test_copy_part_fail_fist_part(self):
        bucket_name = self.bucket_name + 'download-fail-fist-part'
        src_bucket_name = self.bucket_name + 'download-fail-fist-part-src'
        self.client.create_bucket(bucket_name)
        self.client.create_bucket(src_bucket_name)
        self.bucket_delete.append(bucket_name)
        self.bucket_delete.append(src_bucket_name)
        key, content, filename_upload, filename_download = self.__prepare(40 * 1024 * 1025)
        self.client.put_object_from_file(src_bucket_name, key, filename_upload)
        self.__test_resume_copy(bucket_name, key, src_bucket_name, key, 40 * 1024 * 1025, content, [1])

    def test_copy_part_fail_last_part(self):
        bucket_name = self.bucket_name + 'download-fail-mid-part'
        src_bucket_name = self.bucket_name + 'download-fail-mid-part-src'
        self.client.create_bucket(bucket_name)
        self.client.create_bucket(src_bucket_name)
        self.bucket_delete.append(bucket_name)
        self.bucket_delete.append(src_bucket_name)
        key, content, filename_upload, filename_download = self.__prepare(40 * 1024 * 1025)
        self.client.put_object_from_file(src_bucket_name, key, filename_upload)
        self.__test_resume_copy(bucket_name, key, src_bucket_name, key, 40 * 1024 * 1025, content, [3])

    def test_copy_part_fail_mid_part(self):
        bucket_name = self.bucket_name + 'download-fail-mid-part'
        src_bucket_name = self.bucket_name + 'download-fail-mid-part-src'
        self.client.create_bucket(bucket_name)
        self.client.create_bucket(src_bucket_name)
        self.bucket_delete.append(bucket_name)
        self.bucket_delete.append(src_bucket_name)
        key, content, filename_upload, filename_download = self.__prepare(40 * 1024 * 1025)
        self.client.put_object_from_file(src_bucket_name, key, filename_upload)
        self.__test_resume_copy(bucket_name, key, src_bucket_name, key, 40 * 1024 * 1025, content, [2])

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

    def __test_normal(self, bucket_name, file_size, part_size=5 * 1024 * 1024 + 1, thread_num=3, upload_event=None,
                      download_event=None, copy_event=None):
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
                                task_num=thread_num, upload_event_listener=upload_event)

        self.client.download_file(bucket=bucket_name, key=key, file_path=filename_download, part_size=part_size,
                                  task_num=thread_num, download_event_listener=download_event)

        self.client.resumable_copy_object(bucket_name, 'key2', bucket_name, key, copy_event_listener=copy_event)

        self.assertFileContent(filename_upload, content)
        self.assertFileContent(filename_download, content)
        self.assertObjectContent(bucket_name, 'key2', content)

    def __test_resume_download(self, bucket_name, key, file_name, file_size, content, failed_parts):
        total = NonlocalObject(0)
        orig_download_part = tos.checkpoint._BreakpointDownloader._do_task

        def mock_download_part(self, part, failed_parts=None):
            if part.part_number in failed_parts:
                raise RuntimeError("Fail download_part for part: {0}".format(part.part_number))
            else:
                total.var += 1
                orig_download_part(self, part)

        self._test_resume(tos.checkpoint._BreakpointDownloader, '_do_task', mock_download_part, bucket_name, key,
                          file_name, file_size, content, failed_parts, 'download', self.client.download_file, total)

    def __test_resume_upload(self, bucket_name, key, file_name, file_size, content, failed_parts):
        total = NonlocalObject(0)
        orig_upload_part = tos.checkpoint._BreakpointUploader._do_task

        def mock_upload_part(self, part, failed_parts=None):
            if part.part_number in failed_parts:
                raise RuntimeError("Fail upload_part for part: {0}".format(part.part_number))
            else:
                total.var += 1
                orig_upload_part(self, part)

        self._test_resume(tos.checkpoint._BreakpointUploader, '_do_task', mock_upload_part, bucket_name, key,
                          file_name, file_size, content, failed_parts, 'upload', self.client.upload_file, total)

    def __test_resume_copy(self, bucket_name, key, src_bucket, src_key, file_size, content, failed_parts):
        total = NonlocalObject(0)
        orig_copy_part = tos.checkpoint._BreakpointResumableCopyObject._do_task

        def mock_copy_part(self, part, failed_parts=None):
            if part.part_number in failed_parts:
                raise RuntimeError("Fail copy for part: {0}".format(part.part_number))
            else:
                total.var += 1
                orig_copy_part(self, part)

        def percentage(copy_event_type, err, bucket, key, upload_id, src_bucket, src_key, src_version_id, checkpoint,
                       copy_part):
            print(copy_event_type, err, bucket, key, upload_id, src_bucket, src_key, src_version_id, checkpoint,
                  copy_part)

        with patch.object(tos.checkpoint._BreakpointResumableCopyObject, '_do_task',
                          side_effect=partial(mock_copy_part, failed_parts=failed_parts),
                          autospec=True):
            with self.assertRaises(TosClientError):
                self.client.resumable_copy_object(bucket_name, key, src_bucket, src_key, task_num=3,
                                                  copy_event_listener=percentage)

        store = CheckPointStore(tempfile.gettempdir(), '', 'copy')
        print('checkpoint', store.path(bucket_name, key, src_bucket, src_key))
        self.assertTrue(os.path.exists(store.path(bucket_name, key, src_bucket, src_key)))
        with patch.object(tos.checkpoint._BreakpointResumableCopyObject, '_do_task',
                          side_effect=partial(mock_copy_part, failed_parts=[]), autospec=True):
            self.client.resumable_copy_object(bucket_name, key, src_bucket, src_key, copy_event_listener=percentage,
                                              task_num=3)

        self.assertEqual(total.var, tos.utils.get_number(file_size, 20 * 1024 * 1024))
        self.assertFalse(os.path.exists(store.path(bucket_name, key, src_bucket=src_bucket, src_key=src_key)))
        self.assertObjectContent(bucket_name, key, content)

    def _test_resume(self, class_name, func_name, mock_func, bucket_name, key, file_name, file_size, content,
                     failed_parts, operation_type, api, total, src_bucket=None, src_key=None):
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
            if src_bucket is None:
                self.assertRaises(TosClientError, api, bucket, key, file_name, data_transfer_listener=percentage,
                                  task_num=3)
            else:
                self.assertRaises(TosClientError, api, bucket, key, src_bucket, src_key, copy_event_listener=percentage,
                                  task_num=3)

        store = CheckPointStore(get_parent_directory_from_File(os.path.abspath(file_name)), file_name,
                                operation_type)
        if 1 not in failed_parts:
            self.assertTrue(os.path.exists(store.path(bucket, key)))
        if operation_type == 'download':
            self.assertTrue(os.path.exists(file_name + '.temp'))

        with patch.object(class_name, func_name,
                          side_effect=partial(mock_func, failed_parts=[]), autospec=True):
            if src_bucket is None:
                api(bucket, key, file_name, data_transfer_listener=percentage, task_num=3)
            else:
                api(bucket, key, src_bucket, src_key, copy_event_listener=percentage, task_num=3)

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
