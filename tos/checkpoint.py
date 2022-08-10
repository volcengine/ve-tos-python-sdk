import concurrent.futures
import json
import logging
import os
import threading
from concurrent.futures import as_completed
from typing import Dict

from tos import utils
from tos.enum import DownloadEventType, UploadEventType
from tos.exceptions import (CancelNotWithAbortError, CancelWithAbortError,
                            TosClientError, TosServerError)
from tos.models2 import PartInfo, UploadedPart, _PartToDo
from tos.utils import (SizeAdapter, _cal_download_callback,
                       _cal_upload_callback, to_unicode)

logger = logging.getLogger(__name__)


class CheckPointStore(object):
    """
    checkpoint 相关信息维护类
    创建CheckPointStore对象时，指定目录下创建存储 checkpoint信息的文件目录
    支持 获取指定对象 key 的 checkpoint json 信息
    支持 在指定目录下创建 对象checkpoint 信息
    支持 删除对象的 checkpoint 信息
    """

    def __init__(self, dir, file_name):

        self.dir = dir
        self.file_name = file_name

        if os.path.isdir(self.dir):
            return

        utils.makedir_p(self.dir)

    def get(self, bucket, key):
        pathname = self.path(bucket, key)

        if not os.path.exists(pathname):
            return None

        try:
            with open(to_unicode(pathname), 'r') as f:
                content = json.load(f)
        except ValueError:
            os.remove(pathname)
            return None
        else:
            return content

    def put(self, bucket, key, value):
        pathname = self.path(bucket, key)

        with open(to_unicode(pathname), 'w') as f:
            json.dump(value, f)

    def delete(self, bucket, key):
        pathname = self.path(bucket, key)
        os.remove(pathname)

    def path(self, bucket, key):
        name = "{0}.{1}.{2}.upload".format(self.file_name, bucket, key)
        return os.path.join(self.dir, name)


def _cover_to_uploaded_parts(parts: []) -> list:
    """
    将_PartToProcess 转化为 UploadedPart
    """
    l = []
    for p in parts:
        uploaded_part = UploadedPart(p.part_number, p.etag)
        l.append(uploaded_part)

    return l


class CancelHook(object):
    def __init__(self):
        self._is_cal = False
        self._is_abort = None
        self._lock = threading.Lock()

    def cancel(self, is_abort: bool):
        with self._lock:
            self._is_cal = True
            self._is_abort = is_abort

    def _is_abort_func(self):
        if self._is_cal and self._is_abort:
            return True

    def _is_not_abort_func(self):
        if self._is_cal and not self._is_abort:
            return True

    def is_cancel(self):
        with self._lock:
            if self._is_abort_func():
                raise CancelWithAbortError('user cancel upload file task with abort')
            if self._is_not_abort_func():
                raise CancelNotWithAbortError('user cancel upload file task not with abort')


class _BreakpointUploader(object):
    def __init__(self, client, bucket, key, file_path: str, store: CheckPointStore, task_num: int,
                 parts_to_update, upload_id, record: Dict,
                 datatransfer_listener=None, upload_event_listener=None,
                 rate_limiter=None, cancel_hook=None):

        self.client = client
        self.bucket = bucket
        self.key = key
        self.filename = file_path
        self.task_num = task_num
        self.cancel_hook = cancel_hook
        self.parts_to_update = parts_to_update
        self.upload_id = upload_id

        self.datatransfer_listener = datatransfer_listener
        self.upload_event_listener = upload_event_listener
        self.rate_limiter = rate_limiter

        # 下列变量加锁操作
        self.lock = threading.Lock()
        self.record = record
        self.store = store

        # 获取checkpoint文件 和 执行并发任务时会分别修改它
        self.finished_parts = []
        for p in record["parts_info"]:
            self.finished_parts.append(
                PartInfo(part_number=p['part_number'], part_size=p['part_size'], offset=p['offset'], etag=p['etag'],
                         hash_crc64_ecma=p['hash_crc64ecma'], is_completed=True))

    def upload(self):
        """
        执行分段上传任务
        """
        try:
            q = TaskExecutor(self.task_num, self._upload_part, self.cancel_hook)
            for part in self.parts_to_update:
                q.submit(part)

            q.run()

            # 执行任务
            parts = _cover_to_uploaded_parts(self.finished_parts)

            result = self.client.complete_multipart_upload(self.bucket, self.key, self.upload_id, parts)

            _cal_upload_callback(self.upload_event_listener,
                                 UploadEventType.Upload_Event_Complete_Multipart_Upload_Succeed, None, self.bucket,
                                 self.key,
                                 self.upload_id, self.store.path(self.bucket, self.key), None)

            self.store.delete(self.bucket, self.key)

            return result

        except (TosClientError, TosServerError) as e:

            _cal_upload_callback(self.upload_event_listener,
                                 UploadEventType.Upload_Event_Complete_Multipart_Upload_Failed, e, self.bucket,
                                 self.key,
                                 self.upload_id, self.store.path(self.bucket, self.key), None)

            raise e
        except CancelWithAbortError as e:

            _cal_upload_callback(self.upload_event_listener,
                                 UploadEventType.Upload_Event_UploadPart_Aborted, e, self.bucket, self.key,
                                 self.upload_id, self.store.path(self.bucket, self.key), '')

            self.client.abort_multipart_upload(self.bucket, self.key, self.upload_id)

            with self.lock:
                self.store.delete(self.bucket, self.key)

            raise TosClientError('the task is canceled')
        except CancelNotWithAbortError as e:
            _cal_upload_callback(self.upload_event_listener,
                                 UploadEventType.Upload_Event_UploadPart_Aborted, e, self.bucket, self.key,
                                 self.upload_id, self.store.path(self.bucket, self.key), '')
            raise TosClientError('the task is canceled')

        except Exception as e:
            raise e

    def _upload_part(self, part):
        with open(to_unicode(self.filename), 'rb') as f:
            f.seek(part.start, os.SEEK_SET)
            try:
                result = self.client.upload_part(bucket=self.bucket, key=self.key, upload_id=self.upload_id,
                                                 part_number=part.part_number,
                                                 content=SizeAdapter(f, part.size, init_offset=part.start,
                                                                     can_reset=True),
                                                 data_transfer_listener=self.datatransfer_listener,
                                                 rate_limiter=self.rate_limiter)

            except (TosClientError, TosServerError) as e:

                _cal_upload_callback(self.upload_event_listener,
                                     UploadEventType.Upload_Event_Upload_Part_Failed, e, self.bucket,
                                     self.key, self.upload_id, self.store.path(self.bucket, self.key),
                                     PartInfo(part.part_number, part.size, part.start, None, None, False))
                raise e

            except Exception as e:
                raise e

            self._finish_part(
                PartInfo(part_number=part.part_number, part_size=part.size, offset=part.start, etag=result.etag,
                         hash_crc64_ecma=result.hash_crc64_ecma, is_completed=True))

    def _finish_part(self, part_info):

        _cal_upload_callback(self.upload_event_listener,
                             UploadEventType.Upload_Event_Upload_Part_Succeed, None, self.bucket,
                             self.key, self.upload_id, self.store.path(self.bucket, self.key), part_info)

        with self.lock:
            self.finished_parts.append(part_info)

            self.record["parts_info"].append({"part_number": part_info.part_number, "part_size": part_info.part_size,
                                              "offset": part_info.offset, "etag": part_info.etag,
                                              "hash_crc64ecma": part_info.hash_crc64_ecma, "is_completed": True})

            self.store.put(self.bucket, self.key, self.record)


class _BreakpointDownloader(object):
    def __init__(self, client, bucket, key, file_path: str, store: CheckPointStore, task_num: int,
                 parts_to_download, record: Dict, etag,
                 datatransfer_listener=None, download_event_listener=None,
                 rate_limiter=None, cancel_hook=None, version_id=None):
        self.client = client
        self.bucket = bucket
        self.key = key
        self.etag = etag
        self.version_id = version_id
        self.file_path = file_path
        self.task_num = task_num
        self.datatransfer_listener = datatransfer_listener
        self.download_event_listener = download_event_listener
        self.rate_limiter = rate_limiter
        self.cancel_hook = cancel_hook
        self.parts_to_download = parts_to_download
        self._temp = file_path + '.temp'

        # 下列变量加锁操作
        self.lock = threading.Lock()
        self.record = record
        self.store = store

        self.finished_parts = []

        for p in record["parts_info"]:
            self.finished_parts.append(
                _PartToDo(p["part_number"], p["range_start"], p["range_end"], p["hash_crc64ecma"]))

    def download(self, tos_crc):

        open(self._temp, 'a').close()
        _cal_download_callback(self.download_event_listener,
                               DownloadEventType.Download_Event_Create_TempFile_Succeed, None, self.bucket, self.key,
                               self.version_id,
                               self.file_path, self.store.path(self.bucket, self.key), self._temp, None)

        q = TaskExecutor(self.task_num, self._download_part, self.cancel_hook)

        for part in self.parts_to_download:
            q.submit(part)

        try:
            q.run()

            if self.client.enable_crc:
                parts = sorted(self.finished_parts, key=lambda p: p.part_number)
                download_crc = utils.cal_crc_from_parts(parts)
                utils.check_crc("download_file", download_crc, tos_crc, "")

            utils.rename_file(self._temp, self.file_path)

            self.store.delete(bucket=self.bucket, key=self.key)

            _cal_download_callback(self.download_event_listener,
                                   DownloadEventType.Download_Event_Rename_Temp_File_Succeed,
                                   None, self.bucket, self.key, self.version_id,
                                   self.file_path, self.store.path(self.bucket, self.key), self._temp, None)

        except CancelWithAbortError as e:
            _cal_download_callback(self.download_event_listener,
                                   DownloadEventType.Download_Event_Download_Part_Aborted,
                                   e, self.bucket, self.key, self.version_id,
                                   self.file_path, self.store.path(self.bucket, self.key), self._temp, None)

            # 删除临时文件
            os.remove(self.file_path)

            # 删除checkpoint 文件
            self.store.delete(self.bucket, self.key)

            raise TosClientError('the task is canceled', e)
        except CancelNotWithAbortError as e:
            _cal_download_callback(self.download_event_listener,
                                   DownloadEventType.Download_Event_Download_Part_Aborted,
                                   e, self.bucket, self.key, self.version_id,
                                   self.file_path, self.store.path(self.bucket, self.key), self._temp, None)
            raise TosClientError('the task is canceled', e)

        except OSError as e:
            _cal_download_callback(self.download_event_listener,
                                   DownloadEventType.Download_Event_Rename_Temp_File_Failed,
                                   e, self.bucket, self.key, self.version_id,
                                   self.file_path, self.store.path(self.bucket, self.key), self._temp, None)
        except Exception as e:
            raise e

    def _download_part(self, part):

        with open(self._temp, 'wb') as f:
            try:

                f.seek(part.start, os.SEEK_SET)
                content = self.client.get_object(bucket=self.bucket, key=self.key, range_start=part.start,
                                                 range_end=part.end - 1, if_match=self.etag,
                                                 data_transfer_listener=self.datatransfer_listener,
                                                 rate_limiter=self.rate_limiter)
                utils.copy_and_verify_length(content, f, part.end - part.start, request_id=content.request_id)
                if self.client.enable_crc:
                    part.part_crc = content.content.crc

            except (TosClientError, TosServerError) as e:
                _cal_download_callback(self.download_event_listener,
                                       DownloadEventType.Download_Event_Download_Part_Failed,
                                       e, self.bucket, self.key, self.version_id,
                                       self.file_path, self.store.path(self.bucket, self.key), self._temp, part)
                raise e

            self._finish_part(part)

    def _finish_part(self, part):
        _cal_download_callback(self.download_event_listener, DownloadEventType.Download_Event_Download_Part_Succeed,
                               None, self.bucket, self.key, self.version_id,
                               self.file_path, self.store.path(self.bucket, self.key), self._temp, part)
        with self.lock:
            self.finished_parts.append(part)
            self.record['parts_info'].append(
                {"part_number": part.part_number, "range_start": part.start, "range_end": part.end,
                 "hash_crc64ecma": part.part_crc, "is_completed": True})
            self.store.put(bucket=self.bucket, key=self.key, value=self.record)


class TaskExecutor(object):
    def __init__(self, num_task, task_fun, cancel_hook: CancelHook):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=num_task)
        self.task_fun = task_fun
        self.tasks = []
        self.cancel_hook = cancel_hook
        self._futures = []
        self._exc = None

    def submit(self, *args):
        future = self.executor.submit(self.task_fun, *args)
        self._futures.append(future)

    def run(self):
        try:
            # 运行前判定cancel
            if self.cancel_hook:
                self.cancel_hook.is_cancel()
            for future in as_completed(self._futures):
                e = future.exception()
                # 运行中判定cancel
                if self.cancel_hook:
                    self.cancel_hook.is_cancel()

                if isinstance(e, TosServerError):
                    self._exc = e
                    if _need_shutdown(e.status_code):
                        break
                if e:
                    self._exc = e
                    break

            for future in self._futures:
                future.cancel()
            self.executor.shutdown(wait=True)
            if self._exc:
                raise self._exc
        finally:
            for future in self._futures:
                future.cancel()
            self.executor.shutdown(wait=True)


def _need_shutdown(code):
    if code in [403, 404, 405]:
        return True
    return False
