import concurrent.futures
import hashlib
import json
import logging
import os
import threading
import urllib.parse
from concurrent.futures import as_completed
from typing import Dict

from .enum import DownloadEventType, UploadEventType, CopyEventType
from .exceptions import (CancelNotWithAbortError, CancelWithAbortError,
                         TosClientError, TosServerError, TosError, TaskCompleteMultipartError, RenameFileError)
from .models2 import PartInfo, UploadedPart, _PartToDo, CopyPartInfo
from .utils import (SizeAdapter, to_unicode, MergeProcess, to_bytes,
                    cal_crc_from_download_parts, check_crc, rename_file, copy_and_verify_length, makedir_p,
                    cal_crc_from_upload_parts)

logger = logging.getLogger(__name__)


class CheckPointStore(object):
    """
    checkpoint 相关信息维护类
    创建CheckPointStore对象时，指定目录下创建存储 checkpoint信息的文件目录
    支持 获取指定对象 key 的 checkpoint json 信息
    支持 在指定目录下创建 对象checkpoint 信息
    支持 删除对象的 checkpoint 信息
    """

    def __init__(self, dir, file_name, use_type: str):

        self.dir = dir
        self.file_name = file_name
        self.suffix = use_type

        if os.path.isdir(self.dir):
            return

        makedir_p(self.dir)

    def get(self, bucket, key, src_bucket=None, src_key=None, version_id=None):
        pathname = self.path(bucket, key, src_bucket=src_bucket, src_key=src_key, versionId=version_id)

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

    def put(self, bucket, key, value, src_bucket=None, src_key=None, version_id=None):
        pathname = self.path(bucket, key, src_bucket, src_key, version_id)

        with open(to_unicode(pathname), 'w') as f:
            json.dump(value, f)

    def delete(self, bucket, key, src_bucket=None, src_key=None, version_id=None):
        pathname = self.path(bucket, key, src_bucket=src_bucket, src_key=src_key, versionId=version_id)
        try:
            os.remove(pathname)
        except Exception:
            return

    def path(self, bucket, key, src_bucket=None, src_key=None, versionId=None):
        encode_str = ''
        if src_bucket and src_key:
            encode_str += src_bucket + '.' + src_key
            if versionId:
                encode_str += '.' + versionId
            encode_str += '.' + bucket + '.' + key
        else:
            encode_str += bucket + '.' + key
            if versionId:
                encode_str += '.' + versionId
        encoding_data = urllib.parse.quote(hashlib.md5(to_bytes(self.file_name + encode_str)).digest(), safe='')

        name = "{0}.{1}".format(encoding_data, self.suffix)
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


class BreakpointBase(object):
    def __init__(self, client, bucket, key, store: CheckPointStore, task_num,
                 parts_to_do, record: Dict,
                 size, rate_limiter, cancel_hook,
                 datatransfer_listener, event_listener):
        self.client = client
        self.bucket = bucket
        self.key = key
        self.task_num = task_num
        self.parts_to_do = parts_to_do
        self.record = record
        self.size = size
        self.cancel_hook = cancel_hook
        self.datatransfer_listener = datatransfer_listener
        self.event_listener = event_listener
        self.rate_limiter = rate_limiter
        self.need_bytes = 0
        for part in parts_to_do:
            self.need_bytes += part.size

        if self.datatransfer_listener:
            self.datatransfer_listener = MergeProcess(self.datatransfer_listener, size,
                                                      len(self.parts_to_do), size - self.need_bytes)
        # 下列变量加锁操作
        self.lock = threading.Lock()
        self.record = record
        self.store = store

        # 不同实现
        self.finished_parts = []

    def execute(self, **kwargs):
        try:
            self._cover_to_finished_parts()
            self._pre_task()
            q = TaskExecutor(self.task_num, self._do_task, self.cancel_hook)
            for part in self.parts_to_do:
                q.submit(part)

            q.run()
            # 执行任务
            result = self._last_task(**kwargs)
            self._delete_checkpoint()
            self._callback_success()
            return result

        except TaskCompleteMultipartError as e:
            self._callback_fail(e)
            raise TosClientError(e.message, e)
        except CancelWithAbortError as e:
            self._callback_abort(e)
            self._abort_task()
            self._delete_checkpoint()
            raise TosClientError('the task is canceled')
        except CancelNotWithAbortError as e:
            self._callback_abort(e)
            raise TosClientError('the task is canceled')
        except RenameFileError as e:
            self._callback_rename_fail(e)
            raise TosClientError(e.message, e)
        except TosError as e:
            raise e
        except Exception as e:
            raise TosClientError('unknown err', e)

    def _cover_to_finished_parts(self):
        pass

    def _delete_checkpoint(self):
        with self.lock:
            self.store.delete(self.bucket, self.key)

    def _pre_task(self):
        pass

    def _do_task(self, part):
        pass

    def _last_task(self, **args):
        pass

    def _abort_task(self, *args):
        pass

    def _callback_success(self):
        pass

    def _callback_fail(self, e):
        pass

    def _callback_part_fail(self, e, part):
        pass

    def _callback_part_success(self, part_info):
        pass

    def _callback_rename_fail(self, e):
        pass

    def _callback_abort(self, e):
        pass

    def _finish_part(self, part_info):
        pass


class _BreakpointUploader(BreakpointBase):
    def __init__(self, client, bucket, key, store: CheckPointStore, task_num,
                 parts_to_update, upload_id, record: Dict,
                 size, ssec_algorithm, ssec_key, ssec_key_md5, rate_limiter, cancel_hook,
                 datatransfer_listener, upload_event_listener,
                 file_path):

        super(_BreakpointUploader, self).__init__(client=client, bucket=bucket, key=key, store=store, task_num=task_num,
                                                  parts_to_do=parts_to_update, record=record, size=size,
                                                  rate_limiter=rate_limiter, cancel_hook=cancel_hook,
                                                  datatransfer_listener=datatransfer_listener,
                                                  event_listener=upload_event_listener)
        self.filename = file_path
        self.task_num = task_num
        self.upload_id = upload_id
        self.cancel_hook = cancel_hook
        self.ssec_algorithm = ssec_algorithm
        self.ssec_key = ssec_key
        self.ssec_key_md5 = ssec_key_md5

    def _cover_to_finished_parts(self):
        for p in self.record["parts_info"]:
            self.finished_parts.append(
                PartInfo(part_number=p['part_number'], part_size=p['part_size'], offset=p['offset'], etag=p['etag'],
                         hash_crc64_ecma=p['hash_crc64ecma'], is_completed=True))

    def _do_task(self, part):
        with open(to_unicode(self.filename), 'rb') as f:
            f.seek(part.start, os.SEEK_SET)
            try:
                result = self.client.upload_part(bucket=self.bucket, key=self.key, upload_id=self.upload_id,
                                                 part_number=part.part_number,
                                                 content=SizeAdapter(f, part.size, init_offset=part.start,
                                                                     can_reset=True),
                                                 data_transfer_listener=self.datatransfer_listener,
                                                 rate_limiter=self.rate_limiter,
                                                 ssec_algorithm=self.ssec_algorithm,
                                                 ssec_key=self.ssec_key,
                                                 ssec_key_md5=self.ssec_key_md5)
            except Exception as e:
                self._callback_part_fail(e, part)
                raise e

            self._finish_part(
                PartInfo(part_number=part.part_number, part_size=part.size, offset=part.start, etag=result.etag,
                         hash_crc64_ecma=result.hash_crc64_ecma, is_completed=True))

    def _abort_task(self):
        self.client.abort_multipart_upload(self.bucket, self.key, self.upload_id)

    def _delete_checkpoint(self):
        self.store.delete(self.bucket, self.key)

    def _last_task(self):
        try:
            parts = _cover_to_uploaded_parts(self.finished_parts)
            result = self.client.complete_multipart_upload(self.bucket, self.key, self.upload_id, parts=parts)
            if self.client.enable_crc:
                parts = sorted(self.finished_parts, key=lambda p: p.part_number)
                download_crc = cal_crc_from_upload_parts(parts)
                check_crc("upload_file", download_crc, result.hash_crc64_ecma, result.request_id)
            return result
        except Exception as e:
            raise TaskCompleteMultipartError(e)

    def _finish_part(self, part_info):
        self._callback_part_success(part_info)
        with self.lock:
            self.finished_parts.append(part_info)
            self.record["parts_info"].append({"part_number": part_info.part_number, "part_size": part_info.part_size,
                                              "offset": part_info.offset, "etag": part_info.etag,
                                              "hash_crc64ecma": part_info.hash_crc64_ecma, "is_completed": True})
            self.store.put(self.bucket, self.key, self.record)

    def _callback_success(self):
        self.event_listener(UploadEventType.Upload_Event_Complete_Multipart_Upload_Succeed)

    def _callback_fail(self, e):
        self.event_listener(UploadEventType.Upload_Event_Complete_Multipart_Upload_Failed, e)

    def _callback_part_success(self, part_info):
        self.event_listener(UploadEventType.Upload_Event_Upload_Part_Succeed, part_info=part_info)

    def _callback_part_fail(self, e, part):
        self.event_listener(UploadEventType.Upload_Event_Upload_Part_Failed, e)

    def _callback_abort(self, e):
        self.event_listener(UploadEventType.Upload_Event_UploadPart_Aborted, e)


class _BreakpointResumableCopyObject(BreakpointBase):
    def __init__(self, client, bucket, key, store: CheckPointStore, task_num,
                 parts_to_update, upload_id, record: Dict,
                 size, ssec_algorithm, ssec_key, ssec_key_md5, rate_limiter, cancel_hook,
                 datatransfer_listener, upload_event_listener,
                 src_bucket, src_object,
                 copy_source_if_match, copy_source_if_modified_since,
                 copy_source_if_none_match, copy_source_if_unmodified_since, src_version_id,
                 copy_source_ssec_algorithm, copy_source_ssec_key, copy_source_ssec_key_md5):
        super(_BreakpointResumableCopyObject, self).__init__(client=client, bucket=bucket, key=key, store=store,
                                                             task_num=task_num,
                                                             parts_to_do=parts_to_update, record=record, size=size,
                                                             rate_limiter=rate_limiter, cancel_hook=cancel_hook,
                                                             datatransfer_listener=datatransfer_listener,
                                                             event_listener=upload_event_listener)
        self.upload_id = upload_id
        self.src_version_id = src_version_id
        self.ssec_algorithm = ssec_algorithm
        self.ssec_key = ssec_key
        self.ssec_key_md5 = ssec_key_md5
        self.src_bucket = src_bucket
        self.src_object = src_object
        self.copy_source_if_match = copy_source_if_match
        self.copy_source_if_modified_since = copy_source_if_modified_since
        self.copy_source_if_none_match = copy_source_if_none_match
        self.copy_source_if_unmodified_since = copy_source_if_unmodified_since
        self.copy_source_ssec_algorithm = copy_source_ssec_algorithm
        self.copy_source_ssec_key = copy_source_ssec_key
        self.copy_source_ssec_key_md5 = copy_source_ssec_key_md5

    def _cover_to_finished_parts(self):
        for p in self.record["parts_info"]:
            self.finished_parts.append(
                PartInfo(part_number=p['part_number'], part_size=p['part_size'], offset=p['offset'], etag=p['etag'],
                         hash_crc64_ecma=p['hash_crc64ecma'], is_completed=True))

    def _do_task(self, part):
        try:
            result = self.client.upload_part_copy(self.bucket, self.key, self.upload_id, part.part_number,
                                                  self.src_bucket, self.src_object,
                                                  src_version_id=self.src_version_id,
                                                  copy_source_range_start=part.start,
                                                  # 由于拷贝为闭区间，因此end -1
                                                  copy_source_range_end=part.start + part.size - 1,
                                                  copy_source_if_match=self.copy_source_if_match,
                                                  copy_source_ssec_key=self.copy_source_ssec_key,
                                                  copy_source_ssec_algorithm=self.copy_source_ssec_algorithm,
                                                  copy_source_ssec_key_md5=self.copy_source_ssec_key_md5,
                                                  ssec_key=self.ssec_key,
                                                  ssec_algorithm=self.ssec_algorithm,
                                                  ssec_key_md5=self.ssec_key_md5)
        except Exception as e:
            self._callback_part_fail(e, part)
            raise e
        self._finish_part(
            PartInfo(part_number=part.part_number, part_size=part.size, offset=part.start, etag=result.etag,
                     hash_crc64_ecma=result.etag, is_completed=True))

    def _delete_checkpoint(self):
        with self.lock:
            self.store.delete(self.bucket, self.key, self.src_bucket, self.src_object, self.src_version_id)

    def _last_task(self, **kwargs):
        try:
            parts = _cover_to_uploaded_parts(self.finished_parts)
            result = self.client.complete_multipart_upload(self.bucket, self.key, self.upload_id, parts=parts)
            return result
        except Exception as e:
            raise TaskCompleteMultipartError(e)

    def _abort_task(self):
        self.client.abort_multipart_upload(self.bucket, self.key, self.upload_id)

    def _finish_part(self, part_info):
        self._callback_part_success(part_info)
        with self.lock:
            self.finished_parts.append(part_info)
            self.record["parts_info"].append({"part_number": part_info.part_number, "part_size": part_info.part_size,
                                              "offset": part_info.offset, "etag": part_info.etag,
                                              "hash_crc64ecma": part_info.hash_crc64_ecma, "is_completed": True})
            self.store.put(self.bucket, self.key, self.record, src_bucket=self.src_bucket, src_key=self.src_object,
                           version_id=self.src_version_id)

    def _callback_success(self):
        self.event_listener(CopyEventType.Copy_Event_Completed_Multipart_Upload_Succeed)

    def _callback_fail(self, e):
        self.event_listener(CopyEventType.Copy_Event_Completed_Multipart_Upload_Failed, e)

    def _callback_part_success(self, part_info):
        self.event_listener(CopyEventType.Copy_Event_Create_Part_Copy_Succeed,
                            part_info=CopyPartInfo(part_info.part_number,
                                                   part_info.offset,
                                                   part_info.offset + part_info.part_size - 1,
                                                   part_info.etag))

    def _callback_part_fail(self, e, part_info):
        self.event_listener(CopyEventType.Copy_Event_Create_Part_Copy_Failed, e,
                            CopyPartInfo(part_info.part_number,
                                         part_info.start,
                                         part_info.start + part_info.size - 1))

    def _callback_abort(self, e):
        self.event_listener(CopyEventType.Copy_Event_Create_Part_Copy_Aborted, e)


class _BreakpointDownloader(BreakpointBase):
    def __init__(self, client, bucket, key, file_path: str, store: CheckPointStore, task_num: int,
                 parts_to_download, record: Dict, etag,
                 datatransfer_listener, download_event_listener,
                 rate_limiter, cancel_hook, version_id, size,
                 ssec_algorithm, ssec_key, ssec_key_md5):
        super(_BreakpointDownloader, self).__init__(client=client, bucket=bucket, key=key, store=store,
                                                    task_num=task_num,
                                                    parts_to_do=parts_to_download, record=record, size=size,
                                                    rate_limiter=rate_limiter, cancel_hook=cancel_hook,
                                                    datatransfer_listener=datatransfer_listener,
                                                    event_listener=download_event_listener)
        self.etag = etag
        self.version_id = version_id
        self.file_path = file_path
        self.rate_limiter = rate_limiter
        self.ssec_algorithm = ssec_algorithm
        self.ssec_key = ssec_key
        self.ssec_key_md5 = ssec_key_md5
        self.temp = file_path + '.temp'

    def _finish_part(self, part):
        self._callback_part_success(part)
        with self.lock:
            self.finished_parts.append(part)
            self.record['parts_info'].append(
                {"part_number": part.part_number, "range_start": part.start, "range_end": part.end,
                 "hash_crc64ecma": part.part_crc, "is_completed": True})
            self.store.put(bucket=self.bucket, key=self.key, value=self.record, version_id=self.version_id)

    def _cover_to_finished_parts(self):
        self.finished_parts = []
        for p in self.record["parts_info"]:
            self.finished_parts.append(
                _PartToDo(p["part_number"], p["range_start"], p["range_end"], p["hash_crc64ecma"]))

    def _do_task(self, part):
        with open(self.temp, 'rb+') as f:
            try:
                f.seek(part.start, os.SEEK_SET)
                content = self.client.get_object(bucket=self.bucket, key=self.key, range_start=part.start,
                                                 range_end=part.end - 1, if_match=self.etag,
                                                 data_transfer_listener=self.datatransfer_listener,
                                                 rate_limiter=self.rate_limiter,
                                                 ssec_algorithm=self.ssec_algorithm,
                                                 ssec_key=self.ssec_key,
                                                 ssec_key_md5=self.ssec_key_md5,
                                                 version_id=self.version_id)
                copy_and_verify_length(content, f, part.end - part.start, request_id=content.request_id)
                if self.client.enable_crc:
                    part.part_crc = content.content.crc
            except Exception as e:
                self._callback_part_fail(e, part)
                raise e
            self._finish_part(part)

    def _pre_task(self):
        try:
            open(self.temp, 'a').close()
            self.event_listener(DownloadEventType.Download_Event_Create_TempFile_Succeed)
        except Exception as e:
            self.event_listener(DownloadEventType.Download_Event_Create_Temp_File_Failed, e)
            raise e

    def _delete_checkpoint(self):
        self.store.delete(bucket=self.bucket, key=self.key, version_id=self.version_id)

    def _last_task(self, **kwargs):
        try:
            tos_crc = kwargs.get('tos_crc')
            if self.client.enable_crc:
                parts = sorted(self.finished_parts, key=lambda p: p.part_number)
                download_crc = cal_crc_from_download_parts(parts)
                check_crc("download_file", download_crc, tos_crc, "")

            rename_file(self.temp, self.file_path)
        except Exception as e:
            raise RenameFileError(e)

    def _abort_task(self):
        # 删除临时文件
        os.remove(self.file_path)

    def _callback_success(self):
        self.event_listener(DownloadEventType.Download_Event_Rename_Temp_File_Succeed)

    def _callback_fail(self, e):
        self.event_listener(DownloadEventType.Download_Event_Rename_Temp_File_Failed, e)

    def _callback_abort(self, e):
        self.event_listener(DownloadEventType.Download_Event_Download_Part_Aborted, e)

    def _callback_rename_fail(self, e):
        self.event_listener(DownloadEventType.Download_Event_Rename_Temp_File_Failed, e)

    def _callback_part_success(self, part_info):
        self.event_listener(DownloadEventType.Download_Event_Download_Part_Succeed, part_info=part_info)

    def _callback_part_fail(self, e, part):
        self.event_listener(DownloadEventType.Download_Event_Download_Part_Failed, e, part)


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
                # 若为 TosServerError
                if isinstance(e, TosServerError):
                    self._exc = e
                    if _need_shutdown(e.status_code):
                        break
                # 其余异常直接抛出
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
    return code in [403, 404, 405]
