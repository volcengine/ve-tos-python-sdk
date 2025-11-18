import json
import urllib.parse
from datetime import datetime
from typing import List, Any, Optional
from typing import Dict

from . import utils
from .enum import CannedType, DataType, DistanceMetricType, GranteeType, PermissionType, StorageClassType, RedirectType, StatusType, \
    StorageClassInheritDirectiveType, VersioningStatusType, ProtocolType, CertStatus, AzRedundancyType, convert_data_type, convert_distance_metric_type, \
    convert_storage_class_type, convert_az_redundancy_type, convert_permission_type, convert_grantee_type, \
    convert_canned_type, convert_redirect_type, convert_status_type, convert_versioning_status_type, \
    convert_protocol_type, convert_cert_status, TierType, convert_tier_type, ACLType, convert_replication_status_type,\
    InventoryFormatType,InventoryFrequencyType,QueryOrderType,QueryOperationType,AggregationOperationType,\
    ReplicationStatusType,InventoryIncludedObjType,SemanticQueryType
from .consts import CHUNK_SIZE, BUCKET_TYPE_HNS, BUCKET_TYPE_FNS
from .exceptions import TosClientError, make_server_error_with_exception
from .models import CommonPrefixInfo, DeleteMarkerInfo
from .utils import (get_etag, get_value, meta_header_decode,
                    parse_gmt_time_to_utc_datetime,
                    parse_modify_time_to_utc_datetime, _param_to_quoted_query, _make_virtual_host_url,
                    convert_meta,parse_iso_time_to_utc_datetime)


class ResponseInfo(object):
    def __init__(self, resp):
        self.resp = resp
        self.request_id = resp.request_id
        self.id2 = get_value(resp.headers, "x-tos-id-2")
        self.status_code = resp.status
        self.header = resp.headers


class CreateBucketOutput(ResponseInfo):
    def __init__(self, resp):
        super(CreateBucketOutput, self).__init__(resp)
        self.location = get_value(self.header, "Location")
        bucket_type = get_value(self.header, "x-tos-bucket-type")
        self.bucket_type = BUCKET_TYPE_FNS if bucket_type is None else bucket_type


class HeadBucketOutput(ResponseInfo):
    def __init__(self, resp):
        super(HeadBucketOutput, self).__init__(resp)
        self.region = get_value(self.header, "x-tos-bucket-region")
        self.storage_class = get_value(self.header, "x-tos-storage-class", lambda x: convert_storage_class_type(x))
        self.az_redundancy = get_value(self.header, "x-tos-az-redundancy", lambda x: convert_az_redundancy_type(x))
        self.project_name = get_value(self.header, "x-tos-project-name")
        bucket_type = get_value(self.header, "x-tos-bucket-type")
        self.bucket_type = BUCKET_TYPE_FNS if bucket_type is None else bucket_type


class FileStatusOutput(ResponseInfo):
    def __init__(self, key, bucket_type, resp):
        super(FileStatusOutput, self).__init__(resp)
        if bucket_type == BUCKET_TYPE_HNS:
            self.key = key
            self.size = get_value(resp.headers, 'Content-Length')
            self.last_modified = get_value(resp.headers, 'Last-Modified')
            self.crc64 = get_value(resp.headers, 'x-tos-hash-crc64ecma')
            self.crc32 = get_value(resp.headers, 'x-tos-hash-crc32c')
            return
        data = json.loads(resp.read())
        self.key = get_value(data, 'Key')
        self.size = get_value(data, 'Size')
        self.last_modified = get_value(data, 'LastModified')
        self.crc32 = get_value(data, 'CRC32')
        self.crc64 = get_value(data, 'CRC64')


class DeleteBucketOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketOutput, self).__init__(resp)


class ListedBucket(object):
    def __init__(self, name: str, location: str, creation_date: str, extranet_endpoint: str, intranet_endpoint: str,
                 project_name: str = None, bucket_type: str = None):
        self.name = name
        self.location = location
        self.creation_date = creation_date
        self.extranet_endpoint = extranet_endpoint
        self.intranet_endpoint = intranet_endpoint
        self.project_name = project_name
        self.bucket_type = bucket_type

    def __str__(self):
        info = {'name': self.name, 'location': self.location, 'creation_date': self.creation_date,
                'extranet_endpoint': self.extranet_endpoint, 'intranet_endpoint': self.intranet_endpoint}

        return str(info)


class Owner(object):
    def __init__(self, id: str, display_name: str):
        self.id = id
        self.display_name = display_name

    def __str__(self):
        info = {'id': self.id, 'display_name': self.display_name}
        return str(info)


class ListBucketsOutput(ResponseInfo):
    def __init__(self, resp):
        super(ListBucketsOutput, self).__init__(resp)
        self.buckets = []  # ListedBucket
        self.owner = None  # Owner
        data = resp.json_read()
        self.owner = Owner(
            get_value(data['Owner'], 'ID'),
            get_value(data['Owner'], 'Name'),
        )

        bkt_list = get_value(data, 'Buckets') or []
        for bkt in bkt_list:
            self.buckets.append(ListedBucket(
                get_value(bkt, 'Name'),
                get_value(bkt, 'Location'),
                get_value(bkt, 'CreationDate'),
                get_value(bkt, 'ExtranetEndpoint'),
                get_value(bkt, 'IntranetEndpoint'),
                get_value(bkt, 'ProjectName'),
                get_value(bkt, 'BucketType')
            ))

class ImageInfo:
    def __init__(self, img_format, width, height, quality, ave, orientation, frame_count):
        self.ImgFormat = img_format
        self.Width = width
        self.Height = height
        self.Quality = quality
        self.Ave = ave
        self.Orientation = orientation
        self.FrameCount = frame_count


class OriginalInfo:
    def __init__(self, bucket, key, image_info=None, etag=None):
        self.Bucket = bucket
        self.Key = key
        self.ImageInfo = image_info  # 应为ImageInfo实例或None
        self.ETag = etag


class ProcessInfo:
    def __init__(self, bucket, key, image_info=None):
        self.Bucket = bucket
        self.Key = key
        self.ImageInfo = image_info  # 应为ImageInfo实例或None


class ProcessResults:
    def __init__(self, objects=None):
        self.Objects = objects if objects is not None else []  # 默认为空列表

class ImageOperationsResult:
    def __init__(self, original_info=None, process_results=None):
        self.OriginalInfo = original_info  # 应为OriginalInfo实例或None
        self.ProcessResults = process_results  # 应为ProcessResults实例或None


def parse_image_info(image_info_json):
    if not image_info_json:
        return None
    return ImageInfo(
        img_format=image_info_json.get('Format'),
        width=get_value(image_info_json, 'Width',lambda x: int(x)),
        height=get_value(image_info_json, 'Height',lambda x: int(x)),
        quality=get_value(image_info_json, 'Quality',lambda x: int(x)),
        ave=image_info_json.get('Ave'),
        orientation=get_value(image_info_json, 'Orientation',lambda x: int(x)),
        frame_count=get_value(image_info_json, 'FrameCount',lambda x: int(x)),
    )


def parse_original_info(original_info_json):
    if not original_info_json:
        return None
    return OriginalInfo(
        bucket=original_info_json.get('Bucket'),
        key=original_info_json.get('Key'),
        image_info=parse_image_info(original_info_json.get('ImageInfo')),
        etag=original_info_json.get('ETag')
    )


def parse_process_info(process_info_json):
    if not process_info_json:
        return None
    return ProcessInfo(
        bucket=process_info_json.get('Bucket'),
        key=process_info_json.get('Key'),
        image_info=parse_image_info(process_info_json.get('ImageInfo'))
    )


def parse_process_results(process_results_json):
    if not process_results_json:
        return None
    # 解析Objects列表
    objects = []
    for obj_json in process_results_json.get('Objects', []):
        obj = parse_process_info(obj_json)
        if obj:
            objects.append(obj)
    return ProcessResults(objects=objects)


def get_image_operations_result(resp):
    data = resp.json_read()

    original_info = parse_original_info(data.get('OriginalInfo'))
    process_results = parse_process_results(data.get('ProcessResults'))

    return ImageOperationsResult(original_info=original_info, process_results=process_results)

class PutObjectOutput(ResponseInfo):
    def __init__(self, resp, callback=None,image_operation=None):
        super(PutObjectOutput, self).__init__(resp)
        self.request_info = resp
        self.etag = get_etag(resp.headers)
        self.ssec_algorithm = get_value(resp.headers, "x-tos-server-side-encryption-customer-algorithm")
        self.ssec_key_md5 = get_value(resp.headers, "x-tos-server-side-encryption-customer-key-md5")
        self.version_id = get_value(resp.headers, "x-tos-version-id")
        self.hash_crc64_ecma = get_value(resp.headers, "x-tos-hash-crc64ecma", lambda x: int(x))
        if callback:
            self.callback_result = resp.read().decode("utf-8")
        elif image_operation:
            self.ImageOperationsResult = get_image_operations_result(resp)


class CopyObjectOutput(ResponseInfo):
    def __init__(self, resp):
        super(CopyObjectOutput, self).__init__(resp)
        self.copy_source_version_id = get_value(resp.headers, "x-tos-copy-source-version-id")
        self.version_id = get_value(resp.headers, "x-tos-version-id")

        data = resp.json_read()
        self.etag = get_etag(data)
        self.last_modified = get_value(data, 'LastModified')
        if self.last_modified:
            self.last_modified = parse_modify_time_to_utc_datetime(self.last_modified)

        if not self.etag:
            make_server_error_with_exception(resp, data)


class DeleteObjectOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteObjectOutput, self).__init__(resp)
        self.version_id = get_value(resp.headers, 'x-tos-version-id')
        self.delete_marker = get_value(resp.headers, 'x-tos-delete-marker', bool)


class Deleted(object):
    def __init__(self, key: str, version_id: str = None, delete_marker=None,
                 delete_marker_version_id: str = None):
        self.key = key
        self.version_id = version_id
        self.delete_marker = delete_marker
        self.delete_marker_version_id = delete_marker_version_id


class ObjectTobeDeleted(object):
    def __init__(self, key: str, version_id: str = None):
        self.key = key
        self.version_id = version_id


class DeleteError(object):
    def __init__(self, key: str, version_id: str, code: str, message: str):
        self.key = key
        self.version_id = version_id
        self.code = code
        self.message = message


class DeleteObjectsOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteObjectsOutput, self).__init__(resp)
        self.deleted = []  # Deleted
        self.error = []  # DeleteError

        data = resp.json_read()

        delete_list = get_value(data, 'Deleted') or []
        for delete in delete_list:
            self.deleted.append(Deleted(
                get_value(delete, "Key"),
                get_value(delete, "VersionId"),
                get_value(delete, "DeleteMarker"),
                get_value(delete, "DeleteMarkerVersionId")
            ))
        err_list = get_value(data, 'Error') or []
        for err in err_list:
            self.error.append(DeleteError(
                get_value(err, "Key"),
                get_value(err, "VersionId"),
                get_value(err, "Code"),
                get_value(err, "Message"),
            ))


class Grantee(object):
    def __init__(self, type: GranteeType, id: str = None, display_name: str = None, canned: CannedType = None):
        self.type = type
        self.display_name = display_name
        self.id = id
        self.canned = canned

    def __str__(self):
        info = {'type': self.type, 'display_name': self.display_name, 'id': self.id, 'canned': self.canned}
        return str(info)


class Grant(object):
    def __init__(self, grantee: Grantee, permission: PermissionType):
        self.grantee = grantee
        self.permission = permission


class HeadObjectOutput(ResponseInfo):
    def __init__(self, resp, disable_encoding_meta: bool = None):
        super(HeadObjectOutput, self).__init__(resp)
        self.etag = get_etag(resp.headers)
        self.version_id = get_value(resp.headers, "x-tos-version-id")
        self.sse_algorithm = get_value(resp.headers, "x-tos-server-side-encryption-customer-algorithm")
        self.sse_key_md5 = get_value(resp.headers, "x-tos-server-side-encryption-customer-key-MD5")
        self.website_redirect_location = get_value(resp.headers, "x-tos-website-redirect-location")
        self.hash_crc64_ecma = get_value(resp.headers, "x-tos-hash-crc64ecma", lambda x: int(x))
        self.storage_class = get_value(resp.headers, "x-tos-storage-class", lambda x: convert_storage_class_type(x))
        self.restore = get_value(resp.headers, "x-tos-restore")
        self.restore_expiry_days = get_value(resp.headers, "x-tos-restore-expiry-days", lambda x: int(x))
        self.restore_tier = get_value(resp.headers, "x-tos-restore-tier", lambda x: convert_tier_type(x))
        self.tagging_count = get_value(resp.headers, "x-tos-tagging-count",lambda x: int(x))

        self.object_type = get_value(resp.headers, "x-tos-object-type")
        self.symlink_target_size = get_value(resp.headers, "x-tos-symlink-target-size", lambda x: int(x))
        if not self.object_type:
            self.object_type = "Normal"
        self.meta = {}
        for k in resp.headers:
            if k.startswith('x-tos-meta-'):
                self.meta[k[11:]] = resp.headers[k]
        if not disable_encoding_meta:
            self.meta = meta_header_decode(self.meta)

        self.last_modified = get_value(resp.headers, 'last-modified')
        if self.last_modified:
            self.last_modified = parse_gmt_time_to_utc_datetime(self.last_modified)
        self.expires = get_value(resp.headers, 'expires')
        if self.expires:
            self.expires = parse_gmt_time_to_utc_datetime(self.expires)

        if get_value(resp.headers, 'x-tos-delete-marker'):
            self.delete_marker = True
        else:
            self.delete_marker = False

        self.content_type = get_value(resp.headers, "content-type")
        self.content_length = get_value(resp.headers, "content-length", lambda x: int(x))
        self.cache_control = get_value(resp.headers, "cache-control")
        content_dis_str = get_value(resp.headers, 'content-disposition')
        if content_dis_str:
            if disable_encoding_meta:
                self.content_disposition = get_value(resp.headers, "content-disposition")
            else:
                self.content_disposition = urllib.parse.unquote(get_value(resp.headers, "content-disposition"))
        else:
            self.content_disposition = ''
        self.content_encoding = get_value(resp.headers, "content-encoding")
        self.content_language = get_value(resp.headers, "content-language")
        self.replication_status = get_value(resp.headers, "x-tos-replication-status",
                                            lambda x: convert_replication_status_type(x))
        is_directory = get_value(resp.headers, "x-tos-directory")
        self.is_directory = True if is_directory is not None and is_directory == 'true' else False

        self.expiration = get_value(resp.headers, 'x-tos-expiration')


class ListObjectsOutput(ResponseInfo):
    def __init__(self, resp, disable_encoding_meta: bool = None):
        super(ListObjectsOutput, self).__init__(resp)
        data = resp.json_read()

        self.name = get_value(data, 'Name')
        self.prefix = get_value(data, 'Prefix')
        self.marker = get_value(data, 'Marker')
        self.max_keys = get_value(data, 'MaxKeys', int)
        self.next_marker = get_value(data, 'NextMarker')
        self.delimiter = get_value(data, 'Delimiter')
        self.contents = []  # ListedObject
        self.common_prefixes = []  # CommonPrefixInfo
        if get_value(data, 'EncodingType'):
            self.encoding_type = get_value(data, 'EncodingType')
        else:
            self.encoding_type = 'url'

        if get_value(data, 'IsTruncated'):
            self.is_truncated = get_value(data, 'IsTruncated', lambda x: bool(x))
        else:
            self.is_truncated = False

        common_prefix_list = get_value(data, 'CommonPrefixes') or []
        for common_prefix in common_prefix_list:
            self.common_prefixes.append(CommonPrefixInfo(get_value(common_prefix, 'Prefix')))

        object_list = get_value(data, 'Contents') or []
        for object in object_list:
            last_modified = get_value(object, 'LastModified')
            if last_modified:
                last_modified = parse_modify_time_to_utc_datetime(last_modified)
            object_info = ListedObject(
                get_value(object, 'Key'),
                last_modified=last_modified,
                etag=get_etag(object),
                size=get_value(object, 'Size', int),
                storage_class=get_value(object, 'StorageClass', lambda x: convert_storage_class_type(x)),
                hash_crc64_ecma=get_value(object, "HashCrc64ecma", lambda x: int(x)),
                object_type=get_value(object, 'Type'),
                meta=convert_meta(get_value(object, "UserMeta"), disable_encoding_meta),
                hash_crc32_c=get_value(object, "HashCrc32c", lambda x: int(x))
            )
            owner_info = get_value(object, 'Owner')
            if owner_info:
                object_info.owner = Owner(
                    get_value(owner_info, "ID"),
                    get_value(owner_info, 'DisplayName')
                )
            self.contents.append(object_info)


class ListObjectsIterator(object):
    def __init__(self, req_func, max_key, bucket=None, key=None, method=None, data=None, headers=None, params=None,
                 func=None, disable_encoding_meta: bool = None):
        self.req = req_func
        self.bucket = bucket
        self.key = key
        self.method = method
        self.data = data
        self.headers = headers
        self.params = params
        self.func = func
        self.max_key = max_key
        self.number = 0
        self.is_truncated = True
        self.disable_encoding_meta = disable_encoding_meta

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        if self.is_truncated and self.new_max_key > 0:
            resp = self.req(bucket=self.bucket, method=self.method, key=self.key, data=self.data,
                            headers=self.headers, params=self.params)
            info = ListObjectType2Output(resp, self.disable_encoding_meta)
            self.is_truncated = info.is_truncated
            self.number += len(info.contents) + len(info.common_prefixes)
            self.params['max-keys'] = self.new_max_key
            self.params['continuation-token'] = info.next_continuation_token
            return info
        else:
            raise StopIteration

    @property
    def new_max_key(self):
        return self.max_key - self.number


class ListObjectType2Output(ResponseInfo):
    def __init__(self, resp, disable_encoding_meta: bool = None):
        super(ListObjectType2Output, self).__init__(resp)
        data = resp.json_read()
        self.name = get_value(data, 'Name')
        self.prefix = get_value(data, 'Prefix')
        self.continuation_token = get_value(data, 'ContinuationToken')
        self.key_count = get_value(data, 'KeyCount', int)
        self.max_keys = get_value(data, 'MaxKeys', int)
        self.delimiter = get_value(data, 'Delimiter')
        self.common_prefixes = []  # CommonPrefixInfo
        self.contents = []  # ListedObject
        if get_value(data, 'IsTruncated'):
            self.is_truncated = get_value(data, 'IsTruncated', lambda x: bool(x))
        else:
            self.is_truncated = False

        if get_value(data, 'EncodingType'):
            self.encoding_type = get_value(data, 'EncodingType')
        else:
            self.encoding_type = 'url'

        self.next_continuation_token = get_value(data, 'NextContinuationToken')
        common_prefix_list = get_value(data, 'CommonPrefixes') or []
        for common_prefix in common_prefix_list:
            self.common_prefixes.append(CommonPrefixInfo(get_value(common_prefix, 'Prefix')))

        object_list = get_value(data, 'Contents') or []
        for object in object_list:
            last_modified = get_value(object, 'LastModified')
            if last_modified:
                last_modified = parse_modify_time_to_utc_datetime(last_modified)
            object_info = ListedObject(
                key=get_value(object, 'Key'),
                last_modified=last_modified,
                etag=get_etag(object),
                size=get_value(object, 'Size', int),
                storage_class=get_value(object, 'StorageClass', lambda x: convert_storage_class_type(x)),
                hash_crc64_ecma=get_value(object, "HashCrc64ecma", lambda x: int(x)),
                object_type=get_value(object, "Type"),
                meta=convert_meta(get_value(object, "UserMeta"), disable_encoding_meta),
                hash_crc32_c=get_value(object, "HashCrc32c", lambda x: int(x)),
            )
            owner_info = get_value(object, 'Owner')
            if owner_info:
                object_info.owner = Owner(
                    get_value(owner_info, "ID"),
                    get_value(owner_info, 'DisplayName')
                )
            self.contents.append(object_info)

    def combine(self, listObjectType2Outputs: []):
        for output in listObjectType2Outputs:
            self.contents += output.contents
            for prefix in output.common_prefixes:
                self.common_prefixes.append(prefix)
        if len(listObjectType2Outputs) > 0:
            last = listObjectType2Outputs[len(listObjectType2Outputs) - 1]
            self.next_continuation_token = last.next_continuation_token
            self.is_truncated = last.is_truncated
            self.key_count = len(self.contents) + len(self.common_prefixes)

        return self


class ListedObject(object):
    def __init__(self, key: str, last_modified: datetime, etag: str, size: int, storage_class: StorageClassType,
                 hash_crc64_ecma: str, owner: Owner = None, object_type=None, meta=None,hash_crc32_c:str = None):
        self.key = key
        self.last_modified = last_modified
        self.etag = etag
        self.size = size
        self.owner = owner
        self.storage_class = storage_class
        self.hash_crc64_ecma = hash_crc64_ecma
        self.object_type = object_type
        self.meta = meta
        self.hash_crc32c = hash_crc32_c

    def __str__(self):
        info = {"key": self.key, "last_modified": self.last_modified, "etag": self.etag, "size": self.size,
                "owner": self.owner,
                "storage_class": self.storage_class, 'hash_crc64_ecma': self.hash_crc64_ecma}

        return str(info)


class ListedCommonPrefix(object):
    def __init__(self, prefix: str):
        self.prefix = prefix


class ListedObjectVersion(ListedObject):
    def __init__(self, key: str, last_modified: datetime, etag: str, size: int, storage_class: StorageClassType,
                 hash_crc64_ecma, owner: Owner = None, version_id: str = None, is_latest: bool = None,
                 object_type=None, meta=None):
        super(ListedObjectVersion, self).__init__(key, last_modified, etag, size, storage_class, hash_crc64_ecma, owner,
                                                  object_type, meta)
        self.version_id = version_id
        self.is_latest = is_latest


class ListObjectVersionsOutput(ResponseInfo):
    def __init__(self, resp, disable_encoding_meta: bool = None):
        super(ListObjectVersionsOutput, self).__init__(resp)
        self.name = ''
        self.prefix = ''
        self.key_marker = ''
        self.version_id_marker = ''
        self.max_keys = None
        self.next_key_marker = ''
        self.next_version_id_marker = ''
        self.delimiter = ''
        self.is_truncated = False
        self.encoding_type = 'url'
        self.common_prefixes = []  # string list
        self.versions = []  # ListedObjectVersion list
        self.delete_markers = []  # DeleteMarkerInfo list

        data = resp.json_read()
        self.name = get_value(data, 'Name')
        self.prefix = get_value(data, 'Prefix')
        self.key_marker = get_value(data, 'KeyMarker')
        self.version_id_marker = get_value(data, 'VersionIdMarker')
        self.next_key_marker = get_value(data, 'NextKeyMarker')
        self.next_version_id_marker = get_value(data, 'NextVersionIdMarker')
        self.delimiter = get_value(data, 'Delimiter')
        self.max_keys = get_value(data, 'MaxKeys', int)

        if get_value(data, 'EncodingType'):
            self.encoding_type = get_value(data, 'EncodingType')
        else:
            self.encoding_type = 'url'

        if get_value(data, 'IsTruncated'):
            self.is_truncated = get_value(data, 'IsTruncated', lambda x: bool(x))
        else:
            self.is_truncated = False

        common_prefix_list = get_value(data, 'CommonPrefixes') or []
        for common_prefix in common_prefix_list:
            self.common_prefixes.append(CommonPrefixInfo(get_value(common_prefix, 'Prefix')))

        object_list = get_value(data, 'Versions') or []
        for object in object_list:
            last_modified = get_value(object, 'LastModified')
            if last_modified:
                last_modified = parse_modify_time_to_utc_datetime(last_modified)
            object_info = ListedObjectVersion(
                key=get_value(object, 'Key'),
                last_modified=last_modified,
                etag=get_etag(object),
                size=get_value(object, 'Size', lambda x: int(x)),
                storage_class=get_value(object, 'StorageClass', lambda x: convert_storage_class_type(x)),
                version_id=get_value(object, 'VersionId'),
                hash_crc64_ecma=get_value(object, "HashCrc64ecma", lambda x: int(x)),
                is_latest=get_value(object, "IsLatest", lambda x: bool(x)),
                object_type=get_value(object, 'Type'),
                meta=convert_meta(get_value(object, "UserMeta"), disable_encoding_meta)
            )
            owner_info = get_value(object, 'Owner')
            if owner_info:
                object_info.owner = Owner(
                    get_value(owner_info, "ID"),
                    get_value(owner_info, 'DisplayName')
                )
            self.versions.append(object_info)

        delete_marker_list = get_value(data, 'DeleteMarkers') or []
        for delete_marker in delete_marker_list:
            last_modified = get_value(delete_marker, 'LastModified')
            if last_modified:
                last_modified = parse_modify_time_to_utc_datetime(last_modified)
            delete_marker_info = DeleteMarkerInfo(
                get_value(delete_marker, 'Key'),
                get_value(delete_marker, 'IsLatest', lambda x: bool(x)),
                last_modified,
                get_value(delete_marker, 'VersionId')
            )
            owner_info = get_value(delete_marker, 'Owner')
            if owner_info:
                delete_marker_info.owner = Owner(
                    get_value(owner_info, "ID"),
                    get_value(owner_info, 'DisplayName')
                )
            self.delete_markers.append(delete_marker_info)


class Grants(object):
    def __init__(self, id: str, display_name: str, type: GranteeType, canned: CannedType):
        self.id = id
        self.display_name = display_name
        self.type = type
        self.canned = canned


class PutObjectACLOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutObjectACLOutput, self).__init__(resp)


class GetObjectACLOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetObjectACLOutput, self).__init__(resp)
        self.version_id = get_value(self.header, 'x-tos-version-id')
        self.owner = None
        self.grants = []
        data = resp.json_read()

        self.owner = Owner(
            get_value(data['Owner'], 'ID'),
            get_value(data['Owner'], 'DisplayName'),
        )

        grant_list = data.get('Grants') or []
        for grant in grant_list:
            g = Grantee(
                id=get_value(grant['Grantee'], 'ID'),
                display_name=get_value(grant['Grantee'], 'DisplayName'),
                type=get_value(grant['Grantee'], 'Type', lambda x: convert_grantee_type(x)),
                canned=get_value(grant['Grantee'], 'Canned', lambda x: convert_canned_type(x)),
            )
            permission = get_value(grant, 'Permission', lambda x: convert_permission_type(x))
            self.grants.append(Grant(g, permission))


class SetObjectMetaOutput(ResponseInfo):
    def __init__(self, resp):
        super(SetObjectMetaOutput, self).__init__(resp)


class GetObjectOutput(HeadObjectOutput):
    def __init__(self, resp, progress_callback=None, rate_limiter=None, enable_crc=False, disable_encoding_meta=0):
        super(GetObjectOutput, self).__init__(resp, disable_encoding_meta)
        self.enable_crc = enable_crc
        self.content_range = get_value(resp.headers, "content-range")
        self.content = resp
        if progress_callback:
            self.content = utils.add_progress_listener_func(data=resp, progress_callback=progress_callback,
                                                            size=self.content_length,
                                                            download_operator=True, is_response=True)
        if rate_limiter:
            self.content = utils.add_rate_limiter_func(data=self.content, rate_limiter=rate_limiter,
                                                       size=self.content_length,
                                                       is_response=True)

        if enable_crc:
            self.content = utils.add_crc_func(data=self.content, size=self.content_length, is_response=True)

    def read(self, amt=None):
        data = self.content.read(amt)
        if not data:
            if self.enable_crc and self.client_crc and self.content_range is None and self.hash_crc64_ecma is not None \
                    and self.client_crc != self.hash_crc64_ecma:
                raise TosClientError(
                    'client crc:{} is not equal to tos crc:{}'.format(self.client_crc, self.hash_crc64_ecma))
        return data

    @property
    def client_crc(self):
        if self.enable_crc:
            return self.content.crc
        return 0

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        content = self.read(CHUNK_SIZE)
        if content:
            return content
        else:
            if self.enable_crc and self.client_crc and self.content_range is None and self.client_crc != self.hash_crc64_ecma:
                raise TosClientError(
                    'client crc:{} is not equal to tos crc:{}'.format(self.client_crc, self.hash_crc64_ecma))
            raise StopIteration


class AppendObjectOutput(ResponseInfo):
    def __init__(self, resp):
        super(AppendObjectOutput, self).__init__(resp)
        self.version_id = get_value(resp.headers, "x-tos-version-id")
        self.next_append_offset = get_value(resp.headers, "x-tos-next-append-offset", lambda x: int(x))
        self.hash_crc64_ecma = get_value(resp.headers, "x-tos-hash-crc64ecma", lambda x: int(x))


class ModifyObjectOutput(ResponseInfo):
    def __init__(self, resp):
        super(ModifyObjectOutput, self).__init__(resp)
        self.version_id = get_value(resp.headers, "x-tos-version-id")
        self.next_modify_offset = get_value(resp.headers, "x-tos-next-modify-offset", lambda x: int(x))
        self.hash_crc64_ecma = get_value(resp.headers, "x-tos-hash-crc64ecma", lambda x: int(x))


class CreateMultipartUploadOutput(ResponseInfo):
    def __init__(self, resp):
        super(CreateMultipartUploadOutput, self).__init__(resp)

        self.ssec_algorithm = get_value(resp.headers, "x-tos-server-side-encryption-customer-algorithm")
        self.ssec_key_md5 = get_value(resp.headers, "x-tos-server-side-encryption-customer-key-md5")

        data = resp.json_read()
        self.bucket = get_value(data, "Bucket")
        self.key = get_value(data, "Key")
        self.upload_id = get_value(data, "UploadId")
        if get_value(data, 'EncodingType'):
            self.encoding_type = get_value(data, 'EncodingType')
        else:
            self.encoding_type = 'url'


class UploadPartOutput(ResponseInfo):
    def __init__(self, resp, number: int):
        super(UploadPartOutput, self).__init__(resp)
        self.part_number = number
        self.etag = get_etag(resp.headers)
        self.ssec_algorithm = get_value(resp.headers, 'x-tos-server-side-encryption-customer-algorithm')
        self.ssec_key_md5 = get_value(resp.headers, 'x-tos-server-side-encryption-customer-key-md5')
        self.hash_crc64_ecma = get_value(resp.headers, 'x-tos-hash-crc64ecma', lambda x: int(x))


class CompletePart(object):
    def __init__(self, etag, part_number):
        self.etag = etag
        self.part_number = part_number


class CompleteMultipartUploadOutput(ResponseInfo):
    def __init__(self, resp, callback: str = None):
        super(CompleteMultipartUploadOutput, self).__init__(resp)
        self.bucket = None
        self.key = None
        self.complete_parts = []
        self.callback_result = None
        self.version_id = get_value(resp.headers, 'x-tos-version-id')
        self.hash_crc64_ecma = get_value(resp.headers, 'x-tos-hash-crc64ecma', lambda x: int(x))
        if not callback:
            data = resp.json_read()
            self.bucket = get_value(data, 'Bucket')
            self.key = get_value(data, 'Key')
            self.etag = get_etag(data)
            self.location = get_value(data, 'Location')
            complete_part_info = get_value(data, 'CompletedParts') or []
            for part in complete_part_info:
                self.complete_parts.append(CompletePart(
                    etag=get_value(part, 'ETag'),
                    part_number=get_value(part, 'PartNumber')
                ))
        else:
            self.callback_result = resp.read().decode('utf-8')
            self.etag = get_etag(resp.headers)
            self.location = get_value(resp.headers, 'Location')


class AbortMultipartUpload(ResponseInfo):
    def __init__(self, resp):
        super(AbortMultipartUpload, self).__init__(resp)


class UploadPartCopyOutput(ResponseInfo):
    def __init__(self, resp, part_number):
        super(UploadPartCopyOutput, self).__init__(resp)
        data = resp.json_read()
        self.part_number = part_number
        self.etag = get_etag(data)
        self.last_modified = get_value(data, "LastModified")
        if self.last_modified:
            self.last_modified = parse_modify_time_to_utc_datetime(self.last_modified)
        self.copy_source_version_id = get_value(resp.headers, 'x-tos-copy-source-version-id')

        if not self.etag:
            raise make_server_error_with_exception(resp, data)


class ListedUpload(object):
    def __init__(self, key: str, upload_id: str, storage_class: StorageClassType, initiated: datetime,
                 owner: Owner = None):
        self.key = key
        self.upload_id = upload_id
        self.owner = owner
        self.storage_class = storage_class
        self.initiated = initiated


class ListMultipartUploadsOutput(ResponseInfo):
    def __init__(self, resp):
        super(ListMultipartUploadsOutput, self).__init__(resp)
        data = resp.json_read()

        self.bucket = get_value(data, 'Bucket')
        self.upload_id_marker = get_value(data, 'UploadIdMarker')
        self.next_key_marker = get_value(data, 'NextKeyMarker')
        self.next_upload_id_marker = get_value(data, 'NextUploadIdMarker')
        self.delimiter = get_value(data, 'Delimiter')
        self.prefix = get_value(data, 'Prefix')
        self.max_uploads = get_value(data, 'MaxUploads', lambda x: int(x))
        self.key_marker = get_value(data, 'KeyMarker')
        self.common_prefixes = []
        self.uploads = []
        if get_value(data, 'EncodingType'):
            self.encoding_type = get_value(data, 'EncodingType')
        else:
            self.encoding_type = 'url'

        if get_value(data, 'IsTruncated'):
            self.is_truncated = get_value(data, 'IsTruncated', lambda x: bool(x))
        else:
            self.is_truncated = False

        upload_list = get_value(data, 'Uploads') or []
        for upload in upload_list:
            initiated = get_value(upload, 'Initiated')
            if initiated:
                initiated = parse_modify_time_to_utc_datetime(initiated)
            multipart_upload_info = ListedUpload(
                get_value(upload, 'Key'),
                get_value(upload, 'UploadId'),
                get_value(upload, 'StorageClass', lambda x: convert_storage_class_type(x)),
                initiated,
            )

            owner = get_value(upload, 'Owner')
            if owner:
                id = get_value(owner, 'ID')
                name = get_value(owner, 'DisplayName')
                multipart_upload_info.owner = Owner(id, name)

            self.uploads.append(multipart_upload_info)

        common_prefix_list = get_value(data, 'CommonPrefixes') or []
        for common_prefix in common_prefix_list:
            self.common_prefixes.append(CommonPrefixInfo(get_value(common_prefix, 'Prefix')))


class ListPartsOutput(ResponseInfo):
    def __init__(self, resp):
        super(ListPartsOutput, self).__init__(resp)

        data = resp.json_read()

        self.bucket = get_value(data, 'Bucket')
        self.key = get_value(data, 'Key')
        self.upload_id = get_value(data, 'UploadId')
        self.part_number_marker = get_value(data, 'PartNumberMarker', lambda x: int(x))
        self.next_part_number_marker = get_value(data, 'NextPartNumberMarker', int)
        self.max_parts = get_value(data, 'MaxParts', lambda x: int(x))
        self.storage_class = get_value(data, 'StorageClass', lambda x: convert_storage_class_type(x))
        self.parts = []
        if get_value(data, 'EncodingType'):
            self.encoding_type = get_value(data, 'EncodingType')
        else:
            self.encoding_type = 'url'

        if get_value(data, 'IsTruncated'):
            self.is_truncated = get_value(data, 'IsTruncated', lambda x: bool(x))
        else:
            self.is_truncated = False

        owner = get_value(data, 'Owner')
        if owner:
            id = get_value(owner, 'ID')
            name = get_value(owner, 'DisplayName')
            self.owner = Owner(id, name)

        parts = get_value(data, 'Parts') or []
        for part in parts:
            last_modified = get_value(part, 'LastModified')
            if last_modified:
                last_modified = parse_modify_time_to_utc_datetime(last_modified)
            self.parts.append(UploadedPart(
                part_number=get_value(part, 'PartNumber'),
                last_modified=last_modified,
                etag=get_etag(part),
                size=get_value(part, 'Size', int)
            ))


class PutBucketCorsOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketCorsOutput, self).__init__(resp)


class GetBucketCorsOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketCorsOutput, self).__init__(resp)
        data = resp.json_read()
        self.cors_rules = []
        cors_rules = get_value(data, 'CORSRules') or []
        for rule in cors_rules:
            self.cors_rules.append(CORSRule(
                allowed_origins=get_value(rule, 'AllowedOrigins'),
                allowed_methods=get_value(rule, 'AllowedMethods'),
                allowed_headers=get_value(rule, 'AllowedHeaders'),
                expose_headers=get_value(rule, 'ExposeHeaders'),
                max_age_seconds=get_value(rule, 'MaxAgeSeconds', lambda x: int(x)),
                response_vary=get_value(rule, 'ResponseVary', lambda x: bool(x))
            ))


class DeleteBucketCorsOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketCorsOutput, self).__init__(resp)


class Condition(object):
    def __init__(self, http_code: int = None, key_prefix: str = None, key_suffix: str = None,
                 http_method: List[str] = None,allow_host: List[str] = None):
        self.http_code = http_code
        self.key_prefix = key_prefix
        self.key_suffix = key_suffix
        self.http_method = http_method
        self.allow_host = allow_host


class ReplaceKeyPrefix(object):
    def __init__(self, key_prefix: str = None, replace_with: str = None):
        self.key_prefix = key_prefix
        self.replace_with = replace_with


class Transform(object):
    def __init__(self, with_key_prefix: str = None, with_key_suffix: str = None,
                 replace_key_prefix: ReplaceKeyPrefix = None):
        self.with_key_prefix = with_key_prefix
        self.with_key_suffix = with_key_suffix
        self.replace_key_prefix = replace_key_prefix


class SourceEndpoint(object):
    def __init__(self, primary: [] = None, follower: [] = None):
        self.primary = primary
        self.follower = follower


class PublicSource(object):
    def __init__(self, source_endpoint: SourceEndpoint = None, fixed_endpoint: bool = None):
        self.source_endpoint = source_endpoint
        self.fixed_endpoint = fixed_endpoint

class KV(object):
    def __init__(self, key: str, value: str):
        self.key = key
        self.value = value

class MirrorHeader(object):
    def __init__(self, pass_all: bool = None, pass_headers: [] = None, remove: [] = None,set_header:[] = None):
        self.pass_all = pass_all
        self.pass_headers = pass_headers
        self.remove = remove
        self.set_header = set_header

class CredentialProvider:
    def __init__(self, role: str = None):
        self.role: str = role

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'CredentialProvider':
        return cls(role=data.get('Role',""))

    def to_dict(self) -> dict:
        return {"Role": self.role}


class EndpointCredentialProvider:
    def __init__(
        self,
        endpoint: str = None,
        bucket_name: str = None,
        credential_provider: CredentialProvider = None
    ) -> None:
        self.endpoint: str = endpoint
        self.bucket_name: str = bucket_name
        self.credential_provider: CredentialProvider = credential_provider or CredentialProvider()

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'EndpointCredentialProvider':
        cp_data = data.get('CredentialProvider', {})
        credential_provider = CredentialProvider.from_json(cp_data)

        return cls(
            endpoint=data.get('Endpoint',""),
            bucket_name=data.get('BucketName',""),
            credential_provider=credential_provider
        )

    def to_dict(self) -> dict:
        result = {
            "Endpoint": self.endpoint,
            "BucketName": self.bucket_name,
            "CredentialProvider": self.credential_provider.to_dict()
        }
        return {k: v for k, v in result.items() if v is not None}


class CommonSourceEndpoint:
    def __init__(
        self,
        primary: List[EndpointCredentialProvider] = None,
        follower: List[EndpointCredentialProvider] = None
    ) -> None:
        self.primary: List[EndpointCredentialProvider] = primary or []
        self.follower: List[EndpointCredentialProvider] = follower or []

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'CommonSourceEndpoint':
        primary = []
        for item in data.get('Primary', []):
            primary.append(EndpointCredentialProvider.from_json(item))

        follower = []
        for item in data.get('Follower', []):
            follower.append(EndpointCredentialProvider.from_json(item))

        return cls(primary=primary, follower=follower)

    def to_dict(self) -> dict:
        return {
            "Primary": [item.to_dict() for item in self.primary],
            "Follower": [item.to_dict() for item in self.follower]
        }


class PrivateSource:
    def __init__(self, source_endpoint: CommonSourceEndpoint = None) -> None:
        self.source_endpoint: CommonSourceEndpoint = source_endpoint or CommonSourceEndpoint()

    @classmethod
    def from_json(cls, json_data: Dict[str, Any]) -> 'PrivateSource':
        source_ep_data = json_data.get('SourceEndpoint', {})
        source_endpoint = CommonSourceEndpoint.from_json(source_ep_data)
        return cls(source_endpoint=source_endpoint)

    def to_dict(self) -> dict:
        return {
            "SourceEndpoint": self.source_endpoint.to_dict()
        }


class Redirect(object):
    def __init__(self, redirect_type: RedirectType = None, public_source: PublicSource = None,
                 fetch_source_on_redirect: bool = None, pass_query: bool = None, follow_redirect: bool = None,
                 mirror_header: MirrorHeader = None, transform: Transform = None,
                 fetch_header_to_meta_data_rules: list = None,fetch_source_on_redirect_with_query:bool = None,
                 private_source: PrivateSource = None):
        self.redirect_type = redirect_type
        self.fetch_source_on_redirect = fetch_source_on_redirect
        self.public_source = public_source
        self.pass_query = pass_query
        self.follow_redirect = follow_redirect
        self.mirror_header = mirror_header
        self.transform = transform
        self.fetch_header_to_meta_data_rules = fetch_header_to_meta_data_rules
        self.fetch_source_on_redirect_with_query = fetch_source_on_redirect_with_query
        self.private_source = private_source



class FetchHeaderToMetaDataRule(object):
    def __init__(self, source_header: str = None, meta_data_suffix: str = None):
        self.source_header = source_header
        self.meta_data_suffix = meta_data_suffix


class Rule(object):
    def __init__(self, id: str = None, condition: Condition = None, redirect: Redirect = None):
        self.id = id
        self.condition = condition
        self.redirect = redirect


class PutBucketMirrorBackOutPut(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketMirrorBackOutPut, self).__init__(resp)


# class GetBucketMirrorBackOutPut(ResponseInfo):
#     def __init__(self, resp):
#         super(GetBucketMirrorBackOutPut, self).__init__(resp)
#         data = resp.json_read()
#         self.cors_rules = []
#         rules = get_value(data, 'Rules')
#         for rule in rules:
#             self.cors_rules.append(Rule(
#                 id=get_value(rule, 'ID', lambda x: int(x)),
#                 condition=Condition(get_value(rule, 'HttpCode', lambda x: int(x)), get_value(rule, 'ObjectKeyPrefix')),
#                 redirect=Redirect()
#             ))


class DeleteBucketMirrorBackOutPut(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketMirrorBackOutPut, self).__init__(resp)


class UploadedPart(object):
    def __init__(self, part_number: int, etag: int, size: int = None, last_modified: datetime = None):
        self.part_number = part_number
        self.etag = etag
        if size:
            self.size = size
        if last_modified:
            self.last_modified = last_modified


class PreSignedURLOutput(object):
    def __init__(self, signed_url, signed_header):
        self.signed_url = signed_url
        self.signed_header = signed_header


class UploadFileOutput(object):
    def __init__(self, resp: CompleteMultipartUploadOutput, ssec_algorithm, ssec_key_md5, upload_id, encoding_type):
        self.request_id = resp.request_id
        self.id2 = resp.id2
        self.status_code = resp.status_code
        self.header = resp.header
        self.bucket = resp.bucket
        self.key = resp.key
        self.etag = resp.etag
        self.location = resp.location
        self.upload_id = upload_id
        self.version_id = resp.version_id
        self.hash_crc64_ecma = resp.hash_crc64_ecma
        self.encoding_type = encoding_type
        self.ssec_algorithm = ssec_algorithm
        self.ssec_key_md5 = ssec_key_md5


class PartInfo(object):
    def __init__(self, part_number, part_size, offset, etag, hash_crc64_ecma, is_completed):
        self.part_number = part_number
        self.part_size = part_size
        self.offset = offset
        self.etag = etag
        self.hash_crc64_ecma = hash_crc64_ecma
        self.is_completed = is_completed

    def __str__(self):
        info = {'part_number': self.part_number, 'part_size': self.part_size, 'offset': self.offset, 'etag': self.etag,
                'hash_crc64_ecma': self.hash_crc64_ecma, 'is_completed': self.is_completed}
        return str(info)


class DownloadPartInfo(object):
    def __init__(self, part_number, range_start, range_end, hash_crc64_ecma, is_completed):
        self.part_number = part_number
        self.range_start = range_start
        self.range_end = range_end
        self.hash_crc64_ecma = hash_crc64_ecma
        self.is_completed = is_completed

    @property
    def size(self):
        return self.range_end - self.range_start


class _PartToDo(object):
    def __init__(self, part_number, start, end, part_crc=None):
        self.part_number = part_number
        self.start = start
        self.end = end
        self.part_crc = part_crc

    @property
    def size(self):
        return self.end - self.start

    def __hash__(self):
        return hash(self.__key)

    def __eq__(self, other):
        return self.__key == other.__key

    @property
    def __key(self):
        return self.part_number, self.start, self.end

    def __str__(self):
        info = {'part_number': self.part_number, 'start': self.start, 'end': self.end, 'part_crc': self.part_crc}
        return str(info)


class CORSRule(object):
    def __init__(self, allowed_origins: [] = None, allowed_methods: [] = None, allowed_headers: [] = None,
                 expose_headers: [] = None,
                 max_age_seconds: int = None,
                 response_vary: bool = None):
        self.allowed_origins = allowed_origins
        self.allowed_methods = allowed_methods
        self.allowed_headers = allowed_headers
        self.expose_headers = expose_headers
        self.max_age_seconds = max_age_seconds
        self.response_vary = response_vary


class Tag(object):
    def __init__(self, key: str = None, value: str = None):
        self.key = key
        self.value = value

    @classmethod
    def from_json(cls, data: Dict[str, Any])->'Tag':
        return cls(data.get('Key'), data.get('Value'))

    def to_dict(self):
        return {
            "Key": self.key,
            "Value": self.value
        }


class PutBucketStorageClassOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketStorageClassOutput, self).__init__(resp)


class GetBucketLocationOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketLocationOutput, self).__init__(resp)
        data = resp.json_read()
        self.region = get_value(data, 'Region')
        self.extranet_endpoint = get_value(data, 'ExtranetEndpoint')
        self.intranet_endpoint = get_value(data, 'IntranetEndpoint')


class BucketLifeCycleExpiration(object):
    def __init__(self, days: int = None, date: datetime = None):
        self.days = days
        self.date = date


class BucketLifeCycleNoCurrentVersionExpiration(object):
    def __init__(self, no_current_days: int = None, non_current_date: datetime = None):
        self.no_current_days = no_current_days
        self.non_current_date = non_current_date


class BucketLifeCycleAbortInCompleteMultipartUpload(object):
    def __init__(self, days_after_init: int = None):
        self.days_after_init = days_after_init


class BucketLifeCycleTransition(object):
    def __init__(self, storage_class: StorageClassType = None, days: int = None, date: datetime = None):
        self.storage_class = storage_class
        self.days = days
        self.date = date


class BucketLifeCycleNonCurrentVersionTransition(object):
    def __init__(self, storage_class: StorageClassType = None, non_current_days: int = None,
                 non_current_date: datetime = None):
        self.storage_class = storage_class
        self.non_current_days = non_current_days
        self.non_current_date = non_current_date


class BucketLifecycleFilter(object):
    def __init__(self, object_size_greater_than: int = None, greater_than_include_equal: StatusType = None,
                 object_size_less_than: int = None, less_than_include_equal: StatusType = None):
        self.object_size_greater_than = object_size_greater_than
        self.object_size_less_than = object_size_less_than
        self.greater_than_include_equal = greater_than_include_equal
        self.less_than_include_equal = less_than_include_equal


class BucketLifeCycleRule(object):

    def __init__(self, status: StatusType = None,
                 expiration: BucketLifeCycleExpiration = None,
                 no_current_version_expiration: BucketLifeCycleNoCurrentVersionExpiration = None,
                 abort_in_complete_multipart_upload: BucketLifeCycleAbortInCompleteMultipartUpload = None,
                 tags: [] = None,
                 transitions: [] = None,
                 non_current_version_transitions: [] = None,
                 id: str = None,
                 prefix: str = None,
                 filter: BucketLifecycleFilter = None):
        self.id = id
        self.prefix = prefix
        self.status = status
        self.expiration = expiration
        self.no_current_version_expiration = no_current_version_expiration
        self.abort_in_complete_multipart_upload = abort_in_complete_multipart_upload
        self.tags = tags
        self.transitions = transitions
        self.non_current_version_transitions = non_current_version_transitions
        self.filter = filter


class PutBucketLifecycleOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketLifecycleOutput, self).__init__(resp)


class GetBucketLifecycleOutput(ResponseInfo):
    def __init__(self, resp):
        self.rules = []
        super(GetBucketLifecycleOutput, self).__init__(resp)
        data = resp.json_read()
        self.allow_same_action_overlap = get_value(resp.headers, 'x-tos-allow-same-action-overlap', lambda x: bool(x))
        rules_json = get_value(data, 'Rules') or []
        for rule_json in rules_json:
            rule = BucketLifeCycleRule()
            rule.id = get_value(rule_json, 'ID')
            rule.prefix = get_value(rule_json, 'Prefix')
            if get_value(rule_json, 'Status'):
                rule.status = get_value(rule_json, 'Status', lambda x: convert_status_type(x))

            expiration_json = get_value(rule_json, 'Expiration')
            non_current_version_expiration_json = get_value(rule_json, 'NoncurrentVersionExpiration')
            abort_incomplete_multipart_upload_json = get_value(rule_json, 'AbortIncompleteMultipartUpload')
            tags_json = get_value(rule_json, 'Tags') or []
            transitions_json = get_value(rule_json, 'Transitions') or []
            non_current_version_transitions_json = get_value(rule_json, 'NoncurrentVersionTransitions') or []
            filter_json = get_value(rule_json, 'Filter')

            if expiration_json:
                bucket_expiration = BucketLifeCycleExpiration()
                bucket_expiration.days = get_value(expiration_json, 'Days', int)
                if get_value(expiration_json, 'Date'):
                    bucket_expiration.date = parse_modify_time_to_utc_datetime(get_value(expiration_json, 'Date'))
                rule.expiration = bucket_expiration

            if non_current_version_transitions_json:
                rule.non_current_version_transitions = []
                for vt in non_current_version_transitions_json:
                    tr = BucketLifeCycleNonCurrentVersionTransition()
                    tr.storage_class = get_value(vt, 'StorageClass', lambda x: convert_storage_class_type(x))
                    tr.non_current_days = get_value(vt, 'NoncurrentDays', int)
                    if get_value(vt, 'NoncurrentDate'):
                        tr.non_current_date = parse_modify_time_to_utc_datetime(
                            get_value(vt, 'NoncurrentDate'))
                    rule.non_current_version_transitions.append(tr)

            if transitions_json:
                rule.transitions = []
                for transition_json in transitions_json:
                    ts = BucketLifeCycleTransition()
                    ts.storage_class = get_value(transition_json, 'StorageClass',
                                                 lambda x: convert_storage_class_type(x))
                    ts.days = get_value(transition_json, 'Days', int)
                    if get_value(transition_json, 'Date'):
                        ts.date = parse_modify_time_to_utc_datetime(get_value(transition_json, 'Date'))
                    rule.transitions.append(ts)

            if tags_json:
                rule.tags = []
                for tag_json in tags_json:
                    tag = Tag()
                    tag.key = get_value(tag_json, 'Key')
                    tag.value = get_value(tag_json, 'Value')
                    rule.tags.append(tag)

            if abort_incomplete_multipart_upload_json:
                abort = BucketLifeCycleAbortInCompleteMultipartUpload()
                abort.days_after_init = get_value(abort_incomplete_multipart_upload_json, 'DaysAfterInitiation',
                                                  int)
                rule.abort_in_complete_multipart_upload = abort

            if non_current_version_expiration_json:
                exp = BucketLifeCycleNoCurrentVersionExpiration()
                exp.no_current_days = get_value(non_current_version_expiration_json, 'NoncurrentDays', int)
                if get_value(non_current_version_expiration_json, 'NoncurrentDate'):
                    exp.non_current_date = parse_modify_time_to_utc_datetime(
                        get_value(non_current_version_expiration_json, 'NoncurrentDate'))
                rule.no_current_version_expiration = exp

            if filter_json:
                lifecycle_filter = BucketLifecycleFilter()
                if get_value(filter_json, 'ObjectSizeGreaterThan'):
                    lifecycle_filter.object_size_greater_than = get_value(filter_json, 'ObjectSizeGreaterThan', int)
                if get_value(filter_json, 'ObjectSizeLessThan'):
                    lifecycle_filter.object_size_less_than = get_value(filter_json, 'ObjectSizeLessThan', int)
                if get_value(filter_json, 'GreaterThanIncludeEqual'):
                    lifecycle_filter.greater_than_include_equal = get_value(filter_json, 'GreaterThanIncludeEqual',
                                                                            lambda x: convert_status_type(x))
                if get_value(filter_json, 'LessThanIncludeEqual'):
                    lifecycle_filter.less_than_include_equal = get_value(filter_json, 'LessThanIncludeEqual',
                                                                         lambda x: convert_status_type(x))
                rule.filter = lifecycle_filter
            self.rules.append(rule)


class DeleteBucketLifecycleOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketLifecycleOutput, self).__init__(resp)


class PutBucketPolicyOutPut(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketPolicyOutPut, self).__init__(resp)


class GetBucketPolicyOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketPolicyOutput, self).__init__(resp)
        self.policy = resp.read().decode("utf-8")


class DeleteBucketPolicy(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketPolicy, self).__init__(resp)


class GetBucketMirrorBackOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketMirrorBackOutput, self).__init__(resp)
        self.rules = []
        data = resp.json_read()
        get_rules = get_value(data, 'Rules') or []
        for rule in get_rules:
            id = get_value(rule, 'ID')
            cond = get_value(rule, 'Condition')
            condition = None
            red = get_value(rule, 'Redirect')
            redirect = None
            if cond:
                condition = Condition(
                    http_code=get_value(cond, 'HttpCode', int),
                    key_prefix=get_value(cond, 'KeyPrefix', str),
                    key_suffix=get_value(cond, 'KeySuffix', str),
                    http_method=get_value(cond, 'HttpMethod', list),
                    allow_host=get_value(cond, 'AllowHost', list),
                )
            if red:
                redirect = Redirect()
                redirect.redirect_type = get_value(red, 'RedirectType', lambda x: convert_redirect_type(x))
                redirect.fetch_source_on_redirect = get_value(red, 'FetchSourceOnRedirect', lambda x: bool(x))
                redirect.fetch_source_on_redirect_with_query = get_value(red, 'FetchSourceOnRedirectWithQuery', lambda x: bool(x))

                if get_value(red, 'PublicSource'):
                    redirect.public_source = PublicSource(
                        fixed_endpoint=get_value(get_value(red, 'PublicSource'), 'FixedEndpoint', lambda x: bool(x)))
                    if get_value(get_value(red, 'PublicSource'), 'SourceEndpoint'):
                        redirect.public_source.source_endpoint = SourceEndpoint(
                            primary=get_value(get_value(get_value(red, 'PublicSource'), 'SourceEndpoint'), 'Primary'),
                            follower=get_value(get_value(get_value(red, 'PublicSource'), 'SourceEndpoint'), 'Follower')
                        )
                if get_value(red, 'PrivateSource'):
                    redirect.private_source = PrivateSource.from_json(get_value(red, 'PrivateSource'))
                redirect.pass_query = get_value(red, 'PassQuery', lambda x: bool(x))
                redirect.follow_redirect = get_value(red, 'FollowRedirect', lambda x: bool(x))
                if get_value(red, 'MirrorHeader'):
                    redirect.mirror_header = MirrorHeader(
                        pass_all=get_value(get_value(red, 'MirrorHeader'), 'PassAll', lambda x: bool(x)),
                        pass_headers=get_value(get_value(red, 'MirrorHeader'), 'Pass'),
                        remove=get_value(get_value(red, 'MirrorHeader'), 'Remove')
                    )
                    if get_value(get_value(red, 'MirrorHeader'), 'Set'):
                        set_header = []
                        for r in get_value(get_value(red, 'MirrorHeader'), 'Set'):
                            set_header.append(KV(key=get_value(r,"Key"), value=get_value(r,"Value")))
                        redirect.mirror_header.set_header = set_header
                if get_value(red, 'Transform'):
                    redirect.transform = Transform(
                        with_key_prefix=get_value(get_value(red, 'Transform'), 'WithKeyPrefix'),
                        with_key_suffix=get_value(get_value(red, 'Transform'), 'WithKeySuffix'),
                    )
                    if get_value(get_value(red, 'Transform'), 'ReplaceKeyPrefix'):
                        redirect.transform.replace_key_prefix = ReplaceKeyPrefix(
                            key_prefix=get_value(get_value(get_value(red, 'Transform'), 'ReplaceKeyPrefix'),
                                                 'KeyPrefix'),
                            replace_with=get_value(get_value(get_value(red, 'Transform'), 'ReplaceKeyPrefix'),
                                                   'ReplaceWith')
                        )
                if get_value(red, 'FetchHeaderToMetaDataRules'):
                    meta_data_rules = []
                    for r in get_value(red, 'FetchHeaderToMetaDataRules'):
                        meta_data_rules.append(FetchHeaderToMetaDataRule(
                            source_header=get_value(r, 'SourceHeader'),
                            meta_data_suffix=get_value(r, 'MetaDataSuffix'),
                        ))
                    redirect.fetch_header_to_meta_data_rules = meta_data_rules
                r = Rule(id=id, condition=condition, redirect=redirect)
                self.rules.append(r)


class PutObjectTaggingOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutObjectTaggingOutput, self).__init__(resp)
        self.version_id = get_value(resp.headers, 'x-tos-version-id')


class GetObjectTaggingOutPut(ResponseInfo):
    def __init__(self, resp):
        super(GetObjectTaggingOutPut, self).__init__(resp)
        self.version_id = self.version_id = get_value(resp.headers, 'x-tos-version-Id')
        self.tag_set = []
        data = resp.json_read()
        tag_set = get_value(data, 'TagSet')
        if tag_set:
            tags = get_value(tag_set, 'Tags')
            if tags:
                for tag in tags:
                    self.tag_set.append(Tag(
                        get_value(tag, 'Key'),
                        get_value(tag, 'Value')
                    ))


class DeleteObjectTaggingOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteObjectTaggingOutput, self).__init__(resp)
        self.version_id = get_value(resp.headers, 'x-tos-version-id')


class DeleteBucketMirrorBackOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketMirrorBackOutput, self).__init__(resp)


class PutBucketACLOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketACLOutput, self).__init__(resp)


class GetBucketACLOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketACLOutput, self).__init__(resp)
        self.owner = None
        self.grants = []
        data = resp.json_read()

        self.owner = Owner(
            get_value(data['Owner'], 'ID'),
            get_value(data['Owner'], 'DisplayName'),
        )

        grant_list = data['Grants'] or []
        for grant in grant_list:
            g = Grantee(
                id=get_value(grant['Grantee'], 'ID'),
                display_name=get_value(grant['Grantee'], 'DisplayName'),
                type=get_value(grant['Grantee'], 'Type', lambda x: convert_grantee_type(x)),
                canned=get_value(grant['Grantee'], 'Canned', lambda x: convert_canned_type(x)),
            )
            permission = get_value(grant, 'Permission', lambda x: convert_permission_type(x))
            self.grants.append(Grant(g, permission))


class PreSignedPostSignatureOutPut(object):
    def __init__(self):
        self.origin_policy = None  # 签名前 policy
        self.policy = None  # 签名后policy 用于表单域policy
        self.algorithm = None  # 用于表单域 x-tos-algorithm
        self.credential = None  # 用于表单域 x-tos-credential
        self.date = None  # 用于表单域 x-tos-date
        self.signature = None  # 用于表单域 x-tos-signature


class PostSignatureCondition(object):
    def __init__(self, key: str, value: str, operator=None):
        self.key = key
        self.value = value
        self.operator = operator


class PolicySignatureCondition(object):
    def __init__(self, key: str, value: str, operator=None):
        self.key = key
        self.value = value
        self.operator = operator


class ContentLengthRange(object):
    def __init__(self, range_start: int, range_end: int):
        self.start = range_start
        self.end = range_end


class FetchObjectOutput(ResponseInfo):
    def __init__(self, resp):
        super(FetchObjectOutput, self).__init__(resp)
        self.version_id = get_value(resp.headers, 'x-version-id')
        self.ssec_algorithm = get_value(resp.headers, 'x-server-side-encryption-customer-key-md5')
        self.ssec_key_md5 = get_value(resp.headers, 'x-server-side-encryption-customer-algorithm')
        data = resp.json_read()
        self.etag = get_etag(data)


class PutFetchTaskOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutFetchTaskOutput, self).__init__(resp)
        data = resp.json_read()
        self.task_id = get_value(data, 'TaskId')


class FetchTask(object):
    def __init__(self, bucket: str = None, key: str = None, url: str = None, ignore_same_key: bool = None,
                 content_md5: str = None, callback_url: str = None, callback_host: str = None,
                 callback_body_type: str = None, callback_body: str = None, storage_class: StorageClassType = None,
                 acl: ACLType = None, grant_full_control: str = None, grant_read: str = None,
                 grant_read_acp: str = None, grant_write_acp: str = None, ssec_algorithm: str = None,
                 ssec_key: str = None, ssec_key_md5: str = None, meta: dict = None):
        self.bucket = bucket
        self.key = key
        self.url = url
        self.ignore_same_key = ignore_same_key
        self.content_md5 = content_md5
        self.callback_url = callback_url
        self.callback_host = callback_host
        self.callback_body_type = callback_body_type
        self.callback_body = callback_body
        self.storage_class = storage_class
        self.acl = acl
        self.grant_full_control = grant_full_control
        self.grant_read = grant_read
        self.grant_read_acp = grant_read_acp
        self.grant_write_acp = grant_write_acp
        self.ssec_algorithm = ssec_algorithm
        self.ssec_key = ssec_key
        self.ssec_key_md5 = ssec_key_md5
        self.meta = meta


class GetFetchTaskOutput(ResponseInfo):
    def __init__(self, resp, disable_encoding_meta: bool = None):
        super(GetFetchTaskOutput, self).__init__(resp)
        data = resp.json_read()
        self.state = get_value(data, 'State')
        self.err = get_value(data, 'Err')
        self.task = None
        task = get_value(data, 'Task')
        if task:
            meta = convert_meta(task.get('UserMeta'), disable_encoding_meta)
            self.task = FetchTask(
                bucket=get_value(task, 'Bucket'),
                key=get_value(task, 'Key'),
                url=get_value(task, 'URL'),
                ignore_same_key=get_value(task, 'IgnoreSameKey', lambda x: bool(x)),
                callback_url=get_value(task, 'CallbackURL'),
                callback_host=get_value(task, 'CallbackHost'),
                callback_body=get_value(task, 'CallbackBody'),
                callback_body_type=get_value(task, 'CallbackBodyType'),
                storage_class=get_value(task, 'StorageClass', lambda x: convert_storage_class_type(x)),
                acl=get_value(task, 'Acl', lambda x: ACLType(x)),
                grant_full_control=get_value(task, 'GrantFullControl'),
                grant_read=get_value(task, 'GrantRead'),
                grant_read_acp=get_value(task, 'GrantReadAcp'),
                grant_write_acp=get_value(task, 'GrantWriteAcp'),
                ssec_algorithm=get_value(task, 'SSECAlgorithm'),
                ssec_key=get_value(task, 'SSECKey'),
                ssec_key_md5=get_value(task, 'SSECKeyMd5'),
                meta=meta
            )


class PutBucketReplicationOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketReplicationOutput, self).__init__(resp)


class Destination(object):
    def __init__(self, bucket: str = None, location: str = None, storage_class: StorageClassType = None,
                 storage_class_inherit_directive: StorageClassInheritDirectiveType = None):
        self.bucket = bucket
        self.location = location
        self.storage_class = storage_class
        self.storage_class_inherit_directive = storage_class_inherit_directive


class Progress(object):
    def __init__(self, historical_object: float, new_object: str):
        self.historical_object = historical_object
        self.new_object = new_object

class AccessControlTranslation(object):
    def __init__(self, owner:str):
        self.owner = owner


class ReplicationRule(object):
    def __init__(self, id: str = None, status: StatusType = None, prefix_set: [] = None,
                 destination: Destination = None,
                 historical_object_replication: StatusType = None, progress: Progress = None,
                 tags:List[Tag]=None,access_control_translation:AccessControlTranslation=None):
        self.id = id
        self.status = status
        self.prefix_set = prefix_set
        self.destination = destination
        self.historical_object_replication = historical_object_replication
        self.progress = progress
        self.tags = tags
        self.access_control_translation = access_control_translation


class GetBucketReplicationOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketReplicationOutput, self).__init__(resp)
        self.rules = []
        data = resp.json_read()
        rules_json = get_value(data, 'Rules') or []
        for rule_json in rules_json:
            replication_rule = ReplicationRule()
            replication_rule.id = get_value(rule_json, 'ID')
            replication_rule.status = get_value(rule_json, 'Status', lambda x: convert_status_type(x))
            replication_rule.prefix_set = get_value(rule_json, 'PrefixSet')
            replication_rule.historical_object_replication = get_value(rule_json, 'HistoricalObjectReplication',
                                                                       lambda x: convert_status_type(x))

            destination_json = get_value(rule_json, 'Destination')
            progress_json = get_value(rule_json, 'Progress')
            tags_json = get_value(rule_json, 'Tags')
            if destination_json:
                replication_rule.destination = Destination(
                    bucket=get_value(destination_json, 'Bucket'),
                    location=get_value(destination_json, 'Location'),
                    storage_class=get_value(destination_json, 'StorageClass', lambda x: convert_storage_class_type(x)),
                    storage_class_inherit_directive=get_value(destination_json, 'StorageClassInheritDirective',
                                                              lambda x: StorageClassInheritDirectiveType(x)))

            if progress_json:
                replication_rule.progress = Progress(
                    historical_object=get_value(progress_json, 'HistoricalObject', lambda x: float(x)),
                    new_object=get_value(progress_json, 'NewObject'))
            if tags_json:
                replication_rule.tags = [Tag.from_json(t) for t in tags_json]
            if rule_json.get("AccessControlTranslation",None):
                replication_rule.access_control_translation = AccessControlTranslation(rule_json.get("AccessControlTranslation"))
            self.rules.append(replication_rule)


class DeleteBucketReplicationOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketReplicationOutput, self).__init__(resp)


class PutBucketVersioningOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketVersioningOutput, self).__init__(resp)


class GetBucketVersionOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketVersionOutput, self).__init__(resp)
        data = resp.json_read()
        self.status = get_value(data, 'Status', lambda x: convert_versioning_status_type(x))


class RedirectAllRequestsTo(object):
    def __init__(self, host_name, protocol):
        self.host_name = host_name
        self.protocol = protocol


class IndexDocument(object):
    def __init__(self, suffix: str = None, forbidden_sub_dir: bool = None):
        self.suffix = suffix
        self.forbidden_sub_dir = forbidden_sub_dir


class ErrorDocument(object):
    def __init__(self, key: str):
        self.key = key


class RoutingRuleCondition(object):
    def __init__(self, key_prefix_equals=None, http_error_code_returned_equals=None):
        self.key_prefix_equals = key_prefix_equals
        self.http_error_code_returned_equals = http_error_code_returned_equals


class RoutingRuleRedirect(object):
    def __init__(self, protocol: ProtocolType = None, host_name: str = None, replace_key_prefix_with: str = None,
                 replace_key_with: str = None,
                 http_redirect_code: int = None):
        self.protocol = protocol
        self.host_name = host_name
        self.replace_key_prefix_with = replace_key_prefix_with
        self.replace_key_with = replace_key_with
        self.http_redirect_code = http_redirect_code


class RoutingRules(object):
    def __init__(self, rules: []):
        self.rules = rules


class RoutingRule(object):
    def __init__(self, condition: RoutingRuleCondition = None, redirect: RoutingRuleRedirect = None):
        self.condition = condition
        self.redirect = redirect


class PutBucketWebsiteOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketWebsiteOutput, self).__init__(resp)


class GetBucketWebsiteOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketWebsiteOutput, self).__init__(resp)
        self.redirect_all_requests_to = None
        self.index_document = None
        self.error_document = None
        self.routing_rules = []
        data = resp.json_read()
        redirect_all_requests_to = get_value(data, 'RedirectAllRequestsTo')
        index_document = get_value(data, 'IndexDocument')
        error_document = get_value(data, 'ErrorDocument')
        routing_rules = get_value(data, 'RoutingRules') or []
        if redirect_all_requests_to:
            self.redirect_all_requests_to = RedirectAllRequestsTo(
                host_name=get_value(redirect_all_requests_to, 'HostName'),
                protocol=get_value(redirect_all_requests_to, 'Protocol'))
        if index_document:
            self.index_document = IndexDocument(suffix=get_value(index_document, 'Suffix'),
                                                forbidden_sub_dir=get_value(index_document, 'ForbiddenSubDir'))

        if error_document:
            self.error_document = ErrorDocument(key=get_value(error_document, 'Key'))

        for rule_json in routing_rules:
            rule = RoutingRule()
            condition = get_value(rule_json, 'Condition')
            redirect = get_value(rule_json, 'Redirect')
            if condition:
                rule.condition = RoutingRuleCondition(
                    http_error_code_returned_equals=get_value(condition, 'HttpErrorCodeReturnedEquals'),
                    key_prefix_equals=get_value(condition, 'KeyPrefixEquals'))
            if redirect:
                rule.redirect = RoutingRuleRedirect(
                    protocol=get_value(redirect, 'Protocol', lambda x: convert_protocol_type(x)),
                    host_name=get_value(redirect, 'HostName'),
                    replace_key_prefix_with=get_value(redirect, 'ReplaceKeyPrefixWith'),
                    replace_key_with=get_value(redirect, 'ReplaceKeyWith'),
                    http_redirect_code=get_value(redirect, 'HttpRedirectCode'))
            self.routing_rules.append(rule)


class FilterRule(object):
    def __init__(self, name: str = None, value: str = None):
        self.name = name
        self.value = value


class FilterKey(object):
    def __init__(self, rules: [] = None):
        self.rules = rules


class Filter(object):
    def __init__(self, key: FilterKey):
        self.key = key


class RocketMQConf(object):
    def __init__(self, instance_id: str = None, topic: str = None, access_key_id: str = None):
        self.instance_id = instance_id
        self.topic = topic
        self.access_key_id = access_key_id


class CloudFunctionConfiguration(object):
    def __init__(self, id: str = None, events: [] = None, filter: Filter = None, cloud_function: str = None):
        self.id = id
        self.events = events
        self.filter = filter
        self.cloud_function = cloud_function


class RocketMQConfiguration(object):
    def __init__(self, id: str = None, events: [] = None, filter: Filter = None, role: str = None,
                 rocket_mq: RocketMQConf = None):
        self.id = id
        self.events = events
        self.filter = filter
        self.role = role
        self.rocket_mq = rocket_mq


class PutBucketNotificationOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketNotificationOutput, self).__init__(resp)


class GetBucketNotificationOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketNotificationOutput, self).__init__(resp)
        data = resp.json_read()
        self.cloud_function_configurations = []
        self.rocket_mq_configurations = []
        cloud_functions = get_value(data, 'CloudFunctionConfigurations') or []
        rocket_mq_confs = get_value(data, 'RocketMQConfigurations') or []
        for function in cloud_functions:
            config = CloudFunctionConfiguration()
            config.id = get_value(function, 'RuleId')
            config.events = get_value(function, 'Events')
            config.cloud_function = get_value(function, 'CloudFunction')
            filter_json = get_value(function, 'Filter')
            if filter_json:
                config.filter = self._get_filter(filter_json)
            self.cloud_function_configurations.append(config)

        for rocket_mq_conf in rocket_mq_confs:
            config = RocketMQConfiguration()
            config.id = get_value(rocket_mq_conf, 'RuleId')
            config.events = get_value(rocket_mq_conf, 'Events')
            config.role = get_value(rocket_mq_conf, 'Role')
            rocket_mq_json = get_value(rocket_mq_conf, 'RocketMQ')
            if rocket_mq_json:
                rocket_mq = RocketMQConf(
                    instance_id=get_value(rocket_mq_json, 'InstanceId'),
                    topic=get_value(rocket_mq_json, 'Topic'),
                    access_key_id=get_value(rocket_mq_json, 'AccessKeyId'),
                )
                config.rocket_mq = rocket_mq
            filter_json = get_value(rocket_mq_conf, 'Filter')
            if filter_json:
                config.filter = self._get_filter(filter_json)
            self.rocket_mq_configurations.append(config)

    @staticmethod
    def _get_filter(filter_json):
        filter_key = FilterKey([])
        key_json = get_value(filter_json, 'TOSKey')
        if key_json:
            filter_rules = get_value(key_json, 'FilterRules') or []
            for rule in filter_rules:
                filter_key.rules.append(
                    FilterRule(name=get_value(rule, 'Name'), value=get_value(rule, 'Value')))
        return Filter(filter_key)


class CustomDomainRule(object):
    def __init__(self, cert_id: str = None, cert_status: CertStatus = None, domain: str = None, cname: str = None,
                 forbidden: bool = None, forbidden_reason: str = None):
        self.cert_id = cert_id
        self.cert_status = cert_status
        self.domain = domain
        self.cname = cname
        self.forbidden = forbidden
        self.forbidden_reason = forbidden_reason


class PutBucketCustomDomainOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketCustomDomainOutput, self).__init__(resp)


class ListBucketCustomDomainOutput(ResponseInfo):
    def __init__(self, resp):
        super(ListBucketCustomDomainOutput, self).__init__(resp)
        self.rules = []
        data = resp.json_read()
        custom_domain_rules = get_value(data, 'CustomDomainRules') or []
        for custom_domain_rule in custom_domain_rules:
            self.rules.append(
                CustomDomainRule(cert_id=get_value(custom_domain_rule, 'CertId'),
                                 domain=get_value(custom_domain_rule, 'Domain'),
                                 cname=get_value(custom_domain_rule, 'Cname'),
                                 forbidden=get_value(custom_domain_rule, 'Forbidden'),
                                 forbidden_reason=get_value(custom_domain_rule, 'ForbiddenReason'),
                                 cert_status=get_value(custom_domain_rule, 'CertStatus',
                                                       lambda x: convert_cert_status(x))))


class DeleteCustomDomainOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteCustomDomainOutput, self).__init__(resp)


class AccessLogConfiguration(object):
    def __init__(self, use_service_topic: bool = None, tls_project_id: str = None, tls_topic_id: str = None):
        self.use_service_topic = use_service_topic
        self.tls_project_id = tls_project_id
        self.tls_topic_id = tls_topic_id


class RealTimeLogConfiguration(object):
    def __init__(self, role: str = None, configuration: AccessLogConfiguration = None):
        self.role = role
        self.configuration = configuration


class PutBucketRealTimeLogOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketRealTimeLogOutput, self).__init__(resp)


class GetBucketRealTimeLog(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketRealTimeLog, self).__init__(resp)
        self.configuration = RealTimeLogConfiguration()
        data = resp.json_read()
        bucket_real_time_log = get_value(data, 'RealTimeLogConfiguration')
        self.configuration.role = get_value(bucket_real_time_log, 'Role')
        access_log = get_value(bucket_real_time_log, 'AccessLogConfiguration')
        if access_log:
            self.configuration.configuration = AccessLogConfiguration()
            self.configuration.configuration.use_service_topic = get_value(access_log, 'UseServiceTopic')
            self.configuration.configuration.tls_topic_id = get_value(access_log, 'TLSTopicID')
            self.configuration.configuration.tls_project_id = get_value(access_log, 'TLSProjectID')


class DeleteBucketRealTimeLog(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketRealTimeLog, self).__init__(resp)


class ResumableCopyObjectOutput(object):
    def __init__(self, resp: CompleteMultipartUploadOutput = None, ssec_algorithm=None,
                 ssec_key_md5=None, encoding_type=None, upload_id=None,
                 copy_resp: CopyObjectOutput = None, bucket=None, key=None):
        self.hash_crc64_ecma = None
        self.bucket = bucket
        self.key = key
        if resp:
            self.request_id = resp.request_id
            self.id2 = resp.id2
            self.status_code = resp.status_code
            self.header = resp.header
            self.bucket = resp.bucket
            self.key = resp.key
            self.etag = resp.etag
            self.location = resp.location
            self.version_id = resp.version_id
            self.hash_crc64_ecma = resp.hash_crc64_ecma
        if copy_resp:
            self.request_id = copy_resp.request_id
            self.id2 = copy_resp.id2
            self.status_code = copy_resp.status_code
            self.version_id = copy_resp.version_id
            self.header = copy_resp.header
            self.hash_crc64_ecma = get_value(copy_resp.header, "x-tos-hash-crc64ecma", lambda x: int(x))
            self.etag = copy_resp.etag
            self.location = get_value(copy_resp.header, 'Location')
        self.upload_id = upload_id
        self.ssec_algorithm = ssec_algorithm
        self.ssec_key_md5 = ssec_key_md5
        self.encoding_type = encoding_type


class PreSignedPolicyURlInputOutput(object):
    def __init__(self, signed_query, host, scheme, bucket=None):
        self.signed_query = signed_query
        self._host = host
        self._scheme = scheme
        self._bucket = bucket

    def get_signed_url_for_list(self, additional_query=None) -> str:
        if additional_query is None:
            return _make_virtual_host_url(self._host, self._scheme, self._bucket, '') + '?' + self.signed_query

        return _make_virtual_host_url(self._host, self._scheme, self._bucket,
                                      '') + '?' + self.signed_query + '&' + '&'.join(
            _param_to_quoted_query(k, v) for k, v in additional_query.items())

    def get_signed_url_for_get_or_head(self, key: str, additional_query=None) -> str:
        if additional_query is None:
            return _make_virtual_host_url(self._host, self._scheme, self._bucket, key) + '?' + self.signed_query

        return _make_virtual_host_url(self._host, self._scheme, self._bucket,
                                      key) + '?' + self.signed_query + '&' + '&'.join(
            _param_to_quoted_query(k, v) for k, v in additional_query.items())


class CopyPartInfo(object):
    def __init__(self, part_number, copy_source_range_start, copy_source_range_end, etag=None):
        self.part_number = part_number
        self.copy_source_range_start = copy_source_range_start
        self.copy_source_range_end = copy_source_range_end
        self.etag = etag

    def __str__(self):
        info = {'part_number': self.part_number,
                'copy_source_range_start': self.copy_source_range_start,
                'copy_source_range_end': self.copy_source_range_end,
                'etag': self.etag}
        return str(info)


class RestoreJobParameters(object):
    def __init__(self, tier: TierType):
        self.tier = tier


class RestoreObjectOutput(ResponseInfo):
    def __init__(self, resp):
        super(RestoreObjectOutput, self).__init__(resp)


class RenameObjectOutput(ResponseInfo):
    def __init__(self, resp):
        super(RenameObjectOutput, self).__init__(resp)


class GetBucketRenameOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketRenameOutput, self).__init__(resp)
        data = resp.json_read()
        self.rename_enable = get_value(data, 'RenameEnable', bool)


class PutBucketRenameOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketRenameOutput, self).__init__(resp)


class DeleteBucketRenameOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketRenameOutput, self).__init__(resp)


class PutBucketTaggingOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketTaggingOutput, self).__init__(resp)


class GetBucketTaggingOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketTaggingOutput, self).__init__(resp)
        self.tag_set = []
        data = resp.json_read()
        tag_set = get_value(data, 'TagSet')
        if tag_set:
            tags = get_value(tag_set, 'Tags')
            if tags:
                for tag in tags:
                    self.tag_set.append(Tag(
                        get_value(tag, 'Key'),
                        get_value(tag, 'Value')
                    ))


class DeleteBucketTaggingOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketTaggingOutput, self).__init__(resp)


class PutSymlinkOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutSymlinkOutput, self).__init__(resp)
        self.version_id = get_value(resp.headers, "x-tos-version-id")


class GetSymlinkOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetSymlinkOutput, self).__init__(resp)
        self.version_id = get_value(resp.headers, "x-tos-version-id")
        self.symlink_target_key = urllib.parse.unquote_plus(get_value(resp.headers, 'x-tos-symlink-target'))
        self.etag = get_etag(resp.headers)
        self.last_modified = get_value(resp.headers, 'last-modified')
        if self.last_modified:
            self.last_modified = parse_gmt_time_to_utc_datetime(self.last_modified)
        self.symlink_target_bucket = get_value(resp.headers, 'x-tos-symlink-bucket')


class GenericInput(object):
    def __init__(self, request_date: datetime = None,request_host: str = None):
        self.request_date = request_date
        self.request_host = request_host


class ApplyServerSideEncryptionByDefault(object):
    def __init__(self, sse_algorithm: str = None, kms_master_key_id: str = None):
        self.sse_algorithm = sse_algorithm
        self.kms_master_key_id = kms_master_key_id


class BucketEncryptionRule(object):
    def __init__(self, apply_server_side_encryption_by_default: ApplyServerSideEncryptionByDefault = None):
        self.apply_server_side_encryption_by_default = apply_server_side_encryption_by_default


class PutBucketEncryptionOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketEncryptionOutput, self).__init__(resp)


class GetBucketEncryptionOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketEncryptionOutput, self).__init__(resp)
        self.rule = None
        data = resp.json_read()
        rule = get_value(get_value(data, 'Rule'), 'ApplyServerSideEncryptionByDefault')
        if rule:
            self.rule = BucketEncryptionRule(
                apply_server_side_encryption_by_default=ApplyServerSideEncryptionByDefault(
                    sse_algorithm=get_value(rule, 'SSEAlgorithm'),
                    kms_master_key_id=get_value(rule, 'KMSMasterKeyID')
                )
            )


class DeleteBucketEncryptionOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketEncryptionOutput, self).__init__(resp)


class NotificationFilterRule(object):
    def __init__(self, name: str = None, value: str = None):
        self.name = name
        self.value = value


class NotificationFilterKey(object):
    def __init__(self, filter_rules: [] = None):
        self.filter_rules = filter_rules


class NotificationFilter(object):
    def __init__(self, tos_key: NotificationFilterKey = None):
        self.tos_key = tos_key


class DestinationRocketMQ(object):
    def __init__(self, role: str = None, instance_id: str = None, topic: str = None, access_key_id: str = None):
        self.role = role
        self.instance_id = instance_id
        self.topic = topic
        self.access_key_id = access_key_id


class DestinationVeFaaS(object):
    def __init__(self, function_id: str = None):
        self.function_id = function_id


class NotificationDestination(object):
    def __init__(self, rocket_mq: [] = None, ve_faas: [] = None):
        self.rocket_mq = rocket_mq
        self.ve_faas = ve_faas


class NotificationRule(object):
    def __init__(self, rule_id: str = None, events: [] = None, filter: NotificationFilter = None,
                 destination: NotificationDestination = None):
        self.rule_id = rule_id
        self.events = events
        self.filter = filter
        self.destination = destination


class PutBucketNotificationType2Output(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketNotificationType2Output, self).__init__(resp)


class GetBucketNotificationType2Output(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketNotificationType2Output, self).__init__(resp)
        data = resp.json_read()
        self.version = get_value(data, 'Version')
        self.rules = []
        rules = get_value(data, 'Rules') or []
        for rule in rules:
            config = NotificationRule(
                rule_id=get_value(rule, 'RuleId'),
                events=get_value(rule, 'Events'),
            )
            if get_value(rule, 'Destination'):
                config.destination = NotificationDestination()
                destination_json = get_value(rule, 'Destination')
                if get_value(destination_json, 'RocketMQ'):
                    rocket_mqs = []
                    for r in get_value(destination_json, 'RocketMQ'):
                        rocket_mqs.append(DestinationRocketMQ(
                            role=get_value(r, 'Role'),
                            instance_id=get_value(r, 'InstanceId'),
                            topic=get_value(r, 'Topic'),
                            access_key_id=get_value(r, 'AccessKeyId')
                        ))
                    config.destination.rocket_mq = rocket_mqs
                if get_value(destination_json, 'VeFaaS'):
                    ve_faas = []
                    for r in get_value(destination_json, 'VeFaaS'):
                        ve_faas.append(DestinationVeFaaS(function_id=get_value(r, 'FunctionId')))
                    config.destination.ve_faas = ve_faas
            if get_value(rule, 'Filter') and get_value(get_value(rule, 'Filter'), 'TOSKey') and get_value(
                    get_value(get_value(rule, 'Filter'), 'TOSKey'), 'FilterRules'):
                filter_rules = get_value(get_value(get_value(rule, 'Filter'), 'TOSKey'), 'FilterRules')
                config_rules = []
                for r in filter_rules:
                    config_rules.append(NotificationFilterRule(
                        name=get_value(r, 'Name'),
                        value=get_value(r, 'Value')
                    ))
                config.filter = NotificationFilter(
                    tos_key=NotificationFilterKey(
                        filter_rules=config_rules
                    )
                )
            self.rules.append(config)


class InventoryFilter(object):
    def __init__(self, prefix: str):
        self.prefix = prefix


class TOSBucketDestination(object):
    def __init__(self, format: InventoryFormatType, account_id: str, role: str, bucket: str, prefix: str=None):
        self.format = format
        self.account_id = account_id
        self.role = role
        self.bucket = bucket
        self.prefix = prefix

class InventoryDestination(object):
    def __init__(self, tos_bucket_destination: TOSBucketDestination):
        self.tos_bucket_destination = tos_bucket_destination

class InventorySchedule(object):
    def __init__(self, frequency: InventoryFrequencyType):
        self.frequency = frequency

class InventoryOptionalFields(object):
    def __init__(self, fields: List[str]):
        self.fields = fields

class PutBucketInventoryOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketInventoryOutput, self).__init__(resp)

class SetObjectExpiresOutput(ResponseInfo):
    def __init__(self, resp):
        super(SetObjectExpiresOutput, self).__init__(resp)

class BucketInventoryConfiguration(object):
    def __init__(self,inventory_id:str,
                 is_enabled: bool,
                 destination:InventoryDestination,
                 schedule: InventorySchedule,
                 included_object_versions: InventoryIncludedObjType,
                 inventory_filter: InventoryFilter = None,
                 optional_fields:InventoryOptionalFields=None):
        self.inventory_id = inventory_id
        self.is_enabled = is_enabled
        self.inventory_filter = inventory_filter
        self.destination = destination
        self.schedule = schedule
        self.included_object_versions = included_object_versions
        self.optional_fields = optional_fields

    @classmethod
    def from_json(cls, config_data:Dict) -> 'BucketInventoryConfiguration':
        filter_data = config_data.get("Filter")
        inventory_filter = None
        if filter_data:
            inventory_filter = InventoryFilter(
                prefix=filter_data.get("Prefix", "")
            )

        dest_data = config_data.get("Destination", {}).get("TOSBucketDestination")
        destination = None
        if dest_data:
            tos_dest = TOSBucketDestination(
                format=InventoryFormatType(dest_data.get("Format", "")),
                account_id=dest_data.get("AccountId", ""),
                role=dest_data.get("Role", ""),
                bucket=dest_data.get("Bucket", ""),
                prefix=dest_data.get("Prefix", None)
            )
            destination = InventoryDestination(tos_bucket_destination=tos_dest)

        schedule_data = config_data.get("Schedule")
        schedule = None
        if schedule_data:
            schedule = InventorySchedule(
                frequency=InventoryFrequencyType(schedule_data.get("Frequency", ""))
            )

        optional_fields_data = config_data.get("OptionalFields", {}).get("Field")
        optional_fields = None
        if optional_fields_data:
            optional_fields = InventoryOptionalFields(
                fields=optional_fields_data
            )

        included_versions = None
        if "IncludedObjectVersions" in config_data:
            included_versions = InventoryIncludedObjType(config_data["IncludedObjectVersions"])

        return cls(
            inventory_id=config_data.get("Id", ""),
            is_enabled=config_data.get("IsEnabled", False),
            inventory_filter=inventory_filter,
            destination=destination,
            schedule=schedule,
            included_object_versions=included_versions,
            optional_fields=optional_fields
        )

    def to_dict(self) -> dict:
        inventory_config = {}
        inventory_config['Id'] = self.inventory_id
        inventory_config['IsEnabled'] = self.is_enabled

        if self.inventory_filter:
            inventory_config["Filter"] = {"Prefix": self.inventory_filter.prefix}

        if self.destination and self.destination.tos_bucket_destination:
            tos_dest = self.destination.tos_bucket_destination
            inventory_config["Destination"] = {
                "TOSBucketDestination": {
                    "Format": tos_dest.format.value,
                    "AccountId": tos_dest.account_id,
                    "Role": tos_dest.role,
                    "Bucket": tos_dest.bucket,
                }
            }
            if tos_dest.prefix:
                inventory_config["Destination"]["TOSBucketDestination"]["Prefix"] = tos_dest.prefix
        if self.schedule:
            inventory_config["Schedule"] = {
                "Frequency": self.schedule.frequency.value
            }

        if self.included_object_versions:
            inventory_config["IncludedObjectVersions"] = self.included_object_versions.value

        if self.optional_fields and self.optional_fields.fields:
            inventory_config["OptionalFields"] = {
                "Field": self.optional_fields.fields
            }

        return inventory_config

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

class ListBucketInventoryOutput(ResponseInfo):
    def __init__(self, resp):
        super(ListBucketInventoryOutput, self).__init__(resp)
        json_data = resp.json_read()
        list_data = json_data.get("InventoryConfigurations") or []
        self.configurations = [BucketInventoryConfiguration.from_json(item) for item in list_data]
        self.is_truncated = json_data.get("IsTruncated",False)
        self.next_continuation_token = json_data.get("NextContinuationToken",None)



class DeleteBucketInventoryOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketInventoryOutput, self).__init__(resp)

class GetBucketInventoryOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketInventoryOutput, self).__init__(resp)
        config_data = resp.json_read()

        filter_data = config_data.get("Filter")
        inventory_filter = None
        if filter_data:
            inventory_filter = InventoryFilter(
                prefix=filter_data.get("Prefix", "")
            )

        dest_data = config_data.get("Destination", {}).get("TOSBucketDestination")
        destination = None
        if dest_data:
            tos_dest = TOSBucketDestination(
                format=InventoryFormatType(dest_data.get("Format", "")),
                account_id=dest_data.get("AccountId", ""),
                role=dest_data.get("Role", ""),
                bucket=dest_data.get("Bucket", ""),
                prefix=dest_data.get("Prefix", None)
            )
            destination = InventoryDestination(tos_bucket_destination=tos_dest)

        schedule_data = config_data.get("Schedule")
        schedule = None
        if schedule_data:
            schedule = InventorySchedule(
                frequency=InventoryFrequencyType(schedule_data.get("Frequency", ""))
            )

        optional_fields_data = config_data.get("OptionalFields", {}).get("Field")
        optional_fields = None
        if optional_fields_data:
            optional_fields = InventoryOptionalFields(
                fields=optional_fields_data
            )

        included_versions = None
        if "IncludedObjectVersions" in config_data:
            included_versions = InventoryIncludedObjType(config_data["IncludedObjectVersions"])

        self.bucket_inventory_configuration = BucketInventoryConfiguration(
            inventory_id=config_data.get("Id", ""),
            is_enabled=config_data.get("IsEnabled", False),
            inventory_filter=inventory_filter,
            destination=destination,
            schedule=schedule,
            included_object_versions=included_versions,
            optional_fields=optional_fields
        )


class QueryRequest:
    def __init__(self, operation: QueryOperationType,
                 field: str = None,
                 value: str = None,
                 sub_queries: List['QueryRequest'] = None):
        self.operation = operation  # 枚举类型
        self.field = field
        self.value = value
        self.sub_queries = sub_queries if sub_queries is not None else []

    def to_dict(self) -> Dict:
        result = {"Operation": self.operation.value}

        if self.field is not None:
            result["Field"] = self.field
        if self.value is not None:
            result["Value"] = self.value
        if self.sub_queries:
            result["SubQueries"] = [q.to_dict() for q in self.sub_queries]

        return result


class AggregationRequest:
    def __init__(self, field: str, operation: AggregationOperationType):
        self.field = field
        self.operation = operation

    def to_dict(self) -> Dict:
        return {
            "Field": self.field,
            "Operation": self.operation.value
        }

class SemanticQueryOutput(ResponseInfo):
    def __init__(self, resp):
        super(SemanticQueryOutput, self).__init__(resp)
        json_data = resp.json_read()
        self.files = [FileResponse.from_json(item) for item in json_data.get("Files",[])]

class SimpleQueryOutput(ResponseInfo):
    def __init__(self, resp):
        super(SimpleQueryOutput, self).__init__(resp)
        json_data = resp.json_read()
        self.aggregations = []
        self.files = []
        if json_data.get("Aggregations",None):
            for agg in json_data.get("Aggregations",[]):
                groups = [GroupResponse(g.get("Value",""), g.get("Count",0)) for g in (agg.get("Groups") or [])]
                self.aggregations.append(AggregationResponse(
                    field=agg.get("Field",""),
                    operation=AggregationOperationType(agg.get("Operation","")) if agg.get("Operation",None) is not None else None,
                    value=agg.get("Value",0),
                    groups=groups
                ))

        if json_data.get("Files", None):
            self.files = [FileResponse.from_json(item) for item in json_data.get("Files", [])]
        self.next_token = json_data.get("NextToken", "")


class AggregationResponse:
    def __init__(self, field: str,
                 operation: AggregationOperationType,
                 value: float,
                 groups: List['GroupResponse'] = None):
        self.field = field
        self.operation = operation
        self.value = value
        self.groups = groups if groups is not None else []


class GroupResponse:
    def __init__(self, value: str, count: int):
        self.value = value
        self.count = count

class FileResponse:
    def __init__(self,
                    tos_bucket_name: str=None,
                    file_name: str=None,
                    etag: str=None,
                    tos_storage_class: StorageClassType=None,
                    size: int=None,
                    content_type: str =None,
                    tos_crc64: str = None,
                    server_side_encryption: str = None,
                    server_side_encryption_customer_algorithm: str = None,
                    score: float = None,
                    tos_tagging_count: int = None,
                    tos_tagging: Dict[str, str] = None,
                    tos_user_meta: Dict[str, str] = None,
                    tos_version_id: str = None,
                    tos_object_type: str = None,
                    tos_replication_status: ReplicationStatusType = None,
                    tos_is_delete_marker: bool = None,
                    account_id: str = None):
        self.tos_bucket_name = tos_bucket_name
        self.file_name = file_name
        self.etag = etag
        self.tos_storage_class = tos_storage_class  # 枚举类型
        self.tos_crc64 = tos_crc64
        self.server_side_encryption = server_side_encryption
        self.server_side_encryption_customer_algorithm = server_side_encryption_customer_algorithm
        self.size = size
        self.score = score
        self.tos_tagging_count = tos_tagging_count
        self.tos_tagging = tos_tagging
        self.tos_user_meta = tos_user_meta
        self.tos_version_id = tos_version_id
        self.tos_object_type = tos_object_type
        self.content_type = content_type
        self.tos_replication_status = tos_replication_status  # 枚举类型
        self.tos_is_delete_marker = tos_is_delete_marker
        self.account_id = account_id

    @classmethod
    def from_json(cls,file_json:Dict)->'FileResponse':
        result =cls(tos_bucket_name=file_json.get("TOSBucketName", None),
            file_name=file_json.get("FileName", None),
            etag=file_json.get("ETag", None),
            tos_storage_class=StorageClassType(file_json.get("TOSStorageClass", "Unknown")),
            size=file_json.get("Size", None),
            content_type=file_json.get("ContentType", None),
            tos_crc64=file_json.get("TOSCRC64", None),
            server_side_encryption=file_json.get("ServerSideEncryption", None),
            server_side_encryption_customer_algorithm=file_json.get("ServerSideEncryptionCustomerAlgorithm", None),
            score=file_json.get("Score", None),
            tos_tagging_count=file_json.get("TOSTaggingCount", None),
            tos_tagging=file_json.get("TOSTagging", None),
            tos_user_meta=file_json.get("TOSUserMeta", None),
            tos_version_id=file_json.get("TOSVersionId", None),
            tos_object_type=file_json.get("TOSObjectType", None),
            tos_replication_status=file_json.get("TOSReplicationStatus", None),
            tos_is_delete_marker=file_json.get("TOSIsDeleteMarker", None),
            account_id=file_json.get("AccountId", None))
        if file_json.get("FileModifiedTime",None):
            result.file_modified_time = parse_iso_time_to_utc_datetime(file_json["FileModifiedTime"])
        if file_json.get("CreateTime",None):
            result.file_create_time = parse_iso_time_to_utc_datetime(file_json["CreateTime"])
        return result


class VectorData(object):
    def __init__(self, float32: List[float] = None):
        self.float32 = float32


class Vector(object):
    def __init__(self, key: str = None, data: VectorData = None, metadata: Dict[str, Any] = None):
        self.key = key
        self.data = data
        self.metadata = metadata


class PutVectorsOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutVectorsOutput, self).__init__(resp)


class CreateVectorBucketOutput(ResponseInfo):
    def __init__(self, resp):
        super(CreateVectorBucketOutput, self).__init__(resp)


class DeleteVectorBucketOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteVectorBucketOutput, self).__init__(resp)


class GetVectorsOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetVectorsOutput, self).__init__(resp)
        data = resp.json_read()
        self.vectors = []
        for vector_data in data.get('vectors', []):
            vector_key = get_value(vector_data, 'key')
            vector_metadata = get_value(vector_data, 'metadata')
            
            # 处理 vector data
            vector_data_obj = None
            vector_data_dict = get_value(vector_data, 'data')
            if vector_data_dict:
                float32_data = get_value(vector_data_dict, 'float32', list)
                if float32_data:
                    vector_data_obj = VectorData(float32=float32_data)
            
            vector = Vector(key=vector_key, data=vector_data_obj, metadata=vector_metadata)
            self.vectors.append(vector)


class ListVectorsOutput(ResponseInfo):
    def __init__(self, resp):
        super(ListVectorsOutput, self).__init__(resp)
        data = resp.json_read()
        self.next_token = get_value(data, 'nextToken')
        self.vectors = []
        for vector_data in data.get('vectors', []):
            vector_key = get_value(vector_data, 'key')
            vector_metadata = get_value(vector_data, 'metadata')
            
            # 处理 vector data
            vector_data_obj = None
            vector_data_dict = get_value(vector_data, 'data')
            if vector_data_dict:
                float32_data = get_value(vector_data_dict, 'float32')
                if float32_data:
                    vector_data_obj = VectorData(float32=float32_data)
            
            vector = Vector(key=vector_key, data=vector_data_obj, metadata=vector_metadata)
            self.vectors.append(vector)

class DistanceVector(object):
    def __init__(self, key: str = None, data: VectorData = None, distance: float = None, metadata: Dict[str, Any] = None):
        self.key = key
        self.data = data
        self.distance = distance
        self.metadata = metadata

class DeleteVectorsOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteVectorsOutput, self).__init__(resp)


class QueryVectorsOutput(ResponseInfo):
    def __init__(self, resp):
        super(QueryVectorsOutput, self).__init__(resp)
        data = resp.json_read()
        self.vectors = []
        for vector_data in data.get('vectors', []):
            vector_key = get_value(vector_data, 'key')
            vector_distance = get_value(vector_data, 'distance', float)
            vector_metadata = get_value(vector_data, 'metadata')
            
            # 处理 vector data
            vector_data_obj = None
            vector_data_dict = get_value(vector_data, 'data')
            if vector_data_dict:
                float32_data = get_value(vector_data_dict, 'float32')
                if float32_data:
                    vector_data_obj = VectorData(float32=float32_data)
            
            vector = DistanceVector(key=vector_key, data=vector_data_obj, distance=vector_distance, metadata=vector_metadata)
            self.vectors.append(vector)


class CreateIndexOutput(ResponseInfo):
    def __init__(self, resp):
        super(CreateIndexOutput, self).__init__(resp)


class DeleteIndexOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteIndexOutput, self).__init__(resp)


class VectorBucket(object):
    def __init__(self, creation_time: int = None, vector_bucket_trn: str = None, 
                 vector_bucket_name: str = None):
        self.creation_time = creation_time
        self.vector_bucket_trn = vector_bucket_trn
        self.vector_bucket_name = vector_bucket_name


class GetVectorBucketOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetVectorBucketOutput, self).__init__(resp)
        data = resp.json_read()
        vector_bucket_data = get_value(data, 'vectorBucket')
        if vector_bucket_data:
            self.vector_bucket = VectorBucket(
                creation_time=get_value(vector_bucket_data, 'creationTime', int),
                vector_bucket_trn=get_value(vector_bucket_data, 'vectorBucketTrn'),
                vector_bucket_name=get_value(vector_bucket_data, 'vectorBucketName')
            )
        else:
            self.vector_bucket = None


class MetadataConfiguration(object):
    def __init__(self, non_filterable_metadata_keys: List[str] = None):
        self.non_filterable_metadata_keys = non_filterable_metadata_keys or []


class IndexSummary(object):
    def __init__(self, creation_time: int, index_name: str = None, 
                 index_trn: str = None, vector_bucket_name: str = None):
        self.creation_time = creation_time
        self.index_name = index_name
        self.index_trn = index_trn
        self.vector_bucket_name = vector_bucket_name


class ListIndexesOutput(ResponseInfo):
    def __init__(self, resp):
        super(ListIndexesOutput, self).__init__(resp)
        data = resp.json_read()
        self.next_token = get_value(data, 'nextToken')
        self.indexes = []
        for index_data in data.get('indexes', []):
            creation_time = get_value(index_data, 'creationTime', int)
            
            index_summary = IndexSummary(
                creation_time=creation_time,
                index_name=get_value(index_data, 'indexName'),
                index_trn=get_value(index_data, 'indexTrn'),
                vector_bucket_name=get_value(index_data, 'vectorBucketName')
            )
            self.indexes.append(index_summary)


class Index(object):
    def __init__(self, creation_time: int = None, data_type: DataType = None, dimension: int = None,
                 distance_metric: DistanceMetricType = None, metadata_configuration: MetadataConfiguration = None,
                 index_name: str = None, index_trn: str = None, vector_bucket_name: str = None):
        self.creation_time = creation_time
        self.data_type = data_type
        self.dimension = dimension
        self.distance_metric = distance_metric
        self.metadata_configuration = metadata_configuration
        self.index_name = index_name
        self.index_trn = index_trn
        self.vector_bucket_name = vector_bucket_name


class GetIndexOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetIndexOutput, self).__init__(resp)
        data = resp.json_read()
        index_data = get_value(data, 'index')
        if index_data:
            # 处理 metadata_configuration
            metadata_config = None
            metadata_config_data = get_value(index_data, 'metadataConfiguration')
            if metadata_config_data:
                non_filterable_keys = get_value(metadata_config_data, 'nonFilterableMetadataKeys') or []
                metadata_config = MetadataConfiguration(non_filterable_metadata_keys=non_filterable_keys)
            
            self.index = Index(
                creation_time=get_value(index_data, 'creationTime', int),
                data_type=get_value(index_data, 'dataType', convert_data_type),
                dimension=get_value(index_data, 'dimension', int),
                distance_metric=get_value(index_data, 'distanceMetric', convert_distance_metric_type),
                metadata_configuration=metadata_config,
                index_name=get_value(index_data, 'indexName'),
                index_trn=get_value(index_data, 'indexTrn'),
                vector_bucket_name=get_value(index_data, 'vectorBucketName')
            )
        else:
            self.index = None

class PutVectorBucketPolicyOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutVectorBucketPolicyOutput, self).__init__(resp)


class GetVectorBucketPolicyOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetVectorBucketPolicyOutput, self).__init__(resp)
        self.policy = resp.read().decode("utf-8")


class DeleteVectorBucketPolicyOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteVectorBucketPolicyOutput, self).__init__(resp)


class ListVectorBucketsOutput(ResponseInfo):
    def __init__(self, resp):
        super(ListVectorBucketsOutput, self).__init__(resp)
        data = resp.json_read()
        self.next_token = get_value(data, 'nextToken')
        
        # 解析向量存储桶列表
        self.vector_buckets = []
        vector_buckets_data = get_value(data, 'vectorBuckets', list)
        if vector_buckets_data:
            for bucket_data in vector_buckets_data:
                vector_bucket = VectorBucket(
                    creation_time=get_value(bucket_data, 'creationTime', int),
                    vector_bucket_trn=get_value(bucket_data, 'vectorBucketTrn'),
                    vector_bucket_name=get_value(bucket_data, 'vectorBucketName')
                )
                self.vector_buckets.append(vector_bucket)
