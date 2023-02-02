import urllib.parse
from datetime import datetime

from requests.structures import CaseInsensitiveDict

from . import utils
from .enum import CannedType, GranteeType, PermissionType, StorageClassType, RedirectType, StatusType, \
    StorageClassInheritDirectiveType, VersioningStatusType, ProtocolType, CertStatus, AzRedundancyType, \
    convert_storage_class_type, convert_az_redundancy_type, convert_permission_type, convert_grantee_type, \
    convert_canned_type, convert_redirect_type, convert_status_type, convert_versioning_status_type, \
    convert_protocol_type, convert_cert_status
from .consts import CHUNK_SIZE
from .exceptions import TosClientError, make_server_error_with_exception
from .models import CommonPrefixInfo, DeleteMarkerInfo
from .utils import (get_etag, get_value, meta_header_decode,
                    parse_gmt_time_to_utc_datetime,
                    parse_modify_time_to_utc_datetime, _param_to_quoted_query, _make_virtual_host_url)


class ResponseInfo(object):
    def __init__(self, resp):
        self.request_id = resp.request_id
        self.id2 = get_value(resp.headers, "x-tos-id-2")
        self.status_code = resp.status
        self.header = resp.headers


class CreateBucketOutput(ResponseInfo):
    def __init__(self, resp):
        super(CreateBucketOutput, self).__init__(resp)
        self.location = get_value(self.header, "Location")


class HeadBucketOutput(ResponseInfo):
    def __init__(self, resp):
        super(HeadBucketOutput, self).__init__(resp)
        self.region = get_value(self.header, "x-tos-bucket-region")
        self.storage_class = get_value(self.header, "x-tos-storage-class", lambda x: convert_storage_class_type(x))
        self.az_redundancy = get_value(self.header, "x-tos-az-redundancy", lambda x: convert_az_redundancy_type(x))


class DeleteBucketOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketOutput, self).__init__(resp)


class ListedBucket(object):
    def __init__(self, name: str, location: str, creation_date: str, extranet_endpoint: str, intranet_endpoint: str):
        self.name = name
        self.location = location
        self.creation_date = creation_date
        self.extranet_endpoint = extranet_endpoint
        self.intranet_endpoint = intranet_endpoint

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
                get_value(bkt, 'IntranetEndpoint')))


class PutObjectOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutObjectOutput, self).__init__(resp)
        self.etag = get_etag(resp.headers)
        self.ssec_algorithm = get_value(resp.headers, "x-tos-server-side-encryption-customer-algorithm")
        self.ssec_key_md5 = get_value(resp.headers, "x-tos-server-side-encryption-customer-key-md5")
        self.version_id = get_value(resp.headers, "x-tos-version-id")
        self.hash_crc64_ecma = get_value(resp.headers, "x-tos-hash-crc64ecma", lambda x: int(x))


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
    def __init__(self, resp):
        super(HeadObjectOutput, self).__init__(resp)
        self.etag = get_etag(resp.headers)
        self.version_id = get_value(resp.headers, "x-tos-version-id")
        self.sse_algorithm = get_value(resp.headers, "x-tos-server-side-encryption-customer-algorithm")
        self.sse_key_md5 = get_value(resp.headers, "x-tos-server-side-encryption-customer-key-MD5")
        self.website_redirect_location = get_value(resp.headers, "x-tos-website-redirect-location")
        self.hash_crc64_ecma = get_value(resp.headers, "x-tos-hash-crc64ecma", lambda x: int(x))
        self.storage_class = get_value(resp.headers, "x-tos-storage-class", lambda x: convert_storage_class_type(x))
        self.meta = CaseInsensitiveDict()
        self.object_type = get_value(resp.headers, "x-tos-object-type")
        if not self.object_type:
            self.object_type = "Normal"

        meta = {}
        for k in resp.headers:
            if k.startswith('x-tos-meta-'):
                meta[k[11:]] = resp.headers[k]
        self.meta = meta_header_decode(meta)

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
            self.content_disposition = urllib.parse.unquote(get_value(resp.headers, "content-disposition"))
        else:
            self.content_disposition = ''
        self.content_encoding = get_value(resp.headers, "content-encoding")
        self.content_language = get_value(resp.headers, "content-language")


class ListObjectsOutput(ResponseInfo):
    def __init__(self, resp):
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
                hash_crc64_ecma=get_value(object, "HashCrc64ecma", lambda x: int(x))
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
                 func=None):
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

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        if self.is_truncated and self.new_max_key > 0:
            resp = self.req(bucket=self.bucket, method=self.method, key=self.key, data=self.data,
                            headers=self.headers, params=self.params)
            info = ListObjectType2Output(resp)
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
    def __init__(self, resp):
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
                hash_crc64_ecma=get_value(object, "HashCrc64ecma", lambda x: int(x))
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
                 hash_crc64_ecma: str, owner: Owner = None):
        self.key = key
        self.last_modified = last_modified
        self.etag = etag
        self.size = size
        self.owner = owner
        self.storage_class = storage_class
        self.hash_crc64_ecma = hash_crc64_ecma

    def __str__(self):
        info = {"key": self.key, "last_modified": self.key, "etag": self.etag, "size": self.size, "owner": self.owner,
                "storage_class": self.storage_class, 'hash_crc64_ecma': self.hash_crc64_ecma}

        return str(info)


class ListedCommonPrefix(object):
    def __init__(self, prefix: str):
        self.prefix = prefix


class ListedObjectVersion(ListedObject):
    def __init__(self, key: str, last_modified: datetime, etag: str, size: int, storage_class: StorageClassType,
                 hash_crc64_ecma, owner: Owner = None, version_id: str = None, is_latest: bool = None):
        super(ListedObjectVersion, self).__init__(key, last_modified, etag, size, storage_class, hash_crc64_ecma, owner)
        self.version_id = version_id
        self.is_latest = is_latest


class ListObjectVersionsOutput(ResponseInfo):
    def __init__(self, resp):
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
                is_latest=get_value(object, "IsLatest", lambda x: bool(x))
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


class SetObjectMetaOutput(ResponseInfo):
    def __init__(self, resp):
        super(SetObjectMetaOutput, self).__init__(resp)


class GetObjectOutput(HeadObjectOutput):
    def __init__(self, resp, progress_callback=None, rate_limiter=None, enable_crc=False, discard=0):
        super(GetObjectOutput, self).__init__(resp)
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
            if self.enable_crc and self.client_crc and self.content_range is None and self.client_crc != self.hash_crc64_ecma:
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


class CompleteMultipartUploadOutput(ResponseInfo):
    def __init__(self, resp):
        super(CompleteMultipartUploadOutput, self).__init__(resp)
        data = resp.json_read()
        self.bucket = get_value(data, 'Bucket')
        self.key = get_value(data, 'Key')
        self.etag = get_etag(data)
        self.location = get_value(data, 'Location')
        self.version_id = get_value(resp.headers, 'x-tos-version-id')
        self.hash_crc64_ecma = get_value(resp.headers, 'x-tos-hash-crc64ecma', lambda x: int(x))


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
                max_age_seconds=get_value(rule, 'MaxAgeSeconds', lambda x: int(x))
            ))


class DeleteBucketCorsOutput(ResponseInfo):
    def __init__(self, resp):
        super(DeleteBucketCorsOutput, self).__init__(resp)


class Condition(object):
    def __init__(self, http_code: int = None):
        self.http_code = http_code


class SourceEndpoint(object):
    def __init__(self, primary: [] = None, follower: [] = None):
        self.primary = primary
        self.follower = follower


class PublicSource(object):
    def __init__(self, source_endpoint: SourceEndpoint):
        self.source_endpoint = source_endpoint


class MirrorHeader(object):
    def __init__(self, pass_all: bool = None, pass_headers: [] = None, remove: [] = None):
        self.pass_all = pass_all
        self.pass_headers = pass_headers
        self.remove = remove


class Redirect(object):
    def __init__(self, redirect_type: RedirectType = None, public_source: PublicSource = None,
                 fetch_source_on_redirect: bool = None, pass_query: bool = None, follow_redirect: bool = None,
                 mirror_header: MirrorHeader = None):
        self.redirect_type = redirect_type
        self.fetch_source_on_redirect = fetch_source_on_redirect
        self.public_source = public_source
        self.pass_query = pass_query
        self.follow_redirect = follow_redirect
        self.mirror_header = mirror_header


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
                 max_age_seconds: int = None):
        self.allowed_origins = allowed_origins
        self.allowed_methods = allowed_methods
        self.allowed_headers = allowed_headers
        self.expose_headers = expose_headers
        self.max_age_seconds = max_age_seconds


class Tag(object):
    def __init__(self, key: str = None, value: str = None):
        self.key = key
        self.value = value


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
    def __init__(self, no_current_days: int = None):
        self.no_current_days = no_current_days


class BucketLifeCycleAbortInCompleteMultipartUpload(object):
    def __init__(self, days_after_init: int = None):
        self.days_after_init = days_after_init


class BucketLifeCycleTransition(object):
    def __init__(self, storage_class: StorageClassType = None, days: int = None, date: datetime = None):
        self.storage_class = storage_class
        self.days = days
        self.date = date


class BucketLifeCycleNonCurrentVersionTransition(object):
    def __init__(self, storage_class: StorageClassType = None, non_current_days: int = None):
        self.storage_class = storage_class
        self.non_current_days = non_current_days


class BucketLifeCycleRule(object):

    def __init__(self, status: StatusType = None,
                 expiration: BucketLifeCycleExpiration = None,
                 no_current_version_expiration: BucketLifeCycleNoCurrentVersionExpiration = None,
                 abort_in_complete_multipart_upload: BucketLifeCycleAbortInCompleteMultipartUpload = None,
                 tags: [] = None,
                 transitions: [] = None,
                 non_current_version_transitions: [] = None,
                 id: str = None,
                 prefix: str = None):
        self.id = id
        self.prefix = prefix
        self.status = status
        self.expiration = expiration
        self.no_current_version_expiration = no_current_version_expiration
        self.abort_in_complete_multipart_upload = abort_in_complete_multipart_upload
        self.tags = tags
        self.transitions = transitions
        self.non_current_version_transitions = non_current_version_transitions


class PutBucketLifecycleOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketLifecycleOutput, self).__init__(resp)


class GetBucketLifecycleOutput(ResponseInfo):
    def __init__(self, resp):
        self.rules = []
        super(GetBucketLifecycleOutput, self).__init__(resp)
        data = resp.json_read()
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
                    rule.non_current_version_transitions.append(tr)

            if transitions_json:
                rule.transitions = []
                for transition_json in transitions_json:
                    ts = BucketLifeCycleTransition()
                    ts.storage_class = get_value(transition_json, 'StorageClass', lambda x: convert_storage_class_type(x))
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
                rule.no_current_version_expiration = exp
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
                    http_code=get_value(cond, 'HttpCode', int)
                )
            if red:
                redirect = Redirect()
                redirect.redirect_type = get_value(red, 'RedirectType', lambda x: convert_redirect_type(x))
                redirect.fetch_source_on_redirect = get_value(red, 'FetchSourceOnRedirect', lambda x: bool(x))

                if get_value(red, 'PublicSource') and get_value(get_value(red, 'PublicSource'), 'SourceEndpoint'):
                    redirect.public_source = PublicSource(SourceEndpoint(
                        primary=get_value(get_value(get_value(red, 'PublicSource'), 'SourceEndpoint'), 'Primary'),
                        follower=get_value(get_value(get_value(red, 'PublicSource'), 'SourceEndpoint'), 'Follower')
                    ))

                redirect.pass_query = get_value(red, 'PassQuery', lambda x: bool(x))
                redirect.follow_redirect = get_value(red, 'FollowRedirect', lambda x: bool(x))
                if get_value(red, 'MirrorHeader'):
                    redirect.mirror_header = MirrorHeader(
                        pass_all=get_value(get_value(red, 'MirrorHeader'), 'PassAll', lambda x: bool(x)),
                        pass_headers=get_value(get_value(red, 'MirrorHeader'), 'Pass'),
                        remove=get_value(get_value(red, 'MirrorHeader'), 'Remove')
                    )
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


class ReplicationRule(object):
    def __init__(self, id: str = None, status: StatusType = None, prefix_set: [] = None,
                 destination: Destination = None,
                 historical_object_replication: StatusType = None, progress: Progress = None):
        self.id = id
        self.status = status
        self.prefix_set = prefix_set
        self.destination = destination
        self.historical_object_replication = historical_object_replication
        self.progress = progress


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
                rule.redirect = RoutingRuleRedirect(protocol=get_value(redirect, 'Protocol', lambda x: convert_protocol_type(x)),
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


class CloudFunctionConfiguration(object):
    def __init__(self, id: str = None, events: [] = None, filter: Filter = None, cloud_function: str = None):
        self.id = id
        self.events = events
        self.filter = filter
        self.cloud_function = cloud_function


class PutBucketNotificationOutput(ResponseInfo):
    def __init__(self, resp):
        super(PutBucketNotificationOutput, self).__init__(resp)


class GetBucketNotificationOutput(ResponseInfo):
    def __init__(self, resp):
        super(GetBucketNotificationOutput, self).__init__(resp)
        data = resp.json_read()
        self.cloud_function_configurations = []
        cloud_functions = get_value(data, 'CloudFunctionConfigurations') or []
        for function in cloud_functions:
            config = CloudFunctionConfiguration()
            config.id = get_value(function, 'RuleId')
            config.events = get_value(function, 'Events')
            config.cloud_function = get_value(function, 'CloudFunction')
            filter_json = get_value(function, 'Filter')
            if filter_json:
                fileter_key = FilterKey([])
                key_json = get_value(filter_json, 'TOSKey')
                if key_json:
                    filter_rules = get_value(key_json, 'FilterRules') or []
                    for rule in filter_rules:
                        fileter_key.rules.append(
                            FilterRule(name=get_value(rule, 'Name'), value=get_value(rule, 'Value')))
                    config.filter = Filter(fileter_key)
            self.cloud_function_configurations.append(config)


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
                                 cert_status=get_value(custom_domain_rule, 'CertStatus', lambda x: convert_cert_status(x))))


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
    def __init__(self, resp: CompleteMultipartUploadOutput, ssec_algorithm, ssec_key_md5, encoding_type):
        self.request_id = resp.request_id
        self.id2 = resp.id2
        self.status_code = resp.status_code
        self.header = resp.header
        self.bucket = resp.bucket
        self.key = resp.key
        self.upload_id = resp.request_id
        self.etag = resp.etag
        self.location = resp.location
        self.version_id = resp.version_id
        self.hash_crc64_ecma = resp.hash_crc64_ecma
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

        return _make_virtual_host_url(self._host, self._scheme, self._bucket, '') + '?' + self.signed_query + '&' + '&'.join(
            _param_to_quoted_query(k, v) for k, v in additional_query.items())

    def get_signed_url_for_get_or_head(self, key: str, additional_query=None) -> str:
        if additional_query is None:
            return _make_virtual_host_url(self._host, self._scheme, self._bucket, key) + '?' + self.signed_query

        return _make_virtual_host_url(self._host, self._scheme, self._bucket, key) + '?' + self.signed_query + '&' + '&'.join(
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
