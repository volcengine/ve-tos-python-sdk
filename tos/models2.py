import urllib.parse
from datetime import datetime

from requests.structures import CaseInsensitiveDict

from tos.enum import CannedType, GranteeType, PermissionType, StorageClassType
from . import utils
from .models import CommonPrefixInfo
from .utils import (get_etag, get_value, meta_header_decode,
                    parse_gmt_time_to_utc_datetime,
                    parse_modify_time_to_utc_datetime)


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
        self.storage_class = get_value(self.header, "x-tos-storage-class", lambda x: StorageClassType(x))


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
        self.buckets = []
        self.owner = None
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
        self.deleted = []
        self.error = []

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
        self.sse_key_md5 = get_value(resp.headers, "x-tos-server-side-encryption-customer-key-md5")
        self.website_redirect_location = get_value(resp.headers, "x-tos-website-redirect-location")
        self.hash_crc64_ecma = get_value(resp.headers, "x-tos-hash-crc64ecma", lambda x: int(x))
        self.storage_class = StorageClassType(get_value(resp.headers, "x-tos-storage-class"))
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
        self.contents = []
        self.common_prefixes = []
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
                storage_class=get_value(object, 'StorageClass', lambda x: StorageClassType(x)),
                hash_crc64_ecma=get_value(object, "HashCrc64ecma", lambda x: int(x))
            )
            owner_info = get_value(object, 'Owner')
            if owner_info:
                object_info.owner = Owner(
                    get_value(owner_info, "ID"),
                    get_value(owner_info, 'DisplayName')
                )
            self.contents.append(object_info)


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
                 hash_crc64_ecma, owner: Owner = None, version_id: str = None):
        super(ListedObjectVersion, self).__init__(key, last_modified, etag, size, storage_class, hash_crc64_ecma, owner)
        self.version_id = version_id


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
                type=get_value(grant['Grantee'], 'Type', lambda x: GranteeType(x)),
                canned=get_value(grant['Grantee'], 'Canned', lambda x: CannedType(x)),
            )
            permission = get_value(grant, 'Permission', lambda x: PermissionType(x))
            self.grants.append(Grant(g, permission))


class SetObjectMetaOutput(ResponseInfo):
    def __init__(self, resp):
        super(SetObjectMetaOutput, self).__init__(resp)


class GetObjectOutput(HeadObjectOutput):
    def __init__(self, resp, progress_callback=None, rate_limiter=None, enable_crc=False):
        super(GetObjectOutput, self).__init__(resp)
        self.content_range = get_value(resp.headers, "content-range")
        self.content = resp
        if progress_callback:
            self.content = utils.add_progress_listener_func(resp, progress_callback, self.content_length,
                                                            download_operator=True)
        if rate_limiter:
            self.content = utils.add_rate_limiter_func(self.content, rate_limiter)

        if enable_crc:
            self.content = utils.add_crc_func(data=self.content, size=self.content_length)

    def read(self, amt=None):
        return self.content.read(amt)

    def __iter__(self):
        return iter(self.content)

    @property
    def client_crc(self):
        return self.content.crc


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
                StorageClassType(get_value(upload, 'StorageClass')),
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
        self.storage_class = StorageClassType(get_value(data, 'StorageClass'))
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
