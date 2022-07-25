
from requests.structures import CaseInsensitiveDict

from .utils import get_etag, get_value, parse_gmt_time_to_utc_datetime


class RequestResult(object):
    def __init__(self, resp):
        self.resp = resp
        self.status = resp.status
        self.headers = resp.headers
        self.request_id = resp.request_id
        self.version_id = get_value(self.headers, 'x-tos-version-id')
        self.delete_marker = get_value(self.headers, 'x-tos-delete-marker', bool)


class CreateBucketResult(RequestResult):
    def __init__(self, resp):
        super(CreateBucketResult, self).__init__(resp)
        self.location = get_value(self.headers, "Location")


class HeadBucketResult(RequestResult):
    def __init__(self, resp):
        super(HeadBucketResult, self).__init__(resp)
        self.region = get_value(self.headers, "x-tos-bucket-region")


class CreateMultipartUploadResult(RequestResult):
    def __init__(self, resp):
        super(CreateMultipartUploadResult, self).__init__(resp)
        self.upload_id = None
        self.bucket = None
        self.key = None

        self.sse_customer_algorithm = get_value(self.headers, "x-tos-server-side-encryption-customer-algorithm")
        self.sse_customer_key = get_value(self.headers, "x-tos-server-side-encryption-customer-key")
        self.sse_customer_key_md5 = get_value(self.headers, "x-tos-server-side-encryption-customer-key-md5")


class HeadObjectResult(RequestResult):
    def __init__(self, resp):
        super(HeadObjectResult, self).__init__(resp)
        self.content_type = get_value(self.headers, "content-type")
        self.content_length = get_value(self.headers, "content-length", int)
        self.etag = get_etag(self.headers)

        self.sse_customer_algorithm = get_value(self.headers, "x-tos-server-side-encryption-customer-algorithm")
        self.sse_customer_key = get_value(self.headers, "x-tos-server-side-encryption-customer-key")
        self.sse_customer_key_md5 = get_value(self.headers, "x-tos-server-side-encryption-customer-key-md5")

        self.metadata = CaseInsensitiveDict()
        for k in self.headers:
            if k.startswith('x-tos-meta-'):
                self.metadata[k[11:]] = self.headers[k]

        self.last_modified = get_value(self.headers, 'last-modified')
        if self.last_modified:
            self.last_modified = parse_gmt_time_to_utc_datetime(self.last_modified)
        self.expires = get_value(self.headers, 'expires')
        if self.expires:
            self.expires = parse_gmt_time_to_utc_datetime(self.expires)


class CopyObjectResult(RequestResult):
    def __init__(self, resp):
        super(CopyObjectResult, self).__init__(resp)
        self.etag = ''
        self.last_modified = ''
        self.copy_source_version_id = get_value(self.headers, "x-tos-copy-source-version-id")


class UploadPartCopyResult(RequestResult):
    def __init__(self, resp):
        super(UploadPartCopyResult, self).__init__(resp)
        self.etag = ''
        self.last_modified = ''
        self.copy_source_version_id = get_value(self.headers, "x-tos-copy-source-version-id")

        self.sse_customer_algorithm = get_value(self.headers, "x-tos-server-side-encryption-customer-algorithm")
        self.sse_customer_key = get_value(self.headers, "x-tos-server-side-encryption-customer-key")
        self.sse_customer_key_md5 = get_value(self.headers, "x-tos-server-side-encryption-customer-key-md5")


class GetObjectResult(HeadObjectResult):
    def __init__(self, resp):
        super(GetObjectResult, self).__init__(resp)
        self.content_range = get_value(self.headers, "content-range")
        self.stream = self.resp

    def read(self, amt=None):
        return self.stream.read(amt)

    def __iter__(self):
        return iter(self.stream)


class PutObjectResult(RequestResult):
    def __init__(self, resp):
        super(PutObjectResult, self).__init__(resp)
        self.etag = get_etag(self.headers)

        self.sse_customer_algorithm = get_value(self.headers, "x-tos-server-side-encryption-customer-algorithm")
        self.sse_customer_key = get_value(self.headers, "x-tos-server-side-encryption-customer-key")
        self.sse_customer_key_md5 = get_value(self.headers, "x-tos-server-side-encryption-customer-key-md5")


class AppendObjectResult(RequestResult):
    def __init__(self, resp):
        super(AppendObjectResult, self).__init__(resp)
        self.etag = get_etag(self.headers)
        self.sse_customer_algorithm = get_value(self.headers, "x-tos-server-side-encryption-customer-algorithm")
        self.sse_customer_key = get_value(self.headers, "x-tos-server-side-encryption-customer-key")
        self.sse_customer_key_md5 = get_value(self.headers, "x-tos-server-side-encryption-customer-key-md5")


class ListBucketResult(RequestResult):
    def __init__(self, resp):
        super(ListBucketResult, self).__init__(resp)
        self.bucket_list = []  # BucketInfo list
        self.Owner = None  # UserInfo


class ListMultipartUploadsResult(RequestResult):
    def __init__(self, resp):
        super(ListMultipartUploadsResult, self).__init__(resp)
        self.bucket = ''
        self.upload_id_marker = ''
        self.next_key_marker = ''
        self.next_upload_id_marker = ''
        self.delimiter = ''
        self.prefix = ''
        self.max_uploads = None
        self.is_truncated = False
        self.upload_list = []  # MultipartUploadInfo list
        self.common_prefix_list = []  # CommonPrefixInfo list


class ListPartsResult(RequestResult):
    def __init__(self, resp):
        super(ListPartsResult, self).__init__(resp)
        self.bucket = ''
        self.key = ''
        self.upload_id = ''
        self.part_number_marker = None
        self.next_part_number_marker = None
        self.max_parts = None
        self.is_truncated = False
        self.storage_class = ''
        self.owner = None  # UserInfo list
        self.part_list = []  # UploadPartInfo list


class CompleteMultipartUploadResult(RequestResult):
    def __init__(self, resp):
        super(CompleteMultipartUploadResult, self).__init__(resp)
        self.bucket = ''
        self.location = ''
        self.key = ''
        self.etag = ''


class ListObjectsResult(RequestResult):
    def __init__(self, resp):
        super(ListObjectsResult, self).__init__(resp)
        self.name = ''
        self.prefix = ''
        self.key_count = None
        self.marker = ''
        self.max_keys = None
        self.next_marker = ''
        self.delimiter = ''
        self.is_truncated = False
        self.encoding_type = 'url'
        self.common_prefix_list = []  # CommonPrefixInfo list
        self.object_list = []  # ObjectInfo list



class ListObjectVersionsResult(RequestResult):
    def __init__(self, resp):
        super(ListObjectVersionsResult, self).__init__(resp)
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
        self.common_prefix_list = []  # string list
        self.version_list = []  # ObjectVersionInfo list
        self.delete_marker_list = []  # DeleteMarker list


class DeleteObjectsResult(RequestResult):
    def __init__(self, resp):
        super(DeleteObjectsResult, self).__init__(resp)
        self.deleted_list = []  # DeletedObjectInfo list
        self.error_list = []  # DeletedErrInfo list


class GetObjectAclResult(RequestResult):
    def __init__(self, resp):
        super(GetObjectAclResult, self).__init__(resp)
        self.grant_list = []  # GrantInfo list
        self.owner = None


# result 中的元素信息
class UserInfo(object):
    def __init__(self, id, name):
        self.id = id
        self.name = name


class BucketInfo(object):
    def __init__(self, name, location, creation_date, extranet_endpoint, intranet_endpoint):
        self.name = name
        self.location = location
        self.creation_date = creation_date
        self.extranet_endpoint = extranet_endpoint
        self.intranet_endpoint = intranet_endpoint


class GranteeInfo(object):
    def __init__(self, id, display_name, type, canned):
        self.id = id
        self.display_name = display_name
        self.type = type
        self.canned = canned


class GrantInfo(object):
    def __init__(self, id, display_name, type, canned, permission):
        self.grantee = GranteeInfo(id, display_name, type, canned)
        self.permission = permission


class MultipartUploadInfo(object):
    def __init__(self, key, upload_id, storage_class, initiated, owner=None):
        self.key = key
        self.upload_id = upload_id
        self.storage_class = storage_class
        self.initiated = initiated
        self.owner = owner


class UploadPartInfo(object):
    def __init__(self, part_number, last_modified, etag, size):
        self.part_number = part_number
        self.last_modified = last_modified
        self.etag = etag
        self.size = size


class CommonPrefixInfo(object):
    def __init__(self, prefix):
        self.prefix = prefix


class ObjectInfo(object):
    def __init__(self, key, last_modified, etag, size, storage_class, owner=None):
        self.key = key
        self.last_modified = last_modified
        self.etag = etag
        self.size = size
        self.storage_class = storage_class
        self.owner = owner


class ObjectVersionInfo(object):
    def __init__(self, key, is_latest, last_modified, etag, size, storage_class, version_id, owner=None):
        self.key = key
        self.is_latest = is_latest
        self.last_modified = last_modified
        self.etag = etag
        self.size = size
        self.storage_class = storage_class
        self.version_id = version_id
        self.owner = owner


class DeleteMarkerInfo(object):
    def __init__(self, key, is_latest, last_modified, version_id, owner=None):
        self.key = key
        self.is_latest = is_latest
        self.last_modified = last_modified
        self.version_id = version_id
        self.owner = owner


class DeletedObjectInfo(object):
    def __init__(self, key, version_id, delete_marker, delete_marker_version_id):
        self.key = key
        self.version_id = version_id
        self.delete_marker = delete_marker
        self.delete_marker_version_id = delete_marker_version_id


class DeletedErrInfo(object):
    def __init__(self, code, message, key, version_id):
        self.code = code
        self.message = message
        self.key = key
        self.version_id = version_id
