import json

from requests.structures import CaseInsensitiveDict

from .enum import StorageClassType
from .http import Response
from .models import (BucketInfo, CommonPrefixInfo,
                     CompleteMultipartUploadResult, CopyObjectResult,
                     CreateMultipartUploadResult, DeletedErrInfo,
                     DeletedObjectInfo, DeleteMarkerInfo, DeleteObjectsResult,
                     GetObjectAclResult, GrantInfo, ListBucketResult,
                     ListMultipartUploadsResult, ListObjectsResult,
                     ListObjectVersionsResult, ListPartsResult,
                     MultipartUploadInfo, ObjectInfo, ObjectVersionInfo,
                     UploadPartCopyResult, UploadPartInfo, UserInfo)
from .models2 import (GetObjectACLOutput, HeadObjectOutput, ListBucketsOutput,
                      ListedBucket, ListedObjectVersion,
                      ListObjectVersionsOutput, Owner)
from .utils import (get_etag, get_value, parse_gmt_time_to_utc_datetime,
                    parse_modify_time_to_utc_datetime)


def convert_list_buckets_result(resp):
    result = ListBucketResult(resp)
    data = json.loads(resp.read())
    result.owner = UserInfo(
        get_value(data['Owner'], 'ID'),
        get_value(data['Owner'], 'Name'),
    )

    bkt_list = get_value(data, 'Buckets') or []
    for bkt in bkt_list:
        result.bucket_list.append(BucketInfo(
            get_value(bkt, 'Name'),
            get_value(bkt, 'Location'),
            get_value(bkt, 'CreationDate'),
            get_value(bkt, 'ExtranetEndpoint'),
            get_value(bkt, 'IntranetEndpoint')))
    return result


def convert_create_multipart_upload_result(resp):
    result = CreateMultipartUploadResult(resp)
    data = json.loads(resp.read())

    result.upload_id = get_value(data, 'UploadId')
    result.bucket = get_value(data, 'Bucket')
    result.key = get_value(data, 'Key')
    return result


def convert_list_multipart_uploads_result(resp):
    result = ListMultipartUploadsResult(resp)
    data = json.loads(resp.read())

    result.bucket = get_value(data, 'Bucket')
    result.upload_id_marker = get_value(data, 'UploadIdMarker')
    result.next_key_marker = get_value(data, 'NextKeyMarker')
    result.next_upload_id_marker = get_value(data, 'NextUploadIdMarker')
    result.delimiter = get_value(data, 'Delimiter')
    result.prefix = get_value(data, 'Prefix')
    result.max_uploads = get_value(data, 'MaxUploads')
    if get_value(data, 'IsTruncated'):
        result.is_truncated = get_value(data, 'IsTruncated')
    else:
        result.is_truncated = False

    upload_list = get_value(data, 'Uploads') or []
    for upload in upload_list:
        initiated = get_value(upload, 'Initiated')
        if initiated:
            initiated = parse_modify_time_to_utc_datetime(initiated)
        multipart_upload_info = MultipartUploadInfo(
            get_value(upload, 'Key'),
            get_value(upload, 'UploadId'),
            get_value(upload, 'StorageClass'),
            initiated,
        )

        owner = get_value(upload, 'Owner')
        if owner:
            id = get_value(owner, 'ID')
            name = get_value(owner, 'DisplayName')
            multipart_upload_info.owner = UserInfo(id, name)

        result.upload_list.append(multipart_upload_info)

    common_prefix_list = get_value(data, 'CommonPrefixes') or []
    for common_prefix in common_prefix_list:
        result.common_prefix_list.append(CommonPrefixInfo(get_value(common_prefix, 'Prefix')))
    return result


def convert_copy_object_result(resp):
    result = CopyObjectResult(resp)
    data = json.loads(resp.read())

    result.etag = get_etag(data)
    result.last_modified = get_value(data, 'LastModified')
    if result.last_modified:
        result.last_modified = parse_modify_time_to_utc_datetime(result.last_modified)

    return result


def convert_upload_part_copy_result(resp):
    result = UploadPartCopyResult(resp)
    data = json.loads(resp.read())

    result.etag = get_etag(data)
    result.last_modified = get_value(data, 'LastModified')
    if result.last_modified:
        result.last_modified = parse_modify_time_to_utc_datetime(result.last_modified)
    return result


def convert_list_parts_result(resp):
    result = ListPartsResult(resp)
    data = json.loads(resp.read())

    result.bucket = get_value(data, 'Bucket')
    result.key = get_value(data, 'Key')
    result.upload_id = get_value(data, 'UploadId')
    result.part_number_marker = get_value(data, 'PartNumberMarker')
    result.next_part_number_marker = get_value(data, 'NextPartNumberMarker')
    result.max_parts = get_value(data, 'MaxParts')
    result.storage_class = get_value(data, 'StorageClass')

    if get_value(data, 'IsTruncated'):
        result.is_truncated = get_value(data, 'IsTruncated')
    else:
        result.is_truncated = False

    owner = get_value(data, 'Owner')
    if owner:
        id = get_value(owner, 'ID')
        name = get_value(owner, 'DisplayName')
        result.owner = UserInfo(id, name)

    part_list = get_value(data, 'Parts') or []
    for part in part_list:
        last_modified = get_value(part, 'LastModified')
        if last_modified:
            last_modified = parse_modify_time_to_utc_datetime(last_modified)
        result.part_list.append(UploadPartInfo(
            get_value(part, 'PartNumber'),
            last_modified,
            get_etag(part),
            get_value(part, 'Size')
        ))
    return result


def convert_complete_multipart_upload_result(resp):
    result = CompleteMultipartUploadResult(resp)
    data = json.loads(resp.read())

    result.location = get_value(data, 'Location')
    result.bucket = get_value(data, 'Bucket')
    result.key = get_value(data, 'Key')
    result.etag = get_etag(data)
    return result


def convert_list_objects_result(resp):
    result = ListObjectsResult(resp)
    data = json.loads(resp.read())

    result.name = get_value(data, 'Name')
    result.prefix = get_value(data, 'Prefix')
    result.marker = get_value(data, 'Marker')
    result.max_keys = get_value(data, 'MaxKeys', int)
    result.next_marker = get_value(data, 'NextMarker')
    result.delimiter = get_value(data, 'Delimiter')
    if get_value(data, 'EncodingType'):
        result.encoding_type = get_value(data, 'EncodingType')
    else:
        result.encoding_type = 'url'

    if get_value(data, 'IsTruncated'):
        result.is_truncated = get_value(data, 'IsTruncated')
    else:
        result.is_truncated = False

    common_prefix_list = get_value(data, 'CommonPrefixes') or []
    for common_prefix in common_prefix_list:
        result.common_prefix_list.append(CommonPrefixInfo(get_value(common_prefix, 'Prefix')))

    object_list = get_value(data, 'Contents') or []
    for object in object_list:
        last_modified = get_value(object, 'LastModified')
        if last_modified:
            last_modified = parse_modify_time_to_utc_datetime(last_modified)
        object_info = ObjectInfo(
            get_value(object, 'Key'),
            last_modified,
            get_etag(object),
            get_value(object, 'Size'),
            get_value(object, 'StorageClass')
        )
        owner_info = get_value(object, 'Owner')
        if owner_info:
            object_info.owner = UserInfo(
                get_value(owner_info, "ID"),
                get_value(owner_info, 'DisplayName')
            )
        result.object_list.append(object_info)
    return result


def convert_list_object_versions_result(resp):
    result = ListObjectVersionsResult(resp)
    data = json.loads(resp.read())

    result.name = get_value(data, 'Name')
    result.prefix = get_value(data, 'Prefix')
    result.key_marker = get_value(data, 'KeyMarker')
    result.version_id_marker = get_value(data, 'VersionIdMarker')
    result.next_key_marker = get_value(data, 'NextKeyMarker')
    result.next_version_id_marker = get_value(data, 'NextVersionIdMarker')
    result.delimiter = get_value(data, 'Delimiter')
    result.max_keys = get_value(data, 'MaxKeys', lambda x: int(x))

    if get_value(data, 'EncodingType'):
        result.encoding_type = get_value(data, 'EncodingType')
    else:
        result.encoding_type = 'url'

    if get_value(data, 'IsTruncated'):
        result.is_truncated = get_value(data, 'IsTruncated')
    else:
        result.is_truncated = False

    common_prefix_list = get_value(data, 'CommonPrefixes') or []
    for common_prefix in common_prefix_list:
        result.common_prefix_list.append(CommonPrefixInfo(get_value(common_prefix, 'Prefix')))

    object_list = get_value(data, 'Versions') or []
    for object in object_list:
        last_modified = get_value(object, 'LastModified')
        if last_modified:
            last_modified = parse_modify_time_to_utc_datetime(last_modified)
        object_info = ObjectVersionInfo(
            get_value(object, 'Key'),
            get_value(object, 'IsLatest'),
            last_modified,
            get_etag(object),
            get_value(object, 'Size', lambda x: int(x)),
            get_value(object, 'StorageClass'),
            get_value(object, 'VersionId')
        )
        owner_info = get_value(object, 'Owner')
        if owner_info:
            object_info.owner = UserInfo(
                get_value(owner_info, "ID"),
                get_value(owner_info, 'DisplayName')
            )
        result.version_list.append(object_info)

    delete_marker_list = get_value(data, 'DeleteMarkers') or []
    for delete_marker in delete_marker_list:
        delete_marker_info = DeleteMarkerInfo(
            get_value(delete_marker, 'Key'),
            get_value(delete_marker, 'IsLatest'),
            get_value(delete_marker, 'LastModified'),
            get_value(delete_marker, 'VersionId')
        )
        owner_info = get_value(delete_marker, 'Owner')
        if owner_info:
            delete_marker_info.owner = UserInfo(
                get_value(owner_info, "ID"),
                get_value(owner_info, 'DisplayName')
            )
        result.delete_marker_list.append(delete_marker_info)
    return result


def convert_delete_objects_result(resp):
    result = DeleteObjectsResult(resp)
    data = json.loads(resp.read())

    delete_list = get_value(data, 'Deleted') or []
    for delete in delete_list:
        result.deleted_list.append(DeletedObjectInfo(
            get_value(delete, 'Key'),
            get_value(delete, 'VersionId'),
            get_value(delete, 'DeleteMarker'),
            get_value(delete, 'DeleteMarkerVersionId')
        ))
    err_list = get_value(data, 'Error') or []
    for err in err_list:
        result.error_list.append(DeletedErrInfo(
            get_value(err, 'Code'),
            get_value(err, 'Message'),
            get_value(err, 'Key'),
            get_value(err, 'VersionId')
        ))
    return result


def convert_get_object_acl_result(resp):
    result = GetObjectAclResult(resp)
    data = json.loads(resp.read())

    result.owner = UserInfo(
        get_value(data['Owner'], 'ID'),
        get_value(data['Owner'], 'DisplayName'),
    )

    grant_list = data['Grants'] or []
    for grant in grant_list:
        result.grant_list.append(GrantInfo(
            get_value(grant['Grantee'], 'ID'),
            get_value(grant['Grantee'], 'DisplayName'),
            get_value(grant['Grantee'], 'Type'),
            get_value(grant['Grantee'], 'Canned'),
            get_value(grant, 'Permission'),
        ))
    return result


def convert_list_buckets_output(resp: Response) -> ListBucketsOutput:
    output = ListBucketsOutput(resp)
    data = json.loads(resp.read())
    output.owner = Owner(
        get_value(data['Owner'], 'ID'),
        get_value(data['Owner'], 'Name'),
    )

    bkt_list = get_value(data, 'Buckets') or []
    for bkt in bkt_list:
        output.buckets.append(ListedBucket(
            get_value(bkt, 'Name'),
            get_value(bkt, 'Location'),
            get_value(bkt, 'CreationDate'),
            get_value(bkt, 'ExtranetEndpoint'),
            get_value(bkt, 'IntranetEndpoint')))
    return output


def convert_get_object_acl_output(resp: Response) -> GetObjectACLOutput:
    pass


def convert_head_object_output(resp: Response) -> HeadObjectOutput:
    output = HeadObjectOutput(resp)
    output.content_type = get_value(resp.headers, 'content-type')
    output.content_length = get_value(resp.headers, 'content-length', lambda x: int(x))
    output.etag = get_etag(resp.headers)
    output.version_id = get_value(resp.headers, 'x-tos-version-id')
    output.sse_algorithm = get_value(resp.headers, 'x-tos-server-side-encryption-customer-algorithm')
    output.sse__key_md5 = get_value(resp.headers, 'x-tos-server-side-encryption-customer-key-md5')
    output.website_redirect_location = get_value(resp.headers, 'x-tos-website-redirect-location')
    output.hash_crc64_ecma = get_value(resp.headers, 'x-tos-hash-crc64ecma', lambda x: int(x))
    output.storage_class = StorageClassType(get_value(resp.headers, 'x-tos-storage-class'))
    output.meta = CaseInsensitiveDict()
    output.object_type = get_value(resp.headers, 'x-tos-object-type')
    if not output.object_type:
        output.object_type = 'Normal'
    for k in resp.headers:
        if k.startswith('x-tos-meta-'):
            output.meta[k[11:]] = resp.headers[k]

    output.last_modified = get_value(resp.headers, 'last-modified')
    if output.last_modified:
        output.last_modified = parse_gmt_time_to_utc_datetime(output.last_modified)
    output.expires = get_value(resp.headers, 'expires')
    if output.expires:
        output.expires = parse_gmt_time_to_utc_datetime(output.expires)

    if get_value(resp.headers, 'x-tos-delete-marker'):
        output.delete_marker = True
    else:
        output.delete_marker = False


def convert_list_object_versions_output(resp):
    result = ListObjectVersionsOutput(resp)
    data = json.loads(resp.read())

    result.name = get_value(data, 'Name')
    result.prefix = get_value(data, 'Prefix')
    result.key_marker = get_value(data, 'KeyMarker')
    result.version_id_marker = get_value(data, 'VersionIdMarker')
    result.next_key_marker = get_value(data, 'NextKeyMarker')
    result.next_version_id_marker = get_value(data, 'NextVersionIdMarker')
    result.delimiter = get_value(data, 'Delimiter')
    result.max_keys = get_value(data, 'MaxKeys', int)

    if get_value(data, 'EncodingType'):
        result.encoding_type = get_value(data, 'EncodingType')
    else:
        result.encoding_type = 'url'

    if get_value(data, 'IsTruncated'):
        result.is_truncated = get_value(data, 'IsTruncated')
    else:
        result.is_truncated = False

    common_prefix_list = get_value(data, 'CommonPrefixes') or []
    for common_prefix in common_prefix_list:
        result.common_prefixes.append(CommonPrefixInfo(get_value(common_prefix, 'Prefix')))

    object_list = get_value(data, 'Versions') or []
    for object in object_list:
        last_modified = get_value(object, 'LastModified')
        if last_modified:
            last_modified = parse_modify_time_to_utc_datetime(last_modified)
        object_info = ListedObjectVersion(
            key=get_value(object, 'Key'),
            last_modified=last_modified,
            etag=get_etag(object),
            size=get_value(object, 'Size'),
            storage_class=StorageClassType(get_value(object, 'StorageClass')),
            version_id=get_value(object, 'VersionId'),
            hash_crc64_ecma=get_value(object, "HashCrc64ecma", lambda x: int(x))
        )
        owner_info = get_value(object, 'Owner')
        if owner_info:
            object_info.owner = Owner(
                get_value(owner_info, "ID"),
                get_value(owner_info, 'DisplayName')
            )
        result.versions.append(object_info)

    delete_marker_list = get_value(data, 'DeleteMarkers') or []
    for delete_marker in delete_marker_list:
        delete_marker_info = DeleteMarkerInfo(
            get_value(delete_marker, 'Key'),
            get_value(delete_marker, 'IsLatest'),
            get_value(delete_marker, 'LastModified'),
            get_value(delete_marker, 'VersionId')
        )
        owner_info = get_value(delete_marker, 'Owner')
        if owner_info:
            delete_marker_info.owner = Owner(
                get_value(owner_info, "ID"),
                get_value(owner_info, 'DisplayName')
            )
        result.delete_markers.append(delete_marker_info)

    return result
