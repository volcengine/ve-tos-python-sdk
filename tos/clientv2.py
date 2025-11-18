# -*- coding: utf-8 -*-
import base64
import hashlib
import http.client
import json
import math
import os
import platform
import random
import shutil
import socket
import sys
import tempfile
import time
import traceback
import urllib.parse
import uuid
from datetime import datetime
from typing import Dict

import requests
from requests.structures import CaseInsensitiveDict
from urllib3.util import connection
from urllib3.util.connection import _set_socket_options
from typing import List

from . import TosClient
from . import __version__
from . import exceptions, utils
from .auth import AnonymousAuth, CredentialProviderAuth
from .checkpoint import (CheckPointStore, _BreakpointDownloader,
                         _BreakpointUploader, _BreakpointResumableCopyObject)
from .safe_map import SafeMapFIFO
from .client import _make_virtual_host_url, _make_virtual_host_uri, _get_virtual_host, _get_host, _get_scheme
from .consts import (GMT_DATE_FORMAT, SLEEP_BASE_TIME, UNSIGNED_PAYLOAD,
                     WHITE_LIST_FUNCTION, CALLBACK_FUNCTION, BUCKET_TYPE_FNS, BUCKET_TYPE_HNS)
from .credential import StaticCredentialsProvider
from .enum import (ACLType, AzRedundancyType, DataTransferType, HttpMethodType,
                   MetadataDirectiveType, StorageClassType, UploadEventType, VersioningStatusType, CopyEventType,
                   TaggingDirectiveType,InventoryIncludedObjType,SemanticQueryType)
from .exceptions import TosClientError, TosServerError, TosError
from .http import Request, Response
from .json_utils import (to_complete_multipart_upload_request,
                         to_put_acl_request, to_delete_multi_objects_request, to_put_bucket_cors_request,
                         to_put_bucket_mirror_back, to_put_bucket_lifecycle, to_put_tagging, to_fetch_object,
                         to_put_replication, to_put_bucket_website, to_put_bucket_notification, to_put_custom_domain,
                         to_put_bucket_real_time_log, to_restore_object, to_bucket_encrypt, to_put_fetch_object,
                         to_put_bucket_notification_type2, to_simple_query, to_semantic_query)
from .log import get_logger
from .models2 import (AbortMultipartUpload, AppendObjectOutput,
                      CompleteMultipartUploadOutput, CopyObjectOutput,
                      CreateBucketOutput, CreateMultipartUploadOutput,
                      DeleteBucketOutput, DeleteObjectOutput,
                      DeleteObjectsOutput, DownloadPartInfo,
                      GetObjectACLOutput, GetObjectOutput, HeadBucketOutput,
                      HeadObjectOutput, ListBucketsOutput,
                      ListMultipartUploadsOutput, ListObjectsOutput,
                      ListPartsOutput, Owner, PartInfo, PreSignedURLOutput,
                      PutObjectACLOutput, PutObjectOutput, SetObjectMetaOutput,
                      UploadFileOutput, UploadPartCopyOutput, UploadPartOutput,
                      _PartToDo, PutBucketCorsOutput, DeleteBucketCorsOutput, GetBucketCorsOutput,
                      PutBucketMirrorBackOutPut, PutBucketStorageClassOutput, GetBucketLocationOutput,
                      PutBucketLifecycleOutput, GetBucketLifecycleOutput, DeleteBucketLifecycleOutput,
                      GetBucketPolicyOutput, DeleteBucketPolicy, DeleteBucketMirrorBackOutput,
                      GetBucketMirrorBackOutput, PutBucketPolicyOutPut, PutObjectTaggingOutput, GetObjectTaggingOutPut,
                      DeleteObjectTaggingOutput, PutBucketACLOutput, GetBucketACLOutput, ContentLengthRange,
                      ListObjectVersionsOutput, FetchObjectOutput, PutFetchTaskOutput,
                      PreSignedPostSignatureOutPut, PutBucketReplicationOutput, GetBucketReplicationOutput,
                      DeleteBucketReplicationOutput, PutBucketVersioningOutput, GetBucketVersionOutput,
                      RedirectAllRequestsTo, IndexDocument, ErrorDocument, RoutingRules, PutBucketWebsiteOutput,
                      PutBucketNotificationOutput, GetBucketNotificationOutput, CustomDomainRule,
                      PutBucketCustomDomainOutput, ListBucketCustomDomainOutput, DeleteCustomDomainOutput,
                      PutBucketRealTimeLogOutput, RealTimeLogConfiguration,
                      DeleteBucketRealTimeLog, GetBucketWebsiteOutput, ResumableCopyObjectOutput,
                      PreSignedPolicyURlInputOutput, ListObjectType2Output, ListObjectsIterator, GetBucketRealTimeLog,
                      PolicySignatureCondition, RestoreObjectOutput, RestoreJobParameters, RenameObjectOutput,
                      PutBucketRenameOutput, DeleteBucketRenameOutput, GetBucketRenameOutput, PutBucketTaggingOutput,
                      DeleteBucketTaggingOutput, GetBucketTaggingOutput, PutSymlinkOutput, GetSymlinkOutput,
                      GenericInput, GetFetchTaskOutput, BucketEncryptionRule, GetBucketEncryptionOutput,
                      DeleteBucketEncryptionOutput, PutBucketEncryptionOutput, PutBucketNotificationType2Output,
                      GetBucketNotificationType2Output, FileStatusOutput, ModifyObjectOutput, SetObjectExpiresOutput,
                      PutBucketInventoryOutput, GetBucketInventoryOutput, ListBucketInventoryOutput,
                      DeleteBucketInventoryOutput,
                      BucketInventoryConfiguration, QueryOrderType, AggregationRequest, QueryRequest, SimpleQueryOutput,
                      SemanticQueryOutput, ReplicationRule)
from .thread_ctx import consume_body
from .utils import (SizeAdapter, _make_copy_source,
                    _make_range_string, _make_upload_part_file_content,
                    _ReaderAdapter, generate_http_proxies, get_content_type,
                    get_parent_directory_from_File, get_value, init_content, patch_content,
                    meta_header_encode, to_bytes, to_str,
                    to_unicode, init_path, DnsCacheService, check_enum_type, check_part_size, check_part_number,
                    check_client_encryption_algorithm, check_server_encryption_algorithm, try_make_file_dir,
                    _IterableAdapter, init_checkpoint_dir, resolve_ip_list, _get_control_host,
                    UploadEventHandler, ResumableCopyObject, DownloadEventHandler, LogInfo, content_disposition_encode,
                    _build_user_agent)

_dns_cache = DnsCacheService()
_orig_create_connection = connection.create_connection
USER_AGENT = 've-tos-python-sdk/{0}({1}/{2};{3})'.format(__version__.__version__, sys.platform, platform.machine(),
                                                         platform.python_version())
UNDEFINED = 'undefined'

BASE_RETRY_DELAY_TIME = 500


def _get_create_bucket_headers(ACL: ACLType, AzRedundancy: AzRedundancyType, GrantFullControl, GrantRead, GrantReadACP,
                               GrantWrite, GrantWriteACP, StorageClass: StorageClassType, ProjectName, BucketType):
    headers = {}
    if ACL:
        headers['x-tos-acl'] = ACL.value
    if GrantFullControl:
        headers['x-tos-grant-full-control'] = GrantFullControl
    if GrantRead:
        headers['x-tos-grant-read'] = GrantRead
    if GrantReadACP:
        headers['x-tos-grant-read-acp'] = GrantReadACP
    if GrantWrite:
        headers['x-tos-grant-write'] = GrantWrite
    if GrantWriteACP:
        headers['x-tos-grant-write-acp'] = GrantWriteACP
    if StorageClass:
        headers['x-tos-storage-class'] = StorageClass.value
    if AzRedundancy:
        headers['x-tos-az-redundancy'] = AzRedundancy.value
    if ProjectName:
        headers['x-tos-project-name'] = ProjectName
    if BucketType:
        headers['x-tos-bucket-type'] = BucketType
    return headers


def _get_copy_object_headers(ACL, CacheControl, ContentDisposition, ContentEncoding, ContentLanguage,
                             ContentType, CopySource, CopySourceIfMatch, CopySourceIfModifiedSince,
                             CopySourceIfNoneMatch, CopySourceIfUnmodifiedSince, Expires, GrantFullControl,
                             GrantRead, GrantReadACP, GrantWriteACP, Metadata, MetadataDirective,
                             SSECustomerAlgorithm, SSECustomerKey, SSECustomerKeyMD5, server_side_encryption,
                             website_redirect_location, storage_class: StorageClassType,
                             SSECAlgorithm, SSECKey, SSECKeyMD5, TrafficLimit, ForbidOverwrite, IfMatch,
                             DisableEncodingMeta,Tagging,TaggingDirective,ObjectExpires):
    headers = {}
    if Metadata:
        for k in Metadata:
            headers['x-tos-meta-' + k] = Metadata[k]
        if not DisableEncodingMeta:
            headers = meta_header_encode(headers)
    if isinstance(CopySource, str):
        headers['x-tos-copy-source'] = CopySource
    elif isinstance(CopySource, dict):
        copy_source = CopySource['Bucket'] + '/' + urllib.parse.quote(CopySource['Key'], '/~')
        if 'VersionId' in CopySource:
            copy_source = copy_source + '?versionId=' + CopySource['VersionId']
        headers['x-tos-copy-source'] = copy_source
    if MetadataDirective:
        headers['x-tos-metadata-directive'] = MetadataDirective.value
    if CacheControl:
        headers['cache-control'] = CacheControl
    if ContentDisposition:
        headers['content-disposition'] = ContentDisposition if DisableEncodingMeta else content_disposition_encode(
            ContentDisposition)
    if ContentEncoding:
        headers['content-encoding'] = ContentEncoding
    if ContentLanguage:
        headers['content-language'] = ContentLanguage
    if ContentType:
        headers['content-type'] = ContentType
    if Expires:
        headers['expires'] = Expires.strftime(GMT_DATE_FORMAT)
    if ACL:
        headers['x-tos-acl'] = ACL.value
    if GrantFullControl:
        headers['x-tos-grant-full-control'] = GrantFullControl
    if GrantRead:
        headers['x-tos-grant-read'] = GrantRead
    if GrantReadACP:
        headers['x-tos-grant-read-acp'] = GrantReadACP
    if GrantWriteACP:
        headers['x-tos-grant-write-acp'] = GrantWriteACP
    if CopySourceIfMatch:
        headers['x-tos-copy-source-if-match'] = CopySourceIfMatch
    if CopySourceIfModifiedSince:
        headers['x-tos-copy-source-if-modified-since'] = CopySourceIfModifiedSince.strftime(GMT_DATE_FORMAT)
    if CopySourceIfNoneMatch:
        headers['x-tos-copy-source-if-none-match'] = CopySourceIfNoneMatch
    if CopySourceIfUnmodifiedSince:
        headers['x-tos-copy-source-if-unmodified-since'] = CopySourceIfUnmodifiedSince.strftime(GMT_DATE_FORMAT)
    if SSECustomerAlgorithm:
        headers['x-tos-copy-source-server-side-encryption-customer-algorithm'] = SSECustomerAlgorithm
    if SSECustomerKey:
        headers['x-tos-copy-source-server-side-encryption-customer-key'] = SSECustomerKey
    if SSECustomerKeyMD5:
        headers['x-tos-copy-source-server-side-encryption-customer-key-MD5'] = SSECustomerKeyMD5
    if server_side_encryption:
        headers['x-tos-server-side-encryption'] = server_side_encryption
    if website_redirect_location:
        headers['x-tos-website-redirect-location'] = website_redirect_location
    if storage_class:
        headers['x-tos-storage-class'] = storage_class.value
    if SSECAlgorithm:
        headers['x-tos-server-side-encryption-customer-algorithm'] = SSECAlgorithm
    if SSECKey:
        headers['x-tos-server-side-encryption-customer-key'] = SSECKey
    if SSECKeyMD5:
        headers['x-tos-server-side-encryption-customer-key-MD5'] = SSECKeyMD5
    if TrafficLimit:
        headers['x-tos-traffic-limit'] = str(TrafficLimit)
    if ForbidOverwrite:
        headers['x-tos-forbid-overwrite'] = ForbidOverwrite
    if IfMatch:
        headers['x-tos-if-match'] = IfMatch
    if Tagging:
        headers['x-tos-tagging'] = Tagging
    if TaggingDirective:
        headers['x-tos-tagging-directive'] = TaggingDirective.value
    if ObjectExpires:
        headers['x-tos-object-expires'] = str(ObjectExpires)

    return headers


def _get_list_object_params(Delimiter, EncodingType, Marker, MaxKeys, Prefix, Reverse, FetchMeta):
    params = {}
    if Delimiter:
        params['delimiter'] = Delimiter
    if EncodingType:
        params['encoding-type'] = EncodingType
    if MaxKeys:
        params['max-keys'] = MaxKeys
    if Prefix:
        params['prefix'] = Prefix
    if Marker:
        params['marker'] = Marker

    if Reverse:
        params['reverse'] = Reverse
    if FetchMeta:
        params['fetch-meta'] = FetchMeta
    params['x-tos-bucket-type'] = 'hns'
    return params


def _get_list_object_version_params(Delimiter, EncodingType, KeyMarker, MaxKeys, Prefix, VersionIdMarker, FetchMeta):
    params = {'versions': ''}
    if Delimiter:
        params['delimiter'] = Delimiter
    if EncodingType:
        params['encoding-type'] = EncodingType
    if MaxKeys:
        params['max-keys'] = MaxKeys
    if Prefix:
        params['prefix'] = Prefix
    if KeyMarker:
        params['key-marker'] = KeyMarker
    if VersionIdMarker:
        params['version-id-marker'] = VersionIdMarker
    if FetchMeta:
        params['fetch-meta'] = FetchMeta
    return params


def _get_list_object_v2_params(Delimiter, Start_After, ContinueToken, Reverse, MaxKeys, EncodingType, Prefix,
                               FetchMeta):
    params = {'list-type': '2', "fetch-owner": "true"}
    if Delimiter:
        params['delimiter'] = Delimiter
    if EncodingType:
        params['encoding-type'] = EncodingType
    if MaxKeys:
        params['max-keys'] = MaxKeys
    if Start_After:
        params['start-after'] = Start_After
    if ContinueToken:
        params['continuation-token'] = ContinueToken
    if Reverse:
        params['reverse'] = Reverse
    if Prefix:
        params['prefix'] = Prefix
    if FetchMeta:
        params['fetch-meta'] = FetchMeta
    return params


def _get_list_multipart_uploads_params(Delimiter, EncodingType, KeyMarker, MaxUploads, Prefix,
                                       UploadIdMarker):
    params = {'uploads': ''}
    if Delimiter:
        params['delimiter'] = Delimiter
    if EncodingType:
        params['encoding-type'] = EncodingType
    if MaxUploads:
        params['max-uploads'] = MaxUploads
    if Prefix:
        params['prefix'] = Prefix
    if KeyMarker:
        params['key-marker'] = KeyMarker
    if UploadIdMarker:
        params['upload-id-marker'] = UploadIdMarker
    return params


def _get_list_parts_params(MaxParts, PartNumberMarker, UploadId):
    params = {'uploadId': UploadId}
    if MaxParts:
        params['max-parts'] = MaxParts
    if PartNumberMarker:
        params['part-number-marker'] = PartNumberMarker
    return params


def _get_complete_upload_part_headers(CompleteAll, Callback, CallbackVar, ForbidOverwrite):
    headers = {}
    if CompleteAll:
        headers['x-tos-complete-all'] = 'yes'
    if Callback:
        headers['x-tos-callback'] = Callback
    if CallbackVar:
        headers['x-tos-callback-var'] = CallbackVar
    if ForbidOverwrite:
        headers['x-tos-forbid-overwrite'] = ForbidOverwrite
    return headers


def _get_upload_part_copy_headers(CopySource, CopySourceIfMatch, CopySourceIfModifiedSince,
                                  CopySourceIfNoneMatch, CopySourceIfUnmodifiedSince, CopySourceRange,
                                  CopySourceSSECAlgorithm, CopySourceSSECKey, CopySourceSSECKeyMD5,
                                  SSECAlgorithm, SSECKey, SSECKeyMD5, TrafficLimit):
    headers = {}
    if isinstance(CopySource, str):
        headers['x-tos-copy-source'] = CopySource
    elif isinstance(CopySource, dict):
        copy_source = CopySource['Bucket'] + '/' + urllib.parse.quote(CopySource['Key'], '/~')
        if 'VersionId' in CopySource:
            copy_source = copy_source + '?versionId=' + CopySource['VersionId']
        headers['x-tos-copy-source'] = copy_source
    if CopySourceIfMatch:
        headers['x-tos-copy-source-if-match'] = CopySourceIfMatch
    if CopySourceIfModifiedSince:
        headers['x-tos-copy-source-if-modified-since'] = CopySourceIfModifiedSince.strftime(GMT_DATE_FORMAT)
    if CopySourceIfNoneMatch:
        headers['x-tos-copy-source-if-none-match'] = CopySourceIfNoneMatch
    if CopySourceIfUnmodifiedSince:
        headers['x-tos-copy-source-if-unmodified-since'] = CopySourceIfUnmodifiedSince.strftime(GMT_DATE_FORMAT)
    if CopySourceRange:
        headers['x-tos-copy-source-range'] = CopySourceRange

    if CopySourceSSECAlgorithm:
        headers['x-tos-copy-source-server-side-encryption-customer-algorithm'] = CopySourceSSECAlgorithm
    if CopySourceSSECKey:
        headers['x-tos-copy-source-server-side-encryption-customer-key'] = CopySourceSSECKey
    if CopySourceSSECKeyMD5:
        headers['x-tos-copy-source-server-side-encryption-customer-key-MD5'] = CopySourceSSECKeyMD5

    if SSECAlgorithm:
        headers['x-tos-server-side-encryption-customer-algorithm'] = SSECAlgorithm
    if SSECKey:
        headers['x-tos-server-side-encryption-customer-key'] = SSECKey
    if SSECKeyMD5:
        headers['x-tos-server-side-encryption-customer-key-MD5'] = SSECKeyMD5
    if TrafficLimit:
        headers['x-tos-traffic-limit'] = str(TrafficLimit)
    return headers


def _get_put_object_headers(recognize_content_type, ACL, CacheControl, ContentDisposition, ContentEncoding,
                            ContentLanguage, ContentLength, ContentMD5, ContentSha256, ContentType, Expires,
                            GrantFullControl, GrantRead, GrantReadACP, GrantWriteACP, Key, Metadata,
                            SSECustomerAlgorithm, SSECustomerKey, SSECustomerKeyMD5, ServerSideEncryption, StorageClass,
                            WebsiteRedirectLocation, TrafficLimit, Callback, CallbackVar, ForbidOverwrite, IfMatch,
                            DisableEncodingMeta,Tagging,ObjectExpires,ImageOperations):
    headers = {}
    if Metadata:
        for k in Metadata:
            headers['x-tos-meta-' + k] = Metadata[k]
        if not DisableEncodingMeta:
            headers = meta_header_encode(headers)
    if ContentLength:
        headers['Content-Length'] = str(ContentLength)
    if ACL:
        headers['x-tos-acl'] = ACL.value
    if GrantFullControl:
        headers['x-tos-grant-full-control'] = GrantFullControl
    if GrantRead:
        headers['x-tos-grant-read'] = GrantRead
    if GrantReadACP:
        headers['x-tos-grant-read-acp'] = GrantReadACP
    if GrantWriteACP:
        headers['x-tos-grant-write-acp'] = GrantWriteACP
    if ContentMD5:
        headers['Content-MD5'] = ContentMD5
    if CacheControl:
        headers['cache-control'] = CacheControl
    if ContentDisposition:
        headers['content-disposition'] = ContentDisposition if DisableEncodingMeta else content_disposition_encode(
            ContentDisposition)
    if ContentEncoding:
        headers['content-encoding'] = ContentEncoding
    if ContentLanguage:
        headers['content-language'] = ContentLanguage
    if ContentType:
        headers['content-type'] = ContentType
    elif recognize_content_type:
        headers['content-type'] = get_content_type(Key)
    if Expires:
        headers['expires'] = Expires.strftime(GMT_DATE_FORMAT)
    if SSECustomerAlgorithm:
        headers['x-tos-server-side-encryption-customer-algorithm'] = SSECustomerAlgorithm
    if SSECustomerKey:
        headers['x-tos-server-side-encryption-customer-key'] = SSECustomerKey
    if SSECustomerKeyMD5:
        headers['x-tos-server-side-encryption-customer-key-md5'] = SSECustomerKeyMD5
    if WebsiteRedirectLocation:
        headers['x-tos-website-redirect-location'] = WebsiteRedirectLocation
    if StorageClass:
        headers['x-tos-storage-class'] = StorageClass.value
    if ServerSideEncryption:
        headers['x-tos-server-side-encryption'] = ServerSideEncryption
    if ContentSha256:
        headers['x-tos-content-sha256'] = ContentSha256
    if TrafficLimit:
        headers['x-tos-traffic-limit'] = str(TrafficLimit)
    if Callback:
        headers['x-tos-callback'] = Callback
    if CallbackVar:
        headers['x-tos-callback-var'] = CallbackVar
    if ForbidOverwrite:
        headers['x-tos-forbid-overwrite'] = ForbidOverwrite
    if IfMatch:
        headers['x-tos-if-match'] = IfMatch
    if Tagging:
        headers['x-tos-tagging'] = Tagging
    if ObjectExpires:
        headers['x-tos-object-expires'] = str(ObjectExpires)
    if ImageOperations:
        headers['x-tos-image-operations'] = ImageOperations
    return headers


def _get_object_headers(IfMatch, IfModifiedSince, IfNoneMatch, IfUnmodifiedSince, Range, SSECustomerAlgorithm,
                        SSECustomerKey, SSECustomerKeyMD5, TrafficLimit):
    headers = {}
    if IfMatch:
        headers['If-Match'] = IfMatch
    if IfModifiedSince:
        headers['If-Modified-Since'] = IfModifiedSince.strftime(GMT_DATE_FORMAT)
    if IfNoneMatch:
        headers['If-None-Match'] = IfNoneMatch
    if IfUnmodifiedSince:
        headers['If-Unmodified-Since'] = IfUnmodifiedSince.strftime(GMT_DATE_FORMAT)
    if SSECustomerAlgorithm:
        headers['x-tos-server-side-encryption-customer-algorithm'] = SSECustomerAlgorithm
    if SSECustomerKey:
        headers['x-tos-server-side-encryption-customer-key'] = SSECustomerKey
    if SSECustomerKeyMD5:
        headers['x-tos-server-side-encryption-customer-key-md5'] = SSECustomerKeyMD5
    if Range:
        headers['Range'] = Range
    if TrafficLimit:
        headers['x-tos-traffic-limit'] = str(TrafficLimit)

    return headers


def _get_object_params(ResponseCacheControl, ResponseContentDisposition, ResponseContentEncoding,
                       ResponseContentLanguage, ResponseContentType, ResponseExpires, VersionId, Process,
                       SaveAsBucket, SaveAsObject, DisableEncodingMeta):
    params = {}
    if VersionId:
        params['versionId'] = VersionId
    if ResponseCacheControl:
        params['response-cache-control'] = ResponseCacheControl
    if ResponseContentDisposition:
        params[
            'response-content-disposition'] = ResponseContentDisposition if DisableEncodingMeta else urllib.parse.quote(
            ResponseContentDisposition)
    if ResponseContentEncoding:
        params['response-content-encoding'] = ResponseContentEncoding
    if ResponseContentLanguage:
        params['response-content-language'] = ResponseContentLanguage
    if ResponseContentType:
        params['response-content-type'] = ResponseContentType
    if ResponseExpires:
        params['response-expires'] = ResponseExpires.strftime(GMT_DATE_FORMAT)
    if Process:
        params['x-tos-process'] = Process
    if SaveAsBucket:
        params["x-tos-save-bucket"] = SaveAsBucket
    if SaveAsObject:
        params["x-tos-save-object"] = SaveAsObject
    return params


def _get_modify_object_headers_params(recognize_content_type, acl, cache_control, content_disposition,
                                      content_encoding, content_language, content_length, content_type, expires,
                                      grant_full_control, grant_read, grant_read_ACP, grant_write_ACP, key, metadata,
                                      storage_class, website_redirect_location, traffic_limit, if_match,
                                      disable_encoding_meta):
    headers = {}
    if metadata:
        for k in metadata:
            headers['x-tos-meta-' + k] = metadata[k]
        if not disable_encoding_meta:
            headers = meta_header_encode(headers)

    if acl:
        headers['x-tos-acl'] = acl.value
    if grant_full_control:
        headers['x-tos-grant-full-control'] = grant_full_control
    if grant_read:
        headers['x-tos-grant-read'] = grant_read
    if grant_read_ACP:
        headers['x-tos-grant-read-acp'] = grant_read_ACP
    if grant_write_ACP:
        headers['x-tos-grant-write-acp'] = grant_write_ACP
    if cache_control:
        headers['cache-control'] = cache_control

    if content_disposition:
        headers['content-disposition'] = content_disposition if disable_encoding_meta else content_disposition_encode(
            content_disposition)

    if content_encoding:
        headers['content-encoding'] = content_encoding
    if content_language:
        headers["content-language"] = content_language
    if content_type:
        headers["content-type"] = content_type

    elif recognize_content_type:
        headers['content-type'] = get_content_type(key)
    if expires:
        headers["expires"] = expires.strftime(GMT_DATE_FORMAT)
    if website_redirect_location:
        headers['x-tos-website-redirect-location'] = website_redirect_location
    if storage_class:
        headers['x-tos-storage-class'] = storage_class.value
    if if_match:
        headers['x-tos-if-match'] = if_match
    if traffic_limit:
        headers['x-tos-traffic-limit'] = str(traffic_limit)
    if content_length:
        headers['Content-Length'] = str(content_length)
    return headers


def _get_append_object_headers_params(recognize_content_type, ACL, CacheControl, ContentDisposition,
                                      ContentEncoding, ContentLanguage, ContentLength, ContentType, Expires,
                                      GrantFullControl, GrantRead, GrantReadACP, GrantWriteACP, Key, Metadata,
                                      StorageClass, WebsiteRedirectLocation, TrafficLimit, IfMatch,
                                      DisableEncodingMeta,ObjectExpires):
    headers = {}
    if Metadata:
        for k in Metadata:
            headers['x-tos-meta-' + k] = Metadata[k]
        if not DisableEncodingMeta:
            headers = meta_header_encode(headers)
    if ACL:
        headers['x-tos-acl'] = ACL.value
    if GrantFullControl:
        headers['x-tos-grant-full-control'] = GrantFullControl
    if GrantRead:
        headers['x-tos-grant-read'] = GrantRead
    if GrantReadACP:
        headers['x-tos-grant-read-acp'] = GrantReadACP
    if GrantWriteACP:
        headers['x-tos-grant-write-acp'] = GrantWriteACP
    if CacheControl:
        headers['cache-control'] = CacheControl
    if ContentDisposition:
        headers['content-disposition'] = ContentDisposition if DisableEncodingMeta else content_disposition_encode(
            ContentDisposition)
    if ContentEncoding:
        headers['content-encoding'] = ContentEncoding
    if ContentLanguage:
        headers['content-language'] = ContentLanguage
    if ContentType:
        headers['content-type'] = ContentType
    elif recognize_content_type:
        headers['content-type'] = get_content_type(Key)
    if Expires:
        headers['expires'] = Expires.strftime(GMT_DATE_FORMAT)
    if WebsiteRedirectLocation:
        headers['x-tos-website-redirect-location'] = WebsiteRedirectLocation
    if StorageClass:
        headers['x-tos-storage-class'] = StorageClass.value
    if ContentLength:
        headers['Content-Length'] = str(ContentLength)
    if TrafficLimit:
        headers['x-tos-traffic-limit'] = str(TrafficLimit)
    if IfMatch:
        headers['x-tos-if-match'] = IfMatch
    if ObjectExpires:
        headers['x-tos-object-expires'] = str(ObjectExpires)
    return headers


def _get_create_multipart_upload_headers(recognize_content_type, ACL, CacheControl, ContentDisposition, ContentEncoding,
                                         ContentLanguage, ContentType, Expires, GrantFullControl, GrantRead,
                                         GrantReadACP, GrantWriteACP, Key, Metadata, SSECustomerAlgorithm,
                                         SSECustomerKey, SSECustomerKeyMD5, ServerSideEncryption,
                                         WebsiteRedirectLocation, StorageClass: StorageClassType, ForbidOverwrite,
                                         DisableEncodingMeta,Tagging,ObjectExpires):
    headers = {}
    if Metadata:
        for k in Metadata:
            headers['x-tos-meta-' + k] = Metadata[k]
        if not DisableEncodingMeta:
            headers = meta_header_encode(headers)
    if ACL:
        headers['x-tos-acl'] = ACL.value
    if GrantFullControl:
        headers['x-tos-grant-full-control'] = GrantFullControl
    if GrantRead:
        headers['x-tos-grant-read'] = GrantRead
    if GrantReadACP:
        headers['x-tos-grant-read-acp'] = GrantReadACP
    if GrantWriteACP:
        headers['x-tos-grant-write-acp'] = GrantWriteACP
    if CacheControl:
        headers['cache-control'] = CacheControl
    if ContentDisposition:
        headers['content-disposition'] = ContentDisposition if DisableEncodingMeta else content_disposition_encode(
            ContentDisposition)
    if ContentEncoding:
        headers['content-encoding'] = ContentEncoding
    if ContentLanguage:
        headers['content-language'] = ContentLanguage
    if ContentType:
        headers['content-type'] = ContentType
    elif recognize_content_type:
        headers['content-type'] = get_content_type(Key)
    if Expires:
        headers['expires'] = Expires.strftime(GMT_DATE_FORMAT)
    if SSECustomerAlgorithm:
        headers['x-tos-server-side-encryption-customer-algorithm'] = SSECustomerAlgorithm
    if SSECustomerKey:
        headers['x-tos-server-side-encryption-customer-key'] = SSECustomerKey
    if SSECustomerKeyMD5:
        headers['x-tos-server-side-encryption-customer-key-md5'] = SSECustomerKeyMD5
    if WebsiteRedirectLocation:
        headers['x-tos-website-redirect-location'] = WebsiteRedirectLocation
    if ServerSideEncryption:
        headers['x-tos-server-side-encryption'] = ServerSideEncryption
    if StorageClass:
        headers['x-tos-storage-class'] = StorageClass.value
    if ForbidOverwrite:
        headers['x-tos-forbid-overwrite'] = ForbidOverwrite
    if Tagging:
        headers['x-tos-tagging'] = Tagging
    if ObjectExpires:
        headers['x-tos-object-expires'] = str(ObjectExpires)
    return headers


def _get_set_object_meta_headers(recognize_content_type, cache_control, content_disposition, content_encoding,
                                 content_language, content_type, expires, key, meta, disable_encoding_meta):
    headers = {}
    if meta:
        for k in meta:
            headers['x-tos-meta-' + k] = meta[k]
        if not disable_encoding_meta:
            headers = meta_header_encode(headers)
    if cache_control:
        headers['cache-control'] = cache_control
    if content_disposition:
        headers['content-disposition'] = content_disposition if disable_encoding_meta else content_disposition_encode(
            content_disposition)
    if content_encoding:
        headers['content-encoding'] = content_encoding
    if content_language:
        headers['content-language'] = content_language
    if content_type:
        headers['content-type'] = content_type
    elif recognize_content_type:
        headers['content-type'] = get_content_type(key)
    if expires:
        headers['expires'] = expires.strftime(GMT_DATE_FORMAT)
    return headers


def _get_put_object_acl_headers(ACL, GrantFullControl, GrantRead, GrantReadACP, GrantWriteACP):
    return _get_put_acl_headers(ACL, GrantFullControl, GrantRead, GrantReadACP, None, GrantWriteACP)


def _get_put_bucket_acl_headers(ACL, GrantFullControl, GrantRead, GrantReadACP, GrantWrite, GrantWriteACP):
    return _get_put_acl_headers(ACL, GrantFullControl, GrantRead, GrantReadACP, GrantWrite, GrantWriteACP)


def _get_put_acl_headers(ACL, GrantFullControl, GrantRead, GrantReadACP, GrantWrite, GrantWriteACP):
    headers = {}
    if ACL:
        headers['x-tos-acl'] = ACL.value
    if GrantFullControl:
        headers['x-tos-grant-full-control'] = GrantFullControl
    if GrantRead:
        headers['x-tos-grant-read'] = GrantRead
    if GrantReadACP:
        headers['x-tos-grant-read-acp'] = GrantReadACP
    if GrantWrite:
        headers['x-tos-grant-write'] = GrantWrite
    if GrantWriteACP:
        headers['x-tos-grant-write-acp'] = GrantWriteACP
    return headers


def _get_put_symlink_headers(TargetKey, TargetBucket, ACL, StorageClass, Metadata, ForbidOverwrite,
                             DisableEncodingMeta):
    headers = {"x-tos-symlink-target": urllib.parse.quote(TargetKey, '/~')}
    if TargetBucket:
        headers["x-tos-symlink-bucket"] = TargetBucket
    if ACL:
        headers['x-tos-acl'] = ACL.value
    if StorageClass:
        headers['x-tos-storage-class'] = StorageClass.value
    if Metadata:
        for k in Metadata:
            headers['x-tos-meta-' + k] = Metadata[k]
        if not DisableEncodingMeta:
            headers = meta_header_encode(headers)
    if ForbidOverwrite:
        headers['x-tos-forbid-overwrite'] = ForbidOverwrite
    return headers


def _get_upload_part_headers(content_length, content_md5, server_side_encryption, ssec_algorithm, ssec_key,
                             ssec_key_md5, traffic_limit):
    headers = {}
    if content_length:
        headers['Content-Length'] = str(content_length)
    if content_md5:
        headers['Content-MD5'] = content_md5
    if ssec_algorithm:
        headers['x-tos-server-side-encryption-customer-algorithm'] = ssec_algorithm
    if ssec_key:
        headers['x-tos-server-side-encryption-customer-key'] = ssec_key
    if ssec_key_md5:
        headers['x-tos-server-side-encryption-customer-key-md5'] = ssec_key_md5
    if server_side_encryption:
        headers['x-tos-server-side-encryption'] = server_side_encryption
    if traffic_limit:
        headers['x-tos-traffic-limit'] = str(traffic_limit)

    return headers


def _get_fetch_headers(storage_class, acl, grant_full_control,
                       grant_read, grant_read_acp, grant_write_acp, meta,
                       ssec_customer_algorithm,
                       ssec_customer_key, sse_customer_key_md5, disable_encoding_meta):
    headers = {}
    if meta:
        for k in meta:
            headers['x-tos-meta-' + k] = meta[k]
        if not disable_encoding_meta:
            headers = meta_header_encode(headers)
    if acl:
        headers['x-tos-acl'] = acl.value
    if grant_full_control:
        headers['x-tos-grant-full-control'] = grant_full_control
    if grant_read:
        headers['x-tos-grant-read'] = grant_read
    if grant_read_acp:
        headers['x-tos-grant-read-acp'] = grant_read_acp
    if grant_write_acp:
        headers['x-tos-grant-write-acp'] = grant_write_acp
    if ssec_customer_algorithm:
        headers['x-tos-server-side-encryption-customer-algorithm'] = ssec_customer_algorithm
    if ssec_customer_key:
        headers['x-tos-server-side-encryption-customer-key'] = ssec_customer_key
    if sse_customer_key_md5:
        headers['x-tos-server-side-encryption-customer-key-md5'] = sse_customer_key_md5
    if storage_class:
        headers['x-tos-storage-class'] = storage_class.value

    return headers


def _valid_upload_checkpoint(bucket, store: CheckPointStore, key: str, modify_time, part_size) -> bool:
    if os.path.exists(store.path(bucket, key)):
        content = store.get(key=key, bucket=bucket)
        if content and content["file_info"]['last_modified'] == modify_time and content['part_size'] == part_size:
            return True

    return False


def _valid_download_checkpoint(bucket, store: CheckPointStore, key: str, etag: str, part_size, version_id) -> bool:
    if os.path.exists(store.path(bucket, key)):
        content = store.get(key=key, bucket=bucket, version_id=version_id)
        if content:
            object_info = content['object_info']
            if etag == object_info['etag'] and content['part_size'] == part_size:
                return True

    return False


def _valid_copyobject_checkpoint(bucket, store: CheckPointStore, key: str, etag: str, part_size, src_bucket=None,
                                 src_key=None, version_id=None) -> bool:
    if os.path.exists(store.path(bucket, key, src_bucket=src_bucket, src_key=src_key, versionId=version_id)):
        content = store.get(key=key, bucket=bucket, src_bucket=src_bucket, src_key=src_key, version_id=version_id)
        if content:
            object_info = content['copy_source_object_info']
            if etag == object_info['etag'] and content['part_size'] == part_size:
                return True
    return False


def _get_parts_to_upload(size, part_size, parts_uploaded):
    all_parts = _get_parts_of_task(size, part_size)
    if not parts_uploaded:
        return all_parts

    all_parts_map = dict((p.part_number, p) for p in all_parts)

    for uploaded in parts_uploaded:
        if uploaded.part_number in all_parts_map:
            del all_parts_map[uploaded.part_number]

    return all_parts_map.values()


def _get_parts_to_download(size, part_size, parts_downloaded):
    all_parts = _get_parts_of_task(size, part_size)
    if not parts_downloaded:
        return all_parts

    all_parts_map = dict((p.part_number, p) for p in all_parts)

    for download in parts_downloaded:
        if download.part_number in all_parts_map:
            del all_parts_map[download.part_number]

    return all_parts_map.values()


import functools
from . import log


def high_latency_log(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        res = None
        ex = None
        try:
            res = f(*args, **kwargs)
            return res
        except TosError as e:
            ex = e
            raise e
        finally:
            if len(args) <= 0 or not isinstance(args[0], TosClientV2):
                return

            threshold = args[0].high_latency_log_threshold
            if threshold <= 0:
                return

            try:
                total = consume_body()
                # 不足 1KB 当 1KB 计算
                if total < 1024:
                    total = 1024
                # 耗时，单位：秒
                cost = time.perf_counter() - start
                rate = total / 1024 / cost
                # 传输速率小于 threshold 且耗时超过 500 毫秒
                if cost > 0 and rate < threshold and cost * 1000 > 500:
                    # 包含 HTTP 状态码、RequestID、接口调用总耗时
                    pf = get_logger().warning
                    if get_logger().getEffectiveLevel() < log.DEBUG or get_logger().getEffectiveLevel() > log.WARNING:
                        pf = print

                    if res:
                        pf(
                            'high latency request: exec httpCode: {}, requestId: {}, usedTime: {} s'.format(
                                res.status_code,
                                res.request_id,
                                cost))
                    else:
                        pf(
                            'high latency request: exception: {}, usedTime:{} s'.format(ex, cost))
            except Exception:
                # ignore Exception
                pass

    return wrapper


def _signed_req(auth, req, host):
    if auth is None:
        return req
    req.headers['Host'] = host
    auth.sign_request(req)
    return req


class TosClientV2(TosClient):
    def __init__(self, ak='', sk='', endpoint='', region='',
                 security_token=None,
                 auto_recognize_content_type=True,
                 max_retry_count=3,
                 request_timeout=30,  # deprecated
                 max_connections=1024,
                 enable_crc=True,
                 connection_time=10,
                 enable_verify_ssl=True,
                 dns_cache_time=15,
                 proxy_host: str = None,
                 proxy_port: int = None,
                 proxy_username: str = None,
                 proxy_password: str = None,
                 is_custom_domain: bool = False,
                 high_latency_log_threshold: int = 100,
                 socket_timeout=30,
                 credentials_provider=None,
                 disable_encoding_meta: bool = None,
                 except100_continue_threshold: int = 65536,
                 user_agent_product_name: str = None,
                 user_agent_soft_name: str = None,
                 user_agent_soft_version: str = None,
                 user_agent_customized_key_values: Dict[str, str] = None,
                 control_endpoint: str = ''):

        """创建client

        :param ak: Access Key ID: 访问密钥ID，用于标识用户
        :param sk: Secret Access Key: 与访问密钥ID结合使用的密钥，用于加密签名
        :param security_token: 临时鉴权 Token
        :param endpoint: TOS 服务端域名，完整格式：https://{host}:{port}
        :param region: TOS 服务端所在区域
        :param auto_recognize_content_type: 使用自动识别 MIME 类型，默认为 true，代表开启自动识别 MIME 类型能力
        :param max_retry_count: 请求失败后最大的重试次数。默认3次
        :param request_timeout: deprecated，该参数已不再使用，请使用 socket_timeout 参数
        :param connection_time: 建立连接超时时间，单位：秒，默认 10 秒
        :param max_connections: 连接池中允许打开的最大 HTTP 连接数，默认 1024
        :param enable_crc: 是否开启上传后客户端 CRC 校验，默认为 true
        :param enable_verify_ssl: 是否开启 SSL 证书校验，默认为 true
        :param dns_cache_time: DNS 缓存的有效期，单位：分钟，小于等于 0 时代表关闭 DNS 缓存，默认为 15
        :param proxy_host: 代理服务器的主机地址，当前只支持 http 协议
        :param proxy_port: 代理服务器的端口
        :param proxy_username: 连接代理服务器时使用的用户名
        :param proxy_password: 代理服务使用的密码
        :param is_custom_domain: 是否使用自定义域名，默认为False
        :param high_latency_log_threshold: 大于 0 时，代表开启高延迟日志，单位：KB，默认为 100，当单次请求传输总速率低于该值且总请求耗时大于 500 毫秒时打印 WARN 级别日志
        :param socket_timeout: 连接建立成功后，单个请求的 Socket 读写超时时间，单位：秒，默认 30 秒，参考: https://requests.readthedocs.io/en/latest/user/quickstart/#timeouts
        :param credentials_provider: 通过 credentials_provider 实现永久访问密钥、临时访问密钥、ECS免密登陆、环境变量获取访问密钥等方式
        :param disable_encoding_meta: 是否对用户自定义元数据x-tos-meta-*/Content-Disposition进行编码，默认编码，设置为true时不进行编码
        :param except100_continue_threshold: 大于0时，表示上传对象相关接口对与待上传数据长度大于该阈值的请求（无法预测数据长度的情况统一判断为大于阈值）开启100-continue机制，单位字节，默认65536
        :param user_agent_product_name: 业务方/产品名
        :param user_agent_soft_name: user_agent扩展，软件名
        :param user_agent_soft_version: user_agent扩展，软件版本号
        :param user_agent_customized_key_values: user_agent扩展，自定义扩展 KV 键值对
        :param control_endpoint: TOS 服务端控制面域名，完整格式：https://{host}:{port}
        :return TosClientV2:
        """

        endpoint = endpoint if isinstance(endpoint, str) else endpoint.decode() if isinstance(endpoint, bytes) else str(
            endpoint)

        endpoint = endpoint.strip()

        if control_endpoint:
            control_endpoint = control_endpoint.strip()


        if utils.is_s3_endpoint(endpoint):
            raise TosClientError("invalid endpoint, please use Tos endpoint rather than S3 endpoint")
        if credentials_provider is not None and (ak != "" or sk != ""):
            raise TosClientError("credentials_provider, ak, sk both")

        if ak == "" and sk == "" and credentials_provider is None:
            super(TosClientV2, self).__init__(auth=AnonymousAuth(ak, sk, region, sts=security_token),
                                              endpoint=endpoint,
                                              recognize_content_type=auto_recognize_content_type,
                                              connection_pool_size=max_connections,
                                              connect_timeout=connection_time,
                                              control_endpoint=control_endpoint)
        else:
            if credentials_provider is None:
                credentials_provider = StaticCredentialsProvider(ak, sk, security_token)
            super(TosClientV2, self).__init__(auth=CredentialProviderAuth(credentials_provider, region),
                                              endpoint=endpoint,
                                              recognize_content_type=auto_recognize_content_type,
                                              connection_pool_size=max_connections,
                                              connect_timeout=connection_time,
                                              control_endpoint=control_endpoint)

        self.max_retry_count = max_retry_count if max_retry_count >= 0 else 0
        self.dns_cache_time = dns_cache_time * 60 if dns_cache_time > 0 else 0
        self.request_timeout = request_timeout
        self.connection_time = connection_time if connection_time > 0 else 10
        self.enable_verify_ssl = enable_verify_ssl
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.enable_crc = enable_crc
        self.proxies = generate_http_proxies(proxy_host, proxy_port, proxy_username, proxy_password)
        self.is_custom_domain = is_custom_domain
        self.high_latency_log_threshold = high_latency_log_threshold if high_latency_log_threshold >= 0 else 0
        self.socket_timeout = socket_timeout if socket_timeout > 0 else self.request_timeout if self.request_timeout > 0 else 30
        self.disable_encoding_meta = disable_encoding_meta
        self.except100_continue_threshold = except100_continue_threshold
        self.user_agent = _build_user_agent(USER_AGENT, user_agent_product_name, user_agent_soft_name,
                                            user_agent_soft_version, user_agent_customized_key_values, UNDEFINED)


        # 通过 hook 机制实现in-request log
        self.session.hooks['response'].append(hook_request_log)

        self._start_async_refresh_cache = False
        # 开启DNS缓存
        if self.dns_cache_time is not None and self.dns_cache_time > 0:
            self._start_async_refresh_cache = self._open_dns_cache()
        expiration = random.randint(600, 900)
        self.bucket_type_cache = SafeMapFIFO(max_length=100, default_expiration_sec=expiration)

    def close(self):
        """关闭Client

        :return:
        """
        self.session.close()
        if self._start_async_refresh_cache:
            _dns_cache.shutdown()

    def pre_signed_url(self, http_method: HttpMethodType, bucket: str,
                       key: str = None,
                       expires: int = 3600,
                       header: Dict = None,
                       query: Dict = None,
                       alternative_endpoint: str = None,
                       is_custom_domain: bool = None):
        """生成签名url

        :param http_method: http方法
        :param bucket: 桶名
        :param key: 对象名
        :param expires: 过期时间（单位：秒），链接在当前时间再过expires秒后过期
        :param header: 需要签名的头部信息
        :param query: 需要签名的http查询参数
        :param alternative_endpoint: 签名url:如果该参数不为空，则声称的 signed url 使用该参数作为域名，而不是使用 TOS Client 初始化参数中的 endpoint
        :param is_custom_domain: 是否使用自定义域名，默认为None
        :return
        """
        # if not _is_valid_expires(expires):
        #     raise TosClientError('expires invalid')
        key = to_str(key)
        params = query or {}
        header = header or {}
        endpoint = alternative_endpoint or self.endpoint
        req_bucket = None if self.is_custom_domain is True else bucket
        if is_custom_domain is not None:
            req_bucket = None if is_custom_domain is True else bucket
        req = Request(
            http_method.value,
            _make_virtual_host_url(_get_host(endpoint), _get_scheme(endpoint), req_bucket, key),
            _make_virtual_host_uri(key),
            _get_virtual_host(req_bucket, endpoint),
            params=params,
            headers=header
        )
        signed_url = self.auth.sign_url(req, expires)
        signed_header = req.headers.copy()
        signed_header['host'] = signed_header['Host']
        signed_header.pop('Host')
        return PreSignedURLOutput(signed_url, signed_header)

    def pre_signed_post_signature(self, conditions: [],
                                  bucket: str = None, key: str = None,
                                  expires: int = 3600,
                                  content_length_range: ContentLengthRange = None) -> PreSignedPostSignatureOutPut:
        """ 生成POST上传预签名

        :param conditions: 拼接到 policy中的条件组
        :param bucket: 桶名
        :param key: 对象名
        :param expires: 过期时间
        :param content_length_range: body长度范围
        :return: PreSignedPostSignatureOutPut
        """
        # _is_valid_expires(expires)
        if content_length_range:
            start = content_length_range.start
            end = content_length_range.end
            if start and end and start > end:
                raise TosClientError("invalid content_length_range")

        return self.auth.post_sign(bucket=bucket, key=key, expires=expires, conditions=conditions,
                                   content_length_range=content_length_range)

    def pre_signed_policy_url(self, bucket: str, conditions=None,
                              expires: int = 3600,
                              alternative_endpoint: str = None,
                              is_custom_domain: bool = False):
        """ 携带查询参数 X-Tos-Policy 的 URL预签名
        :param bucket: 桶名
        :param conditions: policy 条件组
        :param expires: 过期时间 默认为 3600秒
        :param alternative_endpoint: 若该参数不为空，使用该参数作为域名
        :param is_custom_domain: 是否使用自定义域名，默认为False
        :param bucket_type : 创建桶的类型，BUCKET_TYPE_FNS/BUCKET_TYPE_HNS
        :return: PreSignedPolicyURlInputOutput
        """
        if conditions is None:
            conditions = []
        # if not _is_valid_expires(expires):
        #     raise TosClientError('expires invalid')
        endpoint = alternative_endpoint or self.endpoint
        conditions.append(PolicySignatureCondition(key='bucket', value=bucket))
        signed_query = self.auth.x_tos_post_sign(expires, conditions)
        if is_custom_domain:
            return PreSignedPolicyURlInputOutput(signed_query, _get_host(endpoint), _get_scheme(endpoint))
        return PreSignedPolicyURlInputOutput(signed_query, _get_host(endpoint), _get_scheme(endpoint), bucket)

    def create_bucket(self, bucket: str,
                      acl: ACLType = None,
                      grant_full_control: str = None,
                      grant_read: str = None,
                      grant_read_acp: str = None,
                      grant_write: str = None,
                      grant_write_acp: str = None,
                      storage_class: StorageClassType = None,
                      az_redundancy: AzRedundancyType = None,
                      project_name: str = None,
                      bucket_type: str = BUCKET_TYPE_FNS,
                      generic_input: GenericInput = None) -> CreateBucketOutput:
        """创建bucket

        桶命名规范（其他接口同）：
            - 桶名字符长度为 3~63 个字符；
            - 桶名字符集包括：小写字母 a-z、数字 0-9 和连字符 '-'；
            - 桶名不能以连字符 '-' 作为开头或结尾；
        SDK 会对依照该规范做校验，如果用户指定的桶名与规范不匹配则报错客户端校验失败 TosClientError。

        :param bucket: 桶名
        :param acl: 访问控制列表，用于管理桶和对象的访问权限
        :param grant_full_control: 对桶具有读、写、读ACP、写ACP的权限
        :param grant_read: 允许被授权者列举桶内对象。
        :param grant_read_acp: 允许被授权者读取桶ACL。
        :param grant_write: 允许被授权者在桶中创建新对象。对于现有对象的桶和对象所有者，允许删除和覆盖这些对象。
        :param grant_write_acp: 允许被授权者写ACP权限。
        :param storage_class: 支持设置桶的默认存储类型
        :param az_redundancy: 支持设置桶的 AZ 属性
        :param project_name: 设置桶所属项目名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: CreateBucketOutput
        """

        _is_valid_bucket_name(bucket)

        check_enum_type(acl=acl, storage_class=storage_class, az_redundancy=az_redundancy)

        headers = _get_create_bucket_headers(acl, az_redundancy,
                                             grant_full_control,
                                             grant_read, grant_read_acp, grant_write,
                                             grant_write_acp, storage_class, project_name, bucket_type)

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, headers=headers,
                         generic_input=generic_input)

        return CreateBucketOutput(resp)

    def get_file_status(self, bucket: str, key: str, project_name: str = None, generic_input: GenericInput = None):
        """查询文件状态

        此接口用于查询HNS桶的文件状态
        如果桶不存在或者没有访问桶的权限，此接口会返回404 Not Found或403 Forbidden状态码的TosServerError。

        :param bucket: 桶名
        :param key: 文件名
        :param project_name: 桶所属项目名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: FileStatusOutput
        """

        _is_valid_bucket_name(bucket)
        headers = {}
        if project_name:
            headers['x-tos-project-name'] = project_name

        bucket_type = self._get_bucket_type(bucket)
        if bucket_type == BUCKET_TYPE_HNS:
            # head
            resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Head.value,
                             headers=headers,
                             generic_input=generic_input)
            return FileStatusOutput(key, bucket_type, resp)
        headers = {}
        query = {"stat": ""}
        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Get.value, headers=headers,
                         params=query, generic_input=generic_input)

        return FileStatusOutput(key, bucket_type, resp)

    def _get_bucket_type(self, bucket: str = None):
        bucket_type = self.bucket_type_cache.get(bucket)
        if bucket_type is None:
            rsp = self.head_bucket(bucket=bucket)
            bucket_type = rsp.bucket_type
            if bucket_type is None:
                bucket_type = BUCKET_TYPE_FNS
            self.bucket_type_cache.put(key=bucket, value=bucket_type)
        return bucket_type

    def head_bucket(self, bucket: str, project_name: str = None,
                    generic_input: GenericInput = None) -> HeadBucketOutput:
        """查询桶元数据

        此接口用于判断桶是否存在和是否有桶的访问权限。
        如果桶不存在或者没有访问桶的权限，此接口会返回404 Not Found或403 Forbidden状态码的TosServerError。

        :param bucket: 桶名
        :param project_name: 桶所属项目名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: HeadBucketOutput
        """
        headers = {}
        if project_name:
            headers['x-tos-project-name'] = project_name
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Head.value, headers=headers,
                         generic_input=generic_input)

        return HeadBucketOutput(resp)

    def delete_bucket(self, bucket: str, generic_input: GenericInput = None):
        """删除桶.

        删除已经创建的桶，删除桶之前，要保证桶是空桶，即桶中的对象和段数据已经被清除掉。

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteBucketOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value,
                         generic_input=generic_input)

        return DeleteBucketOutput(resp)

    def list_buckets(self, project_name: str = None, generic_input: GenericInput = None,
                     bucket_type: str = None) -> ListBucketsOutput:
        """ 列举桶

        :param project_name: 桶所属项目名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :param bucket_type: 桶类型
        :return: ListBucketsOutput
        """
        headers = {}
        if project_name:
            headers['x-tos-project-name'] = project_name
        if bucket_type:
            headers['x-tos-bucket-type'] = bucket_type
        resp = self._req(method=HttpMethodType.Http_Method_Get.value, headers=headers, generic_input=generic_input)
        result = ListBucketsOutput(resp)
        return result

    def copy_object(self, bucket: str, key: str, src_bucket: str, src_key: str,
                    src_version_id: str = None,
                    cache_control: str = None,
                    content_disposition: str = None,
                    content_encoding: str = None,
                    content_language: str = None,
                    content_type: str = None,
                    expires: datetime = None,
                    copy_source_if_match: str = None,
                    copy_source_if_modified_since: datetime = None,
                    copy_source_if_none_match: str = None,
                    copy_source_if_unmodified_since: datetime = None,
                    copy_source_ssec_algorithm: str = None,
                    copy_source_ssec_key: str = None,
                    copy_source_ssec_key_md5: str = None,
                    server_side_encryption: str = None,
                    acl: ACLType = ACLType.ACL_Private,
                    grant_full_control: str = None,
                    grant_read: str = None,
                    grant_read_acp: str = None,
                    grant_write_acp: str = None,
                    metadata_directive: MetadataDirectiveType = None,
                    meta: Dict = None,
                    website_redirect_location: str = None,
                    storage_class: StorageClassType = None,
                    ssec_algorithm: str = None,
                    ssec_key: str = None,
                    ssec_key_md5: str = None,
                    traffic_limit: int = None,
                    forbid_overwrite: bool = None,
                    if_match: str = None,
                    generic_input: GenericInput = None,
                    tagging:str = None,
                    tagging_directive:TaggingDirectiveType = None,
                    object_expires: int = None,):
        """拷贝对象

        此接口用于在同一地域下同一个桶或者不同桶之间对象的拷贝操作。桶开启多版本场景，如果需要恢复对象的早期版本为当前版本，
        您只需将对象的早期版本拷贝到同一个桶中，TOS会将该对象对应早期版本置为当前版本。

        :param bucket: 目标桶名
        :param src_bucket: 原桶名
        :param key: 目标对象名
        :param src_key: 原目标名
        :param acl: private'|'public-read'|'public-read-write'|'authenticated-read'|'bucket-owner-read'|
               'bucket-owner-full-control'
        :param src_version_id: 原数据 version
        :param cache_control: 缓存控制
        :param content_disposition: 展示形式
        :param content_encoding: 报文编码
        :param content_language: 报文语言
        :param content_type: 数据类型
        :param copy_source_if_match: 源对象匹配时，才返回对象
        :param copy_source_if_modified_since: datetime(2021, 1, 1)
        :param copy_source_if_none_match: 源对象不匹配时，才返回对象
        :param copy_source_if_unmodified_since: datetime(2021, 1, 1)
        :param expires: datetime(2021, 1, 1)
        :param grant_full_control:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read_acp:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_write_acp: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param meta: 自定义元数据
        :param metadata_directive: 'COPY'|'REPLACE'
        :param copy_source_ssec_algorithm: 'AES256'
        :param copy_source_ssec_key: 加密密钥
        :param copy_source_ssec_key_md5: 密钥md5值
        :param server_side_encryption: TOS管理密钥的加密方式，可扩展，当前只支持 AES256
        :param website_redirect_location: 可以将获取这个对象的请求重定向到桶内另一个对象或一个外部的URL，TOS将这个值从头域中取出，保存在对象的元数据中。
        :param storage_class: 对象存储类型
        :param ssec_algorithm: 目标对象的加密方式
        :param ssec_key: 目标对象的加密 key
        :param ssec_key_md5: 目标对象加密key的md5值
        :param traffic_limit: 单链接限速
        :param forbid_overwrite: 是否禁止覆盖同名对象，True表示禁止覆盖，False表示允许覆盖
        :param if_match: 目标对象匹配时，才复制对象
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :param tagging: 指定上传对象的标签
        :param tagging_directive: 设置复制对象时对象标签的处理方式
        :param object_expires: 设置对象的过期时间
        :return: CopyObjectOutput
        """
        check_enum_type(acl=acl, metadata_directive=metadata_directive, storage_class=storage_class)

        check_client_encryption_algorithm(copy_source_ssec_algorithm)

        check_client_encryption_algorithm(ssec_algorithm)

        check_server_encryption_algorithm(server_side_encryption)

        copy_source = _make_copy_source(src_bucket, src_key, src_version_id)

        headers = _get_copy_object_headers(acl, cache_control, content_disposition, content_encoding, content_language,
                                           content_type, copy_source, copy_source_if_match,
                                           copy_source_if_modified_since,
                                           copy_source_if_none_match, copy_source_if_unmodified_since, expires,
                                           grant_full_control, grant_read, grant_read_acp, grant_write_acp, meta,
                                           metadata_directive, copy_source_ssec_algorithm, copy_source_ssec_key,
                                           copy_source_ssec_key_md5, server_side_encryption, website_redirect_location,
                                           storage_class, ssec_algorithm, ssec_key, ssec_key_md5, traffic_limit,
                                           forbid_overwrite, if_match, self.disable_encoding_meta,tagging,tagging_directive,
                                           object_expires)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Put.value, headers=headers,
                         generic_input=generic_input)

        return CopyObjectOutput(resp)

    def delete_object(self, bucket: str, key: str, version_id: str = None, recursive: bool = None,
                      generic_input: GenericInput = None):
        """删除对象

        :param bucket: 桶名
        :param key: 对象名
        :param version_id: 版本号
        :param recursive: 是否递归删除
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteObjectOutput
        """
        params = {}
        if recursive is not None:
            params['recursive'] = str(recursive).lower()
        if version_id:
            params['versionId'] = version_id
        resp = self._req(bucket=bucket, key=key, params=params, method=HttpMethodType.Http_Method_Delete.value,
                         generic_input=generic_input)

        return DeleteObjectOutput(resp)

    def delete_multi_objects(self, bucket: str, objects: [], quiet: bool = False, recursive: bool = None,
                             generic_input: GenericInput = None):
        """批量删除对象

        在开启版本控制的桶中，在调用DeleteMultiObjects接口来批量删除对象时，如果在Delete请求中未指定versionId，
        将插入删除标记。如果指定了versionId，将永久删除该对象的指定版本。

        批量删除对象支持的响应方式可以通过quiet进行设置。quiet为false时，是指在返回响应时，
        不管对象是否删除成功都将删除结果包含在响应里；quiet为true时，是指在返回响应时，只返回删除失败的对象结果，
        没有返回的认为删除成功。

        :param bucket: 桶名
        :param objects: 对象名
        :param quiet: 批删之后响应模式
        :param recursive: 是否递归删除，hns桶下有效
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteObjectsOutput
        """

        data = to_delete_multi_objects_request(objects, quiet, recursive)
        data = json.dumps(data)

        headers = {'Content-MD5': to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}

        params = {'delete': ''}
        if recursive is not None:
            params['recursive'] = str(recursive).lower()
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Post.value, data=data, headers=headers,
                         params=params, generic_input=generic_input)

        return DeleteObjectsOutput(resp)

    def get_object_acl(self, bucket: str, key: str,
                       version_id: str = None, generic_input: GenericInput = None) -> GetObjectACLOutput:
        """获取对象的acl

        :param bucket: 桶名
        :param key: 对象名
        :param version_id: 版本号
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetObjectACLOutput

        """
        params = {'acl': ''}
        if version_id:
            params['versionId'] = version_id
        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Get.value, params=params,
                         generic_input=generic_input)

        return GetObjectACLOutput(resp)

    def head_object(self, bucket: str, key: str,
                    version_id: str = None,
                    if_match: str = None,
                    if_modified_since: datetime = None,
                    if_none_match: str = None,
                    if_unmodified_since: datetime = None,
                    ssec_algorithm: str = None,
                    ssec_key: str = None,
                    ssec_key_md5: str = None,
                    generic_input: GenericInput = None) -> HeadObjectOutput:

        """查询对象元数据

        :param bucket: 桶名
        :param key: 对象名
        :param if_match: 只有在匹配时，才返回对象
        :param if_modified_since: datetime(2021, 1, 1)
        :param if_none_match: 只有在不匹配时，才返回对象
        :param if_unmodified_since: datetime(2021, 1, 1)
        :param version_id: 版本号
        :param ssec_algorithm: 'AES256'
        :param ssec_key: 加密密钥
        :param ssec_key_md5: 密钥md5值
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: HeadObjectOutput
        """
        check_client_encryption_algorithm(ssec_algorithm)

        headers = _get_object_headers(if_match, if_modified_since, if_none_match, if_unmodified_since, None,
                                      ssec_algorithm, ssec_key, ssec_key_md5, None)

        params = {}

        if version_id:
            params['versionId'] = version_id
        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Head.value, params=params,
                         headers=headers,
                         generic_input=generic_input)

        return HeadObjectOutput(resp, self.disable_encoding_meta)

    def list_objects(self, bucket: str,
                     prefix: str = None,
                     delimiter: str = None,
                     marker: str = None,
                     max_keys: int = None,
                     reverse: bool = None,
                     encoding_type: str = None,
                     generic_input: GenericInput = None,
                     fetch_meta: bool = None) -> ListObjectsOutput:
        """列举对象

        :param bucket: 桶名
        :param delimiter: 目录分隔符
        :param encoding_type: 返回key编码类型
        :param marker: 分页标志
        :param max_keys: 最大返回数
        :param prefix: 前缀
        :param reverse: 反转列举
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :param fetch_meta: 是否获取对象的自定义meta
        :return: ListObjectsOutput
        """
        params = _get_list_object_params(delimiter, encoding_type, marker, max_keys, prefix, reverse, fetch_meta)

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params=params,
                         generic_input=generic_input)

        return ListObjectsOutput(resp, self.disable_encoding_meta)

    def list_object_versions(self, bucket: str,
                             prefix: str = None,
                             delimiter: str = None,
                             key_marker: str = None,
                             version_id_marker: str = None,
                             max_keys: int = None,
                             encoding_type: str = None,
                             generic_input: GenericInput = None,
                             fetch_meta: bool = None) -> ListObjectVersionsOutput:
        """列举多版本对象

        :param bucket: 桶名
        :param delimiter: 分隔符
        :param encoding_type: 返回key编码类型
        :param key_marker: 分页标志
        :param max_keys: 最大返回值
        :param prefix: 前缀
        :param version_id_marker: 版本号分页标志
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :param fetch_meta: 是否获取对象的自定义meta
        :return: ListObjectVersionsOutput
        """
        params = _get_list_object_version_params(delimiter, encoding_type, key_marker, max_keys, prefix,
                                                 version_id_marker, fetch_meta)

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params=params,
                         generic_input=generic_input)

        return ListObjectVersionsOutput(resp, self.disable_encoding_meta)

    def put_object_acl(self, bucket: str, key: str,
                       version: str = None,
                       acl: ACLType = None,
                       grant_full_control: str = None,
                       grant_read: str = None,
                       grant_read_acp: str = None,
                       grant_write_acp: str = None,
                       owner: Owner = None,
                       grants: [] = None,
                       generic_input: GenericInput = None) -> PutObjectACLOutput:
        """设置对象acl

        :param bucket: 桶名
        :param key: 对象名
        :param version: 对象的版本号。标识更改指定版本的对象ACL。
        :param acl: 对象ACL.default（默认）：Object遵循所在存储空间的访问权限。
                            private：Object是私有资源。只有Object的拥有者和授权用户有该Object的读写权限，其他用户没有权限操作该Object。
                            public-read：Object是公共读资源。只有Object的拥有者和授权用户有该Object的读写权限，其他用户只有该Object的读权限。请谨慎使用该权限。
                            public-read-write：Object是公共读写资源。所有用户都有该Object的读写权限。请谨慎使用该权限。
                            authenticated-read：认证用户读。
                            bucket-owner-read：桶所有者读。
                            bucket-owner-full-control：桶所有者完全权限。
        :param grant_full_control:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read_acp:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_write_acp: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param owner: 桶的拥有者
        :param grants: 访问控制列表.
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域

        return: PutObjectACLOutput
        """

        check_enum_type(acl=acl)
        params = {'acl': ''}
        if version:
            params['versionId'] = version

        headers = _get_put_object_acl_headers(acl, grant_full_control, grant_read, grant_read_acp,
                                              grant_write_acp)

        data = None

        if grants:
            body = to_put_acl_request(owner, grants)
            data = json.dumps(body)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Put.value, params=params,
                         headers=headers, data=data,
                         generic_input=generic_input)

        return PutObjectACLOutput(resp)

    @high_latency_log
    def put_object(self, bucket: str, key: str,
                   content_length: int = None,
                   content_md5: str = None,
                   content_sha256: str = None,
                   cache_control: str = None,
                   content_disposition: str = None,
                   content_encoding: str = None,
                   content_language: str = None,
                   content_type: str = None,
                   expires: datetime = None,
                   acl: ACLType = None,
                   grant_full_control: str = None,
                   grant_read: str = None,
                   grant_read_acp: str = None,
                   grant_writeAcp: str = None,
                   ssec_algorithm: str = None,
                   ssec_key: str = None,
                   ssec_key_md5: str = None,
                   server_side_encryption: str = None,
                   meta: Dict = None,
                   website_redirect_location: str = None,
                   storage_class: StorageClassType = None,
                   data_transfer_listener=None,
                   rate_limiter=None,
                   traffic_limit: int = None,
                   content=None,
                   callback: str = None,
                   callback_var: str = None,
                   forbid_overwrite: bool = None,
                   if_match: str = None,
                   generic_input: GenericInput = None,
                   tagging: str = None,
                   object_expires: int = None,
                   image_operations: str = None) -> PutObjectOutput:
        """上传对象

        :param bucket: 桶名
        :param key: 对象名
        :param acl: 'private'|'public-read'|'public-read-write'|'authenticated-read'|'bucket-owner-read'|
                'bucket-owner-full-control'
        :param content_length: 消息体大小
        :param content_md5: 消息体的md5摘要
        :param content_sha256: 消息体的sha256加密值
        :param cache_control: 缓存控制
        :param content_disposition: 对象被下载时的名称
        :param content_encoding: 下载对象时的内容编码类型。
        :param content_language: 对象下载时的内容语言格式
        :param content_type: 数据类型
        :param expires: datetime(2021, 1, 1)
        :param grant_full_control:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read_acp:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_writeAcp: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param server_side_encryption: TOS 管理密钥的加密方式，可扩展，当前只支持 AES256
        :param meta: 自定义元数据，TOS SDK 会对 Key/Value 包含的中文汉字进行 URL 编码
        :param ssec_algorithm: 客户自定义密钥的加密方式，可扩展，不定义为枚举，当前只支持 AES256，TOS SDK 会做强校验
        :param ssec_key: 加密密钥
        :param ssec_key_md5: 密钥md5值
        :param storage_class: 对象存储类型
        :param website_redirect_location: 可以将获取这个对象的请求重定向到桶内另一个对象或一个外部的URL，TOS将这个值从头域中取出，保存在对象的元数据中。
        :param data_transfer_listener: 进度条特效
        :param rate_limiter: 客户端限速
        :param traffic_limit: 单连接限速
        :param content: 数据
        :param callback: 回调
        :param callback_var: 回调参数
        :param forbid_overwrite: 是否禁止覆盖同名对象，True表示禁止覆盖，False表示允许覆盖
        :param if_match: 只有在匹配时，才put对象
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :param tagging: 指定上传对象的标签
        :param object_expires: 指定上传对象的过期时间，单位：天
        :param image_operations: 上传时支持同时执行图片处理
        :return: PutObjectOutput
        """
        check_client_encryption_algorithm(ssec_algorithm)

        check_server_encryption_algorithm(server_side_encryption)

        check_enum_type(acl=acl, storage_class=storage_class)

        _is_valid_object_name(key)

        headers = _get_put_object_headers(self.recognize_content_type, acl, cache_control, content_disposition,
                                          content_encoding, content_language,
                                          content_length, content_md5, content_sha256, content_type, expires,
                                          grant_full_control, grant_read, grant_read_acp, grant_writeAcp, key, meta,
                                          ssec_algorithm, ssec_key, ssec_key_md5,
                                          server_side_encryption, storage_class, website_redirect_location,
                                          traffic_limit, callback, callback_var, forbid_overwrite, if_match,
                                          self.disable_encoding_meta,tagging,object_expires,image_operations)
        if self.except100_continue_threshold > 0 and (
                content_length is None or content_length > self.except100_continue_threshold):
            headers['Expect'] = "100-continue"

        if content:
            content = init_content(content)
            patch_content(content)

            if data_transfer_listener:
                content = utils.add_progress_listener_func(content, data_transfer_listener)

            if rate_limiter:
                content = utils.add_rate_limiter_func(content, rate_limiter)

            if self.enable_crc:
                content = utils.add_crc_func(content)

        try:
            resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Put.value, data=content,
                             headers=headers, generic_input=generic_input)
            result = PutObjectOutput(resp, callback=callback,image_operation=image_operations)
            if self.enable_crc and content:
                utils.check_crc('put_object', content.crc, result.hash_crc64_ecma, result.request_id)
            return result

        except (TosClientError, TosServerError) as e:
            if data_transfer_listener:
                data_transfer_listener(0, 0, 0, DataTransferType.Data_Transfer_Failed)
            raise e

    def put_object_from_file(self, bucket: str, key: str, file_path: str,
                             content_length: int = None,
                             content_md5: str = None,
                             content_sha256: str = None,
                             cache_control: str = None,
                             content_disposition: str = None,
                             content_encoding: str = None,
                             content_language: str = None,
                             content_type: str = None,
                             expires: datetime = None,
                             acl: ACLType = None,
                             grant_full_control: str = None,
                             grant_read: str = None,
                             grant_read_acp: str = None,
                             grant_writeAcp: str = None,
                             ssec_algorithm: str = None,
                             ssec_key: str = None,
                             ssec_key_md5: str = None,
                             server_side_encryption: str = None,
                             meta: Dict = None,
                             website_redirect_location: str = None,
                             storage_class: StorageClassType = None,
                             data_transfer_listener=None,
                             traffic_limit: int = None,
                             rate_limiter=None,
                             callback: str = None,
                             callback_var: str = None,
                             forbid_overwrite: bool = None,
                             if_match: str = None,
                             generic_input: GenericInput = None) -> PutObjectOutput:
        """上传对象

        :param bucket: 桶名
        :param key: 对象名
        :param acl: 'private'|'public-read'|'public-read-write'|'authenticated-read'|'bucket-owner-read'|
                'bucket-owner-full-control'
        :param content_length: 消息体大小
        :param content_md5: 消息体的md5摘要
        :param content_sha256: 消息体的sha256加密值
        :param cache_control: 缓存控制
        :param content_disposition: 展示形式
        :param content_encoding: 报文编码
        :param content_language: 报文语言
        :param content_type: 数据类型
        :param expires: datetime(2021, 1, 1)
        :param grant_full_control:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read_acp:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_writeAcp: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param server_side_encryption: TOS 管理密钥的加密方式，可扩展，当前只支持 AES256
        :param meta: 自定义元数据，TOS SDK 会对 Key/Value 包含的中文汉字进行 URL 编码
        :param ssec_algorithm: 客户自定义密钥的加密方式，可扩展，不定义为枚举，当前只支持 AES256，TOS SDK 会做强校验
        :param ssec_key: 加密密钥
        :param ssec_key_md5: 密钥md5值
        :param storage_class: 对象存储类型
        :param website_redirect_location: 可以将获取这个对象的请求重定向到桶内另一个对象或一个外部的URL，TOS将这个值从头域中取出，保存在对象的元数据中。
        :param data_transfer_listener: 进度条特效
        :param rate_limiter: 客户端限速
        :param file_path: 文件路径
        :param traffic_limit: 单连接限速
        :param callback: 回调
        :param callback_var: 回调参数
        :param forbid_overwrite: 是否禁止覆盖同名对象，True表示禁止覆盖，False表示允许覆盖
        :param if_match: 只有在匹配时，才put对象
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutObjectOutput
        """
        check_client_encryption_algorithm(ssec_algorithm)

        check_server_encryption_algorithm(server_side_encryption)

        if not os.path.exists(file_path) or (os.path.isdir(file_path)):
            raise TosClientError('invalid file path, the file does not exist')

        with open(to_unicode(file_path), 'rb') as f:
            f = init_content(f, can_reset=True, init_offset=0)
            return self.put_object(bucket, key, content_length, content_md5, content_sha256, cache_control,
                                   content_disposition, content_encoding, content_language,
                                   content_type, expires, acl, grant_full_control, grant_read, grant_read_acp,
                                   grant_writeAcp, ssec_algorithm, ssec_key,
                                   ssec_key_md5, server_side_encryption, meta, website_redirect_location, storage_class,
                                   data_transfer_listener, rate_limiter, traffic_limit, f, callback, callback_var,
                                   forbid_overwrite, if_match, generic_input)

    def _modify_object(self, bucket: str, key: str, offset: int,
                       content=None,
                       content_length: int = None,
                       cache_control: str = None,
                       content_disposition: str = None,
                       content_encoding: str = None,
                       content_language: str = None,
                       content_type: str = None,
                       expires: datetime = None,
                       acl: ACLType = None,
                       grant_full_control: str = None,
                       grant_read: str = None,
                       grant_read_acp: str = None,
                       grant_write_acp: str = None,
                       meta: Dict = None,
                       website_redirect_location: str = None,
                       storage_class: StorageClassType = None,
                       data_transfer_listener=None,
                       rate_limiter=None,
                       pre_hash_crc64_ecma: int = None,
                       traffic_limit: int = None,
                       if_match: str = None,
                       generic_input: GenericInput = None):

        check_enum_type(acl=acl, storage_class=storage_class)
        _is_valid_object_name(key)

        params = {"modify": ""}
        if offset is not None:
            params['offset'] = offset
        headers = _get_modify_object_headers_params(self.recognize_content_type, acl, cache_control,
                                                    content_disposition,
                                                    content_encoding,
                                                    content_language, content_length, content_type,
                                                    expires, grant_full_control, grant_read, grant_read_acp,
                                                    grant_write_acp, key, meta, storage_class,
                                                    website_redirect_location, traffic_limit, if_match,
                                                    self.disable_encoding_meta)

        if self.except100_continue_threshold > 0 and (
                content_length is None or content_length > self.except100_continue_threshold):
            headers['Expect'] = "100-continue"
        if content:
            content = init_content(content)
            patch_content(content)
            if isinstance(content, _ReaderAdapter) and content.size == 0:
                raise TosClientError('Your proposed append content is smaller than the minimum allowed size')

            if data_transfer_listener:
                content = utils.add_progress_listener_func(content, data_transfer_listener)

            if rate_limiter:
                content = utils.add_rate_limiter_func(content, rate_limiter)

            if content and self.enable_crc and pre_hash_crc64_ecma is not None:
                content = utils.add_crc_func(content, init_crc=pre_hash_crc64_ecma)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Post.value, data=content,
                         headers=headers, params=params, generic_input=generic_input)

        result = ModifyObjectOutput(resp)

        if self.enable_crc and result.hash_crc64_ecma is not None and pre_hash_crc64_ecma is not None:
            utils.check_crc('append object', content.crc, result.hash_crc64_ecma, resp.request_id)

        return result

    @high_latency_log
    def append_object(self, bucket: str, key: str, offset: int,
                      content=None,
                      content_length: int = None,
                      cache_control: str = None,
                      content_disposition: str = None,
                      content_encoding: str = None,
                      content_language: str = None,
                      content_type: str = None,
                      expires: datetime = None,
                      acl: ACLType = None,
                      grant_full_control: str = None,
                      grant_read: str = None,
                      grant_read_acp: str = None,
                      grant_write_acp: str = None,
                      meta: Dict = None,
                      website_redirect_location: str = None,
                      storage_class: StorageClassType = None,
                      data_transfer_listener=None,
                      rate_limiter=None,
                      pre_hash_crc64_ecma: int = None,
                      traffic_limit: int = None,
                      if_match: str = None,
                      generic_input: GenericInput = None,
                      object_expires: int = None) -> AppendObjectOutput:
        """追加写对象

        :param bucket: 桶名
        :param key: 对象名
        :param content: 上传内容
        :param cache_control:	指定该对象被下载时网页的缓存行为
        :param content_disposition: 内容呈现方式
        :param offset: 指定从何处进行追加。
        :param acl: 'private'|'public-read'|'public-read-write'|'authenticated-read'|'bucket-owner-read'|
        :param content_encoding: 编码方式
        :param content_language: 上传内容语言类型
        :param content_type: 内容类型
        :param expires: 有效时间
        :param content_length: 内容大小
        :param meta: 自定义元数据
        :param grant_full_control:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read_acp:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_write_acp: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param website_redirect_location: 当桶设置了Website配置，可以将获取这个对象的请求重定向到桶内另一个对象或一个外部的URL，TOS将这个值从头域中取出，保存在对象的元数据中。
        :param storage_class: 第一次追加写对象时，可以使用该头域，设置目的对象的存储类型。如果未设置，则目的对象的存储类型，和所在桶的默认存储类型保持一致
        :param data_transfer_listener: 进度条特效
        :param rate_limiter: 客户端限速
        :param traffic_limit: 单连接限制速
        :param pre_hash_crc64_ecma: 上一次crc值，第一次上传设置为0
        :param if_match: 只有在匹配时，才追加对象
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :param object_expires: 设置对象过期时间
        :return: AppendObjectOutput
        """

        check_enum_type(acl=acl, storage_class=storage_class)

        _is_valid_object_name(key)

        params = {'append': '', 'offset': offset}

        bucket_type = self._get_bucket_type(bucket)
        if bucket_type == BUCKET_TYPE_HNS:
            # modify_object时，如果对象不存在，创建对象
            if offset == 0:
                if content is not None and content_length is None:
                    raise TosClientError("tos: The method need param content_length.")
                try:
                    head_rsp = self.head_object(bucket=bucket, key=key)
                    if head_rsp.content_length > 0:
                        raise TosClientError("tos: The object offset of this modify not matched.")
                    if if_match == "":
                        if_match = head_rsp.etag
                except TosServerError as e:
                    if e.status_code == 404:
                        if if_match:
                            raise e
                        put_output = self.put_object(bucket=bucket, key=key, content=content,
                                                     content_length=content_length,
                                                     data_transfer_listener=data_transfer_listener,
                                                     rate_limiter=rate_limiter, forbid_overwrite=True,
                                                     object_expires=object_expires)
                        if content_length is None:
                            content_length = 0
                        result = AppendObjectOutput(put_output.resp)
                        result.next_append_offset = content_length
                        return result
                    else:
                        raise e
            modify_output = self._modify_object(bucket=bucket, key=key, offset=offset, content=content,
                                                content_length=content_length, cache_control=cache_control,
                                                content_disposition=content_disposition,
                                                content_encoding=content_encoding,
                                                content_language=content_language, content_type=content_type,
                                                expires=expires,
                                                acl=acl, grant_full_control=grant_full_control,
                                                grant_read=grant_read,
                                                grant_read_acp=grant_read_acp, grant_write_acp=grant_write_acp,
                                                meta=meta,
                                                website_redirect_location=website_redirect_location,
                                                storage_class=storage_class,
                                                data_transfer_listener=data_transfer_listener,
                                                rate_limiter=rate_limiter,
                                                pre_hash_crc64_ecma=pre_hash_crc64_ecma,
                                                traffic_limit=traffic_limit,
                                                if_match=if_match, generic_input=generic_input)
            result = AppendObjectOutput(modify_output.resp)
            result.next_append_offset = modify_output.next_modify_offset
            return result

        headers = _get_append_object_headers_params(self.recognize_content_type, acl, cache_control,
                                                    content_disposition,
                                                    content_encoding,
                                                    content_language, content_length, content_type,
                                                    expires, grant_full_control, grant_read, grant_read_acp,
                                                    grant_write_acp, key, meta, storage_class,
                                                    website_redirect_location, traffic_limit, if_match,
                                                    self.disable_encoding_meta,object_expires)
        if self.except100_continue_threshold > 0 and (
                content_length is None or content_length > self.except100_continue_threshold):
            headers['Expect'] = "100-continue"

        if content:
            content = init_content(content)
            patch_content(content)
            if isinstance(content, _ReaderAdapter) and content.size == 0:
                raise TosClientError('Your proposed append content is smaller than the minimum allowed size')

            if data_transfer_listener:
                content = utils.add_progress_listener_func(content, data_transfer_listener)

            if rate_limiter:
                content = utils.add_rate_limiter_func(content, rate_limiter)

            if content and self.enable_crc and pre_hash_crc64_ecma is not None:
                content = utils.add_crc_func(content, init_crc=pre_hash_crc64_ecma)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Post.value, data=content,
                         headers=headers, params=params, generic_input=generic_input)

        result = AppendObjectOutput(resp)

        if self.enable_crc and result.hash_crc64_ecma is not None and pre_hash_crc64_ecma is not None:
            utils.check_crc('append object', content.crc, result.hash_crc64_ecma, resp.request_id)

        return result

    def set_object_meta(self, bucket: str, key: str,
                        version_id: str = None,
                        cache_control: str = None,
                        content_disposition: str = None,
                        content_encoding: str = None,
                        content_language: str = None,
                        content_type: str = None,
                        expires: datetime = None,
                        meta: Dict = None,
                        generic_input: GenericInput = None):
        """设置对象元数据

        :param bucket: 桶名
        :param key: 对象名
        :param version_id: 对象的版本号。标识更改指定版本的对象自定义元数据
        :param cache_control: 下载对象时的网页缓存行为
        :param content_disposition: 对象被下载时的名称
        :param content_encoding: 下载对象时的内容编码类型
        :param content_language: 对象下载时的内容语言格式
        :param content_type: 对象内容类型
        :param expires: 下载对象时的网页缓存过期
        :param meta: 要修改的元数据
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: SetObjectMetaOutput
        """

        headers = _get_set_object_meta_headers(self.recognize_content_type, cache_control, content_disposition,
                                               content_encoding, content_language, content_type, expires, key, meta,
                                               self.disable_encoding_meta)

        params = {'metadata': ''}

        if version_id:
            params['versionId'] = version_id

        resp = self._req(bucket, key, HttpMethodType.Http_Method_Post.value,
                         headers=headers, params=params, generic_input=generic_input)

        return SetObjectMetaOutput(resp)

    def get_object(self, bucket: str, key: str,
                   version_id: str = None,
                   if_match: str = None,
                   if_modified_since: datetime = None,
                   if_none_match: str = None,
                   if_unmodified_since: datetime = None,
                   ssec_algorithm: str = None,
                   ssec_key: str = None,
                   ssec_key_md5: str = None,
                   response_cache_control: str = None,
                   response_content_disposition: str = None,
                   response_content_encoding: str = None,
                   response_content_language: str = None,
                   response_content_type: str = None,
                   response_expires: datetime = None,
                   range_start: int = None,
                   range_end: int = None,
                   data_transfer_listener=None,
                   rate_limiter=None,
                   range: str = None,
                   traffic_limit: int = None,
                   process: str = None,
                   save_bucket: str = None,
                   save_object: str = None,
                   generic_input: GenericInput = None) -> GetObjectOutput:

        """下载对象

        :param bucket: 桶名
        :param key: 对象名
        :param if_match: 只有在匹配时，才返回对象
        :param if_modified_since: datetime(2021, 1, 1)
        :param if_none_match: 只有在不匹配时，才返回对象
        :param if_unmodified_since: datetime(2021, 1, 1)
        :param response_cache_control: 指定回包的Cache-Control
        :param response_content_disposition: 指定回包的Content-Disposition
        :param response_content_encoding: 指定回包的Content-Encoding
        :param response_content_language: 指定回包的Content-Language
        :param response_content_type: 指定回包的Content-Type
        :param response_expires: 指定回包的Expires
        :param version_id: 版本号
        :param ssec_algorithm: 'AES256'
        :param ssec_key: 加密密钥
        :param ssec_key_md5: 密钥md5值
        :param data_transfer_listener: 进度条回调函数
        :param rate_limiter: 限速接口
        :param range_start: 指定对象的获取下边界
        :param range_end: 指定对象获取的上边界
        :param range: 查询范围 与range_start range_end 互斥优先使用此字段
        :param traffic_limit: 单连接限速
        :param process: 图片处理参数
        :param save_bucket: 图片处理或者video处理持久化的bucket
        :param save_object: 图片处理或者video处理持久化的对象名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetObjectOutput
        """

        check_client_encryption_algorithm(ssec_algorithm)

        if range is None:
            range = _make_range_string(range_start, range_end)

        headers = _get_object_headers(if_match, if_modified_since, if_none_match, if_unmodified_since, range,
                                      ssec_algorithm, ssec_key, ssec_key_md5, traffic_limit)

        params = _get_object_params(response_cache_control, response_content_disposition, response_content_encoding,
                                    response_content_language, response_content_type, response_expires, version_id,
                                    process, save_bucket, save_object, self.disable_encoding_meta)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Get.value, headers=headers,
                         params=params, generic_input=generic_input)

        return GetObjectOutput(resp, progress_callback=data_transfer_listener, rate_limiter=rate_limiter,
                               enable_crc=self.enable_crc, disable_encoding_meta=self.disable_encoding_meta)

    @high_latency_log
    def _get_object_by_part(self, bucket: str, key: str, part, file, if_match=None, data_transfer_listener=None,
                            rate_limiter=None,
                            ssec_algorithm=None, ssec_key=None, ssec_key_md5=None, version_id=None, traffic_limit=None,
                            generic_input=None):
        result = self.get_object(bucket, key, range_start=part.start, range_end=part.end - 1, if_match=if_match,
                                 data_transfer_listener=data_transfer_listener,
                                 rate_limiter=rate_limiter, ssec_algorithm=ssec_algorithm, ssec_key=ssec_key,
                                 ssec_key_md5=ssec_key_md5, version_id=version_id, traffic_limit=traffic_limit,
                                 generic_input=generic_input)
        patch_content(result)
        utils.copy_and_verify_length(result, file, part.end - part.start, request_id=result.request_id)
        return result

    @high_latency_log
    def get_object_to_file(self, bucket: str, key: str, file_path: str,
                           version_id: str = None,
                           if_match: str = None,
                           if_modified_since: datetime = None,
                           if_none_match: str = None,
                           if_unmodified_since: datetime = None,
                           ssec_algorithm: str = None,
                           ssec_key: str = None,
                           ssec_key_md5: str = None,
                           response_cache_control: str = None,
                           response_content_disposition: str = None,
                           response_content_encoding: str = None,
                           response_content_language: str = None,
                           response_content_type: str = None,
                           response_expires: datetime = None,
                           range_start: int = None,
                           range_end: int = None,
                           data_transfer_listener=None,
                           rate_limiter=None,
                           traffic_limit: int = None,
                           process: str = None,
                           generic_input: GenericInput = None):
        """下载对象到文件

        :param bucket: 桶名
        :param key: 对象名
        :param if_match: 只有在匹配时，才返回对象
        :param if_modified_since: datetime(2021, 1, 1)
        :param if_none_match: 只有在不匹配时，才返回对象
        :param if_unmodified_since: datetime(2021, 1, 1)
        :param response_cache_control: 指定回包的Cache-Control
        :param response_content_disposition: 指定回包的Content-Disposition
        :param response_content_encoding: 指定回包的Content-Encoding
        :param response_content_language: 指定回包的Content-Language
        :param response_content_type: 指定回包的Content-Type
        :param response_expires: 指定回包的Expires
        :param version_id: 版本号
        :param ssec_algorithm: 'AES256'
        :param ssec_key: 加密密钥
        :param ssec_key_md5: 密钥md5值
        :param data_transfer_listener: 进度条回调函数
        :param rate_limiter: 限速接口
        :param range_start: 指定对象的获取下边界
        :param range_end: 指定对象获取的上边界
        :param file_path: 文件路径
        :param traffic_limit: 单连接限速
        :param process: 图片处理参数
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetObjectOutput
        """

        check_client_encryption_algorithm(ssec_algorithm)
        result = self.get_object(bucket=bucket,
                                 key=key,
                                 version_id=version_id,
                                 if_match=if_match,
                                 if_modified_since=if_modified_since,
                                 if_none_match=if_none_match,
                                 if_unmodified_since=if_unmodified_since,
                                 ssec_algorithm=ssec_algorithm,
                                 ssec_key=ssec_key,
                                 ssec_key_md5=ssec_key_md5,
                                 response_cache_control=response_cache_control,
                                 response_content_disposition=response_content_disposition,
                                 response_content_encoding=response_content_encoding,
                                 response_content_language=response_content_language,
                                 response_content_type=response_content_type,
                                 response_expires=response_expires,
                                 range_start=range_start,
                                 range_end=range_end,
                                 data_transfer_listener=data_transfer_listener,
                                 rate_limiter=rate_limiter,
                                 traffic_limit=traffic_limit,
                                 process=process,
                                 generic_input=generic_input)

        patch_content(result)
        if init_path(file_path, key):
            dir = os.path.join(file_path, key)
            os.makedirs(dir, exist_ok=True)
            # 空循环读取数据
            for content in result.content:
                pass
            return result

        if os.path.isdir(file_path):
            file_path = os.path.join(file_path, key)
            try_make_file_dir(file_path)
        tmp_file_path = file_path + ".temp."+str(uuid.uuid4())

        with open(tmp_file_path, 'wb') as f:
            shutil.copyfileobj(result, f)

        os.rename(tmp_file_path, file_path)

        return result

    def create_multipart_upload(self, bucket: str, key: str,
                                encoding_type: str = None,
                                cache_control: str = None,
                                content_disposition: str = None,
                                content_encoding: str = None,
                                content_language: str = None,
                                content_type: str = None,
                                expires: datetime = None,
                                acl: ACLType = None,
                                grant_full_control: str = None,
                                grant_read: str = None,
                                grant_read_acp: str = None,
                                grant_write_acp: str = None,
                                ssec_algorithm: str = None,
                                ssec_key: str = None,
                                ssec_key_md5: str = None,
                                server_side_encryption: str = None,
                                meta: Dict = None,
                                website_redirect_location: str = None,
                                storage_class: StorageClassType = None,
                                forbid_overwrite: bool = None,
                                generic_input: GenericInput = None,
                                tagging:str = None,
                                object_expires: int = None) -> CreateMultipartUploadOutput:
        """初始化分片上传任务

        :param bucket: 桶名
        :param key: 对象名
        :param encoding_type: 指定对返回的内容进行编码的编码类型
        :param cache_control:  是否开启缓存
        :param content_disposition: 对象被下载时的名称
        :param content_encoding: 对象的编码方式
        :param content_language:
        :param content_type: 上传对象类型
        :param expires: 有效时间
        :param acl: 桶访问权限
        :param grant_full_control: 具有对象的读、写、读ACL、写ACL的权限。
        :param grant_read: 允许被授权者读取对象
        :param grant_read_acp: 允许被授权者肚读取对象ACL
        :param grant_write_acp: 允许被收授权者写对象ACL
        :param ssec_algorithm: 指定加密目标对象使用的算法，比如AES256
        :param ssec_key: 指定目标对象的加密密钥
        :param ssec_key_md5: 该头域表示加密目标对象使用的密钥的MD5值。MD5值用于消息完整性检查，确认加密密钥传输过程中没有出错。
        :param server_side_encryption: 设置目标对象的加密方式，如果未设置，默认为非加密对象，取值AES256：
        :param meta: 对象元数据
        :param website_redirect_location: 当桶设置了Website配置，可以将获取这个对象的请求重定向到桶内另一个对象或一个外部的URL，TOS将这个值从头域中取出，保存在对象的元数据中。
        :param storage_class: 存储类型
        :param forbid_overwrite: 是否禁止覆盖同名对象，True表示禁止覆盖，False表示允许覆盖
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :param tagging: 指定上传对象的标签
        :param object_expires: 指定对象过期时间
        return: CreateMultipartUploadOutput
        """
        check_client_encryption_algorithm(ssec_algorithm)

        check_server_encryption_algorithm(server_side_encryption)

        check_enum_type(acl=acl, storage_class=storage_class)

        _is_valid_object_name(key)

        headers = _get_create_multipart_upload_headers(self.recognize_content_type, acl, cache_control,
                                                       content_disposition, content_encoding,
                                                       content_language,
                                                       content_type, expires, grant_full_control,
                                                       grant_read, grant_read_acp, grant_write_acp, key, meta,
                                                       ssec_algorithm, ssec_key, ssec_key_md5,
                                                       server_side_encryption, website_redirect_location, storage_class,
                                                       forbid_overwrite, self.disable_encoding_meta,tagging,object_expires)

        params = {'uploads': ''}
        if encoding_type:
            params['encoding-type'] = encoding_type

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Post.value, params=params,
                         headers=headers, generic_input=generic_input)

        return CreateMultipartUploadOutput(resp)

    def upload_file(self, bucket, key, file_path: str,
                    encoding_type: str = None,
                    cache_control: str = None,
                    content_disposition: str = None,
                    content_encoding: str = None,
                    content_language: str = None,
                    content_type: str = None,
                    expires: datetime = None,
                    acl: ACLType = None,
                    grant_full_control: str = None,
                    grant_read: str = None,
                    grant_read_acp: str = None,
                    grant_write_acp: str = None,
                    ssec_algorithm: str = None,
                    ssec_key: str = None,
                    ssec_key_md5: str = None,
                    server_side_encryption: str = None,
                    meta: Dict = None,
                    website_redirect_location: str = None,
                    storage_class: StorageClassType = None,
                    part_size: int = 20 * 1024 * 1024,
                    task_num: int = 1,
                    enable_checkpoint: bool = True,
                    checkpoint_file: str = None,
                    data_transfer_listener=None,
                    upload_event_listener=None,
                    rate_limiter=None,
                    cancel_hook=None,
                    traffic_limit: int = None,
                    generic_input: GenericInput = None,
                    tagging:str = None):

        """断点续传上传

        :param bucket: 桶名
        :param key: 对象名
        :param encoding_type: 指定对返回的内容进行编码的编码类型
        :param cache_control:  是否开启缓存
        :param content_disposition: 对象被下载时的名称
        :param content_encoding: 对象的编码方式
        :param content_language:
        :param content_type: 上传对象类型
        :param expires: 有效时间
        :param acl: 桶访问权限
        :param grant_full_control: 具有对象的读、写、读ACL、写ACL的权限。
        :param grant_read: 允许被授权者读取对象
        :param grant_read_acp: 允许被授权者肚读取对象ACL
        :param grant_write_acp: 允许被收授权者写对象ACL
        :param ssec_algorithm: 指定加密目标对象使用的算法，比如AES256
        :param ssec_key: 指定目标对象的加密密钥
        :param ssec_key_md5: 该头域表示加密目标对象使用的密钥的MD5值。MD5值用于消息完整性检查，确认加密密钥传输过程中没有出错。
        :param server_side_encryption: 设置目标对象的加密方式，如果未设置，默认为非加密对象，取值AES256：
        :param meta: 对象元数据
        :param website_redirect_location: 当桶设置了Website配置，可以将获取这个对象的请求重定向到桶内另一个对象或一个外部的URL，TOS将这个值从头域中取出，保存在对象的元数据中。
        :param file_path: 待上传的本地文件全路径，只支持文件
        :param part_size: 单个分段大小，默认为20M
        :param task_num: 并发上传线程个数
        :param enable_checkpoint: 是否启用断点传输
        :param checkpoint_file: 断点传输文件全路径
        :param data_transfer_listener: 进度条特性
        :param upload_event_listener: 上传事件回调
        :param rate_limiter: 客户端限速
        :param storage_class: 存储类型
        :param cancel_hook: 支持取消断点任务
        :param traffic_limit: 单连接限速
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :param tagging: 指定上传对象的标签
        :return: CreateMultipartUploadOutput
        """
        check_client_encryption_algorithm(ssec_algorithm)

        check_server_encryption_algorithm(server_side_encryption)

        check_enum_type(acl=acl, storage_class=storage_class)

        check_part_size(part_size)

        # 检查上传文件的有效性
        if not os.path.exists(file_path) or (os.path.isdir(file_path)):
            raise TosClientError('invalid file path, the file does not exist')

        size = os.path.getsize(file_path)

        check_part_number(size, part_size)

        last_modify = os.path.getmtime(file_path)

        dir = ""
        if checkpoint_file:
            dir, file = os.path.split(checkpoint_file)
            os.makedirs(dir, exist_ok=True)
        else:
            dir = get_parent_directory_from_File(os.path.abspath(file_path))

        _, file_name = os.path.split(file_path)
        store = CheckPointStore(dir, file_name, "upload")

        # 创建内部eventHandler
        upload_event_listener = UploadEventHandler(upload_event_listener, bucket, key, os.path.abspath(file_path),
                                                   store.path(bucket, key))
        parts = []
        record = {}
        upload_id = None

        if enable_checkpoint and _valid_upload_checkpoint(bucket=bucket, store=store, key=key,
                                                          modify_time=last_modify, part_size=part_size):
            # upload_id 存在
            record = store.get(bucket=bucket, key=key)

            upload_id = record['upload_id']
            part_updated = []
            for p in record['parts_info']:
                if p['is_completed']:
                    part_updated.append(
                        PartInfo(p['part_number'], p['part_size'], p['offset'], p['etag'], p['hash_crc64ecma'],
                                 p['is_completed']))
            if size == 0:
                parts.append(_PartToDo(part_number=1, start=0, end=0))
            else:
                parts = _get_parts_to_upload(size, part_size, part_updated)
        else:
            # 否则创建分段任务, parts等信息
            create_mult_upload = None

            try:
                create_mult_upload = self.create_multipart_upload(bucket=bucket, key=key, encoding_type=encoding_type,
                                                                  cache_control=cache_control,
                                                                  content_disposition=content_disposition,
                                                                  content_encoding=content_encoding,
                                                                  content_language=content_language,
                                                                  content_type=content_type, expires=expires, acl=acl,
                                                                  grant_full_control=grant_full_control,
                                                                  grant_read=grant_read,
                                                                  grant_read_acp=grant_read_acp,
                                                                  grant_write_acp=grant_write_acp,
                                                                  ssec_algorithm=ssec_algorithm,
                                                                  ssec_key=ssec_key, ssec_key_md5=ssec_key_md5,
                                                                  server_side_encryption=server_side_encryption,
                                                                  meta=meta,
                                                                  website_redirect_location=website_redirect_location,
                                                                  storage_class=storage_class,
                                                                  generic_input=generic_input,
                                                                  tagging=tagging)
            except TosError as e:
                upload_event_listener(UploadEventType.Upload_Event_Create_Multipart_Upload_Failed, e)
                raise e

            upload_id = create_mult_upload.upload_id
            upload_event_listener.upload_id = upload_id

            upload_event_listener(UploadEventType.Upload_Event_Create_Multipart_Upload_Succeed)

            record = {
                'bucket': bucket,
                'key': key,
                'part_size': part_size,
                'upload_id': upload_id,
                'ssec_algorithm': ssec_algorithm,
                'ssec_key_md5': ssec_key_md5,
                'encoding_type': create_mult_upload.encoding_type,
                'file_path': file_path,
                'file_info': {
                    'last_modified': last_modify,
                    'file_size': size,
                },
                'parts_info': []
            }

            store.put(bucket, key, record)
            if size == 0:
                parts.append(_PartToDo(part_number=1, start=0, end=0))
            else:
                parts = _get_parts_to_upload(size, part_size, [])

        uploader = _BreakpointUploader(self, bucket=bucket, key=key, file_path=file_path, store=store,
                                       task_num=task_num, parts_to_update=parts, upload_id=upload_id,
                                       record=record, datatransfer_listener=data_transfer_listener,
                                       upload_event_listener=upload_event_listener, cancel_hook=cancel_hook,
                                       rate_limiter=rate_limiter, size=size, ssec_algorithm=ssec_algorithm,
                                       ssec_key=ssec_key, ssec_key_md5=ssec_key_md5, traffic_limit=traffic_limit,
                                       generic_input=generic_input)

        result = uploader.execute()

        return UploadFileOutput(result, ssec_algorithm, ssec_key_md5, upload_id, record['encoding_type'])

    def resumable_copy_object(self, bucket: str, key: str, src_bucket: str, src_key: str,
                              encoding_type: str = None,
                              cache_control: str = None,
                              content_disposition: str = None,
                              content_encoding: str = None,
                              content_language: str = None,
                              content_type: str = None,
                              expires: datetime = None,
                              acl: ACLType = None,
                              grant_full_control: str = None,
                              grant_read: str = None,
                              grant_read_acp: str = None,
                              grant_write_acp: str = None,
                              ssec_algorithm: str = None,
                              ssec_key: str = None,
                              ssec_key_md5: str = None,
                              server_side_encryption: str = None,
                              meta: Dict = None,
                              website_redirect_location: str = None,
                              storage_class: StorageClassType = None,
                              src_version_id: str = None,
                              copy_source_if_match: str = None,
                              copy_source_if_modified_since: datetime = None,
                              copy_source_if_none_match: str = None,
                              copy_source_if_unmodified_since: datetime = None,
                              copy_source_ssec_algorithm: str = None,
                              copy_source_ssec_key: str = None,
                              copy_source_ssec_key_md5: str = None,
                              part_size: int = 20 * 1024 * 1024,
                              task_num: int = 1,
                              enable_checkpoint: bool = True,
                              checkpoint_file: str = None,
                              copy_event_listener=None,
                              cancel_hook=None,
                              traffic_limit: int = None,
                              generic_input: GenericInput = None) -> ResumableCopyObjectOutput:
        """断点续传复制

        :param bucket: 桶名
        :param key: 对象名
        :param src_bucket: 源桶名
        :param src_key: 源对象名
        :param encoding_type: 指定对返回的内容进行编码的编码类型
        :param cache_control:  是否开启缓存
        :param content_disposition: 对象被下载时的名称
        :param content_encoding: 对象的编码方式
        :param content_language:
        :param content_type: 上传对象类型
        :param expires: 有效时间
        :param acl: 桶访问权限
        :param grant_full_control: 具有对象的读、写、读ACL、写ACL的权限。
        :param grant_read: 允许被授权者读取对象
        :param grant_read_acp: 允许被授权者肚读取对象ACL
        :param grant_write_acp: 允许被收授权者写对象ACL
        :param ssec_algorithm: 指定加密目标对象使用的算法，比如AES256
        :param ssec_key: 指定目标对象的加密密钥
        :param ssec_key_md5: 该头域表示加密目标对象使用的密钥的MD5值。MD5值用于消息完整性检查，确认加密密钥传输过程中没有出错。
        :param server_side_encryption: 设置目标对象的加密方式，如果未设置，默认为非加密对象，取值AES256：
        :param meta: 对象元数据
        :param website_redirect_location: 当桶设置了Website配置，可以将获取这个对象的请求重定向到桶内另一个对象或一个外部的URL，TOS将这个值从头域中取出，保存在对象的元数据中。
        :param storage_class: 存储类型
        :param src_version_id: 源对象版本id
        :param copy_source_if_match: 源对象匹配时，才返回对象
        :param copy_source_if_modified_since: datetime(2021, 1, 1)
        :param copy_source_if_none_match: 源对象不匹配时，才返回对象
        :param copy_source_if_unmodified_since: datetime(2021, 1, 1)
        :param copy_source_ssec_algorithm: 'AES256'
        :param copy_source_ssec_key: 加密密钥
        :param copy_source_ssec_key_md5: 密钥md5值
        :param part_size: 分片大小 默认为 20mb
        :param task_num: 执行任务线程数
        :param enable_checkpoint: 是否开启断点续传
        :param checkpoint_file: 断点续传上传文件夹，在该文件夹下生成断点续传文件
        :param copy_event_listener: 断点续传事件回调
        :param cancel_hook: 取消回调
        :param traffic_limit: 单连接限速
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: ResumableCopyObjectOutput
        """

        check_client_encryption_algorithm(ssec_algorithm)

        check_server_encryption_algorithm(server_side_encryption)

        check_enum_type(acl=acl, storage_class=storage_class)

        check_part_size(part_size)

        head_out = self.head_object(src_bucket, src_key,
                                    version_id=src_version_id,
                                    if_match=copy_source_if_match,
                                    if_modified_since=copy_source_if_modified_since,
                                    if_none_match=copy_source_if_none_match,
                                    if_unmodified_since=copy_source_if_unmodified_since,
                                    ssec_key=copy_source_ssec_key,
                                    ssec_key_md5=copy_source_ssec_key_md5,
                                    ssec_algorithm=copy_source_ssec_algorithm,
                                    generic_input=generic_input)
        if head_out.object_type == 'Symlink':
            copy_output = self.copy_object(bucket, key,
                                           src_bucket=src_bucket,
                                           src_key=src_key,
                                           src_version_id=src_version_id,
                                           cache_control=cache_control,
                                           content_disposition=content_disposition,
                                           content_encoding=content_encoding,
                                           content_language=content_language,
                                           content_type=content_type, expires=expires, acl=acl,
                                           grant_full_control=grant_full_control,
                                           grant_read=grant_read,
                                           grant_read_acp=grant_read_acp,
                                           grant_write_acp=grant_write_acp,
                                           ssec_algorithm=ssec_algorithm,
                                           ssec_key=ssec_key, ssec_key_md5=ssec_key_md5,
                                           server_side_encryption=server_side_encryption,
                                           meta=meta,
                                           website_redirect_location=website_redirect_location,
                                           storage_class=storage_class,
                                           copy_source_if_match=copy_source_if_match,
                                           copy_source_if_none_match=copy_source_if_none_match,
                                           copy_source_if_unmodified_since=copy_source_if_unmodified_since,
                                           copy_source_if_modified_since=copy_source_if_modified_since,
                                           copy_source_ssec_algorithm=copy_source_ssec_algorithm,
                                           copy_source_ssec_key=copy_source_ssec_key,
                                           copy_source_ssec_key_md5=copy_source_ssec_key_md5,
                                           generic_input=generic_input)
            return ResumableCopyObjectOutput(copy_resp=copy_output, bucket=bucket, key=key)
        size = head_out.content_length
        if not copy_source_if_match:
            copy_source_if_match = head_out.etag

        # if size == 0:
        #     raise TosClientError('object size is 0, please use copy_object')

        check_part_number(size, part_size)

        if checkpoint_file:
            dir = init_checkpoint_dir(checkpoint_file)
        else:
            dir = tempfile.gettempdir()

        store = CheckPointStore(dir, "", "copy")

        # 若 copy_event_listener 不包装为内部 eventHandler
        copy_event_listener = ResumableCopyObject(copy_event_listener, bucket, key, src_bucket, src_key,
                                                  src_version_id,
                                                  store.path(bucket, key, src_bucket, src_key, src_version_id))

        parts = []
        record = {}
        upload_id = None

        if enable_checkpoint and _valid_copyobject_checkpoint(bucket=bucket, store=store, key=key,
                                                              etag=head_out.etag, part_size=part_size,
                                                              src_bucket=src_bucket, src_key=src_key,
                                                              version_id=src_version_id):
            # upload_id 存在
            record = store.get(bucket=bucket, key=key, src_bucket=src_bucket, src_key=src_key,
                               version_id=src_version_id)

            upload_id = record['upload_id']
            part_updated = []
            for p in record['parts_info']:
                if p['is_completed']:
                    part_updated.append(
                        PartInfo(p['part_number'], p['part_size'], p['offset'], p['etag'], p['hash_crc64ecma'],
                                 p['is_completed']))
            parts = _get_parts_to_upload(size, part_size, part_updated)

        else:
            # 否则创建分段任务, parts等信息
            create_mult_upload = None

            try:
                create_mult_upload = self.create_multipart_upload(bucket=bucket, key=key, encoding_type=encoding_type,
                                                                  cache_control=cache_control,
                                                                  content_disposition=content_disposition,
                                                                  content_encoding=content_encoding,
                                                                  content_language=content_language,
                                                                  content_type=content_type, expires=expires, acl=acl,
                                                                  grant_full_control=grant_full_control,
                                                                  grant_read=grant_read,
                                                                  grant_read_acp=grant_read_acp,
                                                                  grant_write_acp=grant_write_acp,
                                                                  ssec_algorithm=ssec_algorithm,
                                                                  ssec_key=ssec_key, ssec_key_md5=ssec_key_md5,
                                                                  server_side_encryption=server_side_encryption,
                                                                  meta=meta,
                                                                  website_redirect_location=website_redirect_location,
                                                                  storage_class=storage_class,
                                                                  generic_input=generic_input)
                upload_id = create_mult_upload.upload_id
            except TosError as e:
                copy_event_listener(CopyEventType.Copy_Event_Create_Multipart_Upload_Failed, e)
                raise e

            copy_event_listener(CopyEventType.Copy_Event_Create_Multipart_Upload_Succeed)

            copy_event_listener.upload_id = upload_id
            # 需修改文件的基本结构
            record = {
                'bucket': bucket,
                'key': key,
                'part_size': part_size,
                'upload_id': upload_id,
                'ssec_algorithm': ssec_algorithm,
                'ssec_key_md5': ssec_key_md5,
                'encoding_type': create_mult_upload.encoding_type,
                'copy_source_object_info': {
                    'etag': head_out.etag,
                    'hash_crc64ecma': head_out.hash_crc64_ecma,
                    'last_modified': head_out.last_modified.timestamp(),
                    'object_size': head_out.content_length
                },
                'parts_info': []
            }

            store.put(bucket, key, record, src_bucket=src_bucket, src_key=src_key, version_id=src_version_id)

            parts = _get_parts_to_upload(size, part_size, [])

        # 若源对象大小为0，则直接上传一个空分片
        if size == 0:
            parts.append(_PartToDo(part_number=-1, start=0, end=0))
        uploader = _BreakpointResumableCopyObject(self, bucket=bucket, key=key, store=store,
                                                  src_bucket=src_bucket, src_object=src_key,
                                                  src_version_id=src_version_id,
                                                  task_num=task_num, parts_to_update=parts, upload_id=upload_id,
                                                  record=record, size=size, ssec_key=ssec_key,
                                                  ssec_key_md5=ssec_key_md5,
                                                  ssec_algorithm=ssec_algorithm,
                                                  copy_source_if_match=copy_source_if_match,
                                                  upload_event_listener=copy_event_listener,
                                                  cancel_hook=cancel_hook,
                                                  copy_source_ssec_algorithm=copy_source_ssec_algorithm,
                                                  copy_source_ssec_key=copy_source_ssec_key,
                                                  copy_source_ssec_key_md5=copy_source_ssec_key_md5,
                                                  rate_limiter=None,
                                                  datatransfer_listener=None,
                                                  copy_source_if_none_match=copy_source_if_none_match,
                                                  copy_source_if_unmodified_since=copy_source_if_unmodified_since,
                                                  copy_source_if_modified_since=copy_source_if_modified_since,
                                                  traffic_limit=traffic_limit,
                                                  generic_input=generic_input)

        result = uploader.execute(tos_crc=head_out.hash_crc64_ecma)

        return ResumableCopyObjectOutput(result, ssec_algorithm, ssec_key_md5, record['encoding_type'], upload_id)

    def download_file(self, bucket: str, key: str, file_path: str,
                      version_id: str = None,
                      if_match: str = None,
                      if_modified_since: datetime = None,
                      if_none_match: str = None,
                      if_unmodified_since: datetime = None,
                      ssec_algorithm: str = None,
                      ssec_key: str = None,
                      ssec_key_md5: str = None,
                      part_size: int = 20 * 1024 * 1024,
                      task_num: int = 1,
                      enable_checkpoint: bool = True,
                      checkpoint_file: str = None,
                      data_transfer_listener=None,
                      download_event_listener=None,
                      rate_limiter=None,
                      cancel_hook=None,
                      traffic_limit: int = None,
                      generic_input: GenericInput = None):
        """断点传输下载

        :param bucket: 桶名
        :param key: 对象名
        :param file_path: 下载存储路径
        :param if_match: 只有在匹配时，才返回对象
        :param if_modified_since: datetime(2021, 1, 1)
        :param if_none_match: 只有在不匹配时，才返回对象
        :param if_unmodified_since: datetime(2021, 1, 1)
        :param version_id: 版本号
        :param ssec_algorithm: 'AES256'
        :param ssec_key: 加密密钥
        :param ssec_key_md5: 密钥md5值
        :param part_size: 单个分片大小
        :param task_num: 并发数
        :param enable_checkpoint: 是否开启断点传输
        :param checkpoint_file: checkpoint 文件
        :param data_transfer_listener: 进度条特性
        :param download_event_listener: 下载事件回调
        :param rate_limiter: 客户端限速
        :param cancel_hook: 取消断点下载任务
        :param traffic_limit: 单连接限速
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: HeadObjectOutput
        """
        check_client_encryption_algorithm(ssec_algorithm)

        # 校验待下载的本地文件路径有效性
        if not file_path:
            raise TosClientError('tos: file_path = {0} is invalid'.format(file_path))

        # 下载对象有效性
        result = self.head_object(bucket, key, version_id=version_id, if_match=if_match,
                                  if_modified_since=if_modified_since,
                                  if_none_match=if_none_match, if_unmodified_since=if_unmodified_since,
                                  ssec_algorithm=ssec_algorithm, ssec_key=ssec_key, ssec_key_md5=ssec_key_md5,
                                  generic_input=generic_input)

        if init_path(file_path, key):
            dir = os.path.join(file_path, key)
            os.makedirs(dir, exist_ok=True)
            return result

        dir = ""
        record = {}
        parts = []
        store = None

        content_length = result.content_length
        if result.object_type == 'Symlink':
            content_length = int(result.header.get('x-tos-symlink-target-size'))
        if not if_match:
            if_match = result.etag

        if checkpoint_file:
            dir, file = os.path.split(checkpoint_file)
        else:
            dir = get_parent_directory_from_File(os.path.abspath(file_path))

        if os.path.isdir(file_path):
            store = CheckPointStore(dir, key, 'download')
            file_path = os.path.join(file_path, key)
            try_make_file_dir(file_path)
        else:
            _, file_name = os.path.split(file_path)
            store = CheckPointStore(dir, file_name, 'download')

        download_event_listener = DownloadEventHandler(download_event_listener, bucket, key, version_id,
                                                       os.path.abspath(file_path),
                                                       store.path(bucket, key, versionId=version_id))

        if enable_checkpoint and _valid_download_checkpoint(bucket=bucket, store=store, key=key,
                                                            etag=result.etag, part_size=part_size,
                                                            version_id=version_id):
            record = store.get(bucket=bucket, key=key, version_id=version_id)
            part_downloaded = []
            for p in record["parts_info"]:
                if p["is_completed"]:
                    part_downloaded.append(
                        DownloadPartInfo(p["part_number"], p["range_start"], p["range_end"], p["hash_crc64ecma"],
                                         p["is_completed"]))

            parts = _get_parts_to_download(size=content_length, part_size=part_size,
                                           parts_downloaded=part_downloaded)

        else:
            record = {
                "bucket": bucket,
                "key": key,
                "version_id": result.version_id,
                "part_size": part_size,
                "object_info": {
                    "etag": result.etag,
                    "hash_crc64ecma": result.hash_crc64_ecma,
                    'last_modify': result.last_modified.timestamp(),
                    "object_size": content_length,
                },
                "file_info": {
                    "file_path": file_path,
                    "temp_file_path": file_path + '.temp',
                },
                "parts_info": []
            }
            if if_match:
                record['if_match'] = if_match

            if if_modified_since:
                record['if_modified_since'] = float(if_modified_since.timestamp())

            if if_none_match:
                record['if_none_match'] = if_none_match

            if if_unmodified_since:
                record['if_unmodified_since'] = float(if_unmodified_since.timestamp())
            parts = _get_parts_to_download(size=content_length, part_size=part_size, parts_downloaded=[])

        downloader = _BreakpointDownloader(client=self, bucket=bucket, key=key, file_path=file_path, store=store,
                                           task_num=task_num, parts_to_download=parts, record=record, etag=result.etag,
                                           datatransfer_listener=data_transfer_listener,
                                           download_event_listener=download_event_listener, rate_limiter=rate_limiter,
                                           cancel_hook=cancel_hook, size=content_length,
                                           ssec_algorithm=ssec_algorithm, ssec_key=ssec_key, ssec_key_md5=ssec_key_md5,
                                           version_id=version_id, traffic_limit=traffic_limit,
                                           generic_input=generic_input)

        downloader.execute(tos_crc=result.hash_crc64_ecma)

        return result

    @high_latency_log
    def upload_part(self, bucket: str, key: str, upload_id: str, part_number: int,
                    content_md5: str = None,
                    ssec_algorithm: str = None,
                    ssec_key: str = None,
                    ssec_key_md5: str = None,
                    server_side_encryption: str = None,
                    content_length: int = None,
                    content=None,
                    data_transfer_listener=None,
                    rate_limiter=None,
                    traffic_limit: int = None,
                    generic_input: GenericInput = None) -> UploadPartOutput:

        """上传分片数据

        :param bucket: 桶名
        :param key: 对象名称
        :param upload_id: 初始化分片任务返回的分片任务ID，用于唯一标识上传的分片属于哪个对象。
        :param part_number: 上传的分片号，有效取值[1,10000]。
        :param content_md5: 	消息体的MD5摘要
        :param ssec_algorithm: 指定加密目标对象使用的算法，比如AES256。
        :param ssec_key: 指定加密目标对象的加密密钥。
        :param ssec_key_md5: 该头域表示加密目标对象使用的密钥的MD5值。MD5值用于消息完整性检查，确认加密密钥传输过程中没有出错。
        :param server_side_encryption: 指定server的加密方式
        :param content_length: 消息体的长度
        :param content: 内容
        :param data_transfer_listener: 进度条
        :param rate_limiter: 限速
        :param traffic_limit: 单连接限速
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: UploadPartOutput
        """
        check_client_encryption_algorithm(ssec_algorithm)

        check_server_encryption_algorithm(server_side_encryption)

        headers = _get_upload_part_headers(content_length, content_md5, server_side_encryption, ssec_algorithm,
                                           ssec_key, ssec_key_md5, traffic_limit)

        if self.except100_continue_threshold > 0 and (
                content_length is None or content_length > self.except100_continue_threshold):
            headers['Expect'] = "100-continue"
        if content:
            content = init_content(content)
            patch_content(content)

            if data_transfer_listener:
                content = utils.add_progress_listener_func(content, data_transfer_listener)

            if rate_limiter:
                content = utils.add_rate_limiter_func(content, rate_limiter)

            if self.enable_crc:
                content = utils.add_crc_func(content)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Put.value,
                         params={'uploadId': upload_id, 'partNumber': part_number},
                         data=content, headers=headers, generic_input=generic_input)

        upload_part_output = UploadPartOutput(resp, part_number)

        if content and self.enable_crc and upload_part_output.hash_crc64_ecma:
            utils.check_crc('upload part', client_crc=content.crc, tos_crc=upload_part_output.hash_crc64_ecma,
                            request_id=upload_part_output.request_id)

        return upload_part_output

    def upload_part_from_file(self, bucket: str, key: str, upload_id: str, part_number: int,
                              content_md5: str = None,
                              ssec_algorithm: str = None,
                              ssec_key: str = None,
                              ssec_key_md5: str = None,
                              server_side_encryption: str = None,
                              data_transfer_listener=None,
                              rate_limiter=None,
                              file_path: str = None,
                              part_size: int = -1,
                              offset: int = 0,
                              traffic_limit: int = None,
                              generic_input: GenericInput = None) -> UploadPartOutput:
        """以文件形式上传分片数据

        :param bucket: 桶名
        :param key: 对象名称
        :param upload_id: 初始化分片任务返回的分片任务ID，用于唯一标识上传的分片属于哪个对象。
        :param part_number: 上传的分片号，有效取值[1,10000]。
        :param content_md5: 	消息体的MD5摘要
        :param ssec_algorithm: 指定加密目标对象使用的算法，比如AES256。
        :param ssec_key: 指定加密目标对象的加密密钥。
        :param ssec_key_md5: 该头域表示加密目标对象使用的密钥的MD5值。MD5值用于消息完整性检查，确认加密密钥传输过程中没有出错。
        :param server_side_encryption: 指定server的加密方式
        :param data_transfer_listener: 进度条
        :param rate_limiter: 限速度
        :param file_path: 文件路径
        :param part_size: 当前分段长度
        :param offset: 当前分段在文件中的起始位置
        :param traffic_limit: 单连接限速
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: UploadPartOutput
        """
        check_client_encryption_algorithm(ssec_algorithm)

        check_server_encryption_algorithm(server_side_encryption)

        with open(file_path, 'rb') as f:
            size = os.path.getsize(file_path)
            content = _make_upload_part_file_content(f, offset=offset, part_size=part_size, size=size)
            if content is None:
                raise TosClientError(
                    'tos invalid offset:{0}, and part_size:{1} with filesize={2}'.format(offset, part_size, size))

            return self.upload_part(bucket=bucket,
                                    key=key,
                                    upload_id=upload_id,
                                    part_number=part_number,
                                    content_md5=content_md5,
                                    ssec_algorithm=ssec_algorithm,
                                    ssec_key=ssec_key,
                                    ssec_key_md5=ssec_key_md5,
                                    server_side_encryption=server_side_encryption,
                                    content=content,
                                    data_transfer_listener=data_transfer_listener,
                                    rate_limiter=rate_limiter,
                                    traffic_limit=traffic_limit,
                                    generic_input=generic_input)

    def complete_multipart_upload(self, bucket: str, key: str, upload_id: str, parts: list = None,
                                  complete_all: bool = False,
                                  callback: str = None,
                                  callback_var: str = None,
                                  forbid_overwrite: bool = None,
                                  generic_input: GenericInput = None) -> CompleteMultipartUploadOutput:
        """ 合并段

        :param bucket: 桶名
        :param key: 对象名
        :param upload_id: 分段任务编号
        :param parts: 完成的分段任务
        :param complete_all: 指定是否合并指定当前UploadId已上传的所有Part
        :param callback: 回调
        :param callback_var: 回调参数
        :param forbid_overwrite: 是否禁止覆盖同名对象，True表示禁止覆盖，False表示允许覆盖
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: CompleteMultipartUploadOutput
        """
        headers = _get_complete_upload_part_headers(complete_all, callback, callback_var, forbid_overwrite)

        data = None
        if not complete_all:
            body = to_complete_multipart_upload_request(parts)
            data = json.dumps(body)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Post.value,
                         params={'uploadId': upload_id}, data=data, headers=headers, generic_input=generic_input)

        return CompleteMultipartUploadOutput(resp, callback)

    def abort_multipart_upload(self, bucket: str, key: str, upload_id: str,
                               generic_input: GenericInput = None) -> AbortMultipartUpload:
        """取消分片上传

        :param bucket: 桶名
        :param key: 对象名
        :param upload_id: 分片任务id
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: AbortMultipartUpload
        """

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Delete.value,
                         params={'uploadId': upload_id}, generic_input=generic_input)

        return AbortMultipartUpload(resp)

    def upload_part_copy(self, bucket: str, key: str, upload_id: str, part_number: int, src_bucket: str, src_key: str,
                         src_version_id: str = None,
                         copy_source_range_start: int = None,
                         copy_source_range_end: int = None,
                         copy_source_if_match: str = None,
                         copy_source_if_modified_since: datetime = None,
                         copy_source_if_none_match: str = None,
                         copy_source_if_unmodified_since: datetime = None,
                         copy_source_ssec_algorithm: str = None,
                         copy_source_ssec_key: str = None,
                         copy_source_ssec_key_md5: str = None,
                         ssec_algorithm: str = None,
                         ssec_key: str = None,
                         ssec_key_md5: str = None,
                         copy_source_range: str = None,
                         traffic_limit: int = None,
                         generic_input: GenericInput = None) -> UploadPartCopyOutput:
        """复制段

        :param bucket: 桶名
        :param key: 对象名
        :param upload_id: 初始化分片任务返回的段任务ID，用于唯一标识上传的分片属于哪个对象。
        :param part_number: 上传的分片号，有效取值[1,10000]。
        :param src_bucket: 指定拷贝的源桶名
        :param src_key: 指定拷贝的源对象名
        :param src_version_id: 指定拷贝的版本
        :param copy_source_range_start: 原对象的拷贝字节-起始字节
        :param copy_source_range_end: 原对象的拷贝字节-截止字节
        :param copy_source_range: 拷贝范围
        :param copy_source_if_match: 只有当源对象的Etag与此参数指定的值相等时才进行复制对象操作。
        :param copy_source_if_modified_since: 如果自指定时间以来对象已被修改，则复制该对象。
        :param copy_source_if_none_match: 只有当源对象的Etag与此参数指定的值不相等时才进行复制对象操作。
        :param copy_source_if_unmodified_since: 如果自指定时间以来对象未被修改，则复制该对象。
        :param copy_source_ssec_key: SSE-C方式下使用该头域，指定解密源对象的加密密钥。此头域提供的加密密钥必须是创建源对象时使用的密钥。
        :param copy_source_ssec_key_md5: SSE-C方式下使用该头域，该头域表示解密源对象使用的密钥的MD5值。MD5值用于消息完整性检查，确认加密密钥传输过程中没有出错。
        :param copy_source_ssec_algorithm: ssec 加密算法
        :param ssec_algorithm: 目标对象的加密方式
        :param ssec_key: 目标对象的加密 key
        :param ssec_key_md5: 目标对象加密key的md5值
        :param traffic_limit: 单连接限速
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        return: UploadPartCopyOutput
        """
        check_client_encryption_algorithm(copy_source_ssec_algorithm)

        copy_source = _make_copy_source(src_bucket=src_bucket, src_key=src_key, src_version_id=src_version_id)

        if copy_source_range is None:
            copy_source_range = _make_range_string(copy_source_range_start, copy_source_range_end)

        headers = _get_upload_part_copy_headers(copy_source, copy_source_if_match, copy_source_if_modified_since,
                                                copy_source_if_none_match, copy_source_if_unmodified_since,
                                                copy_source_range, copy_source_ssec_algorithm, copy_source_ssec_key,
                                                copy_source_ssec_key_md5, ssec_algorithm, ssec_key, ssec_key_md5,
                                                traffic_limit)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Put.value,
                         params={'uploadId': upload_id, 'partNumber': part_number},
                         headers=headers, generic_input=generic_input)

        return UploadPartCopyOutput(resp, part_number)

    def list_multipart_uploads(self, bucket: str,
                               prefix: str = None,
                               delimiter: str = None,
                               key_marker: str = None,
                               upload_id_marker: str = None,
                               max_uploads: int = 1000,
                               encoding_type: str = None,
                               generic_input: GenericInput = None) -> ListMultipartUploadsOutput:
        """列举正在进行的分片上传任务

        :param bucket: 桶名称
        :param prefix: 用于指定列举返回对象的前缀名称。可以使用此参数对桶中对象进行分组管理（类似文件夹功能）。
        :param delimiter: 用于对Object名称进行分组的字符。所有名称包含指定的前缀且首次出现delimiter字符之间的Object作为一组元素CommonPrefixes。
        :param key_marker: 与参数upload-id-marker一起使用
        :param upload_id_marker: 与参数key-marker一起使用
        :param max_uploads: 限定列举返回的分片上传任务数量，最大1000，默认1000。
        :param encoding_type: 指定对响应中的内容进行编码，指定编码的类型。如果请求中设置了encoding-type，
        那响应中的Delimiter、KeyMarker、Prefix（包括CommonPrefixes中的Prefix）、NextKeyMarker和Key会被编码。
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域

        :return: ListMultipartUploadsOutput
        """
        params = _get_list_multipart_uploads_params(delimiter, encoding_type, key_marker, max_uploads, prefix,
                                                    upload_id_marker)

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params=params,
                         generic_input=generic_input)

        return ListMultipartUploadsOutput(resp)

    def list_parts(self, bucket: str, key: str, upload_id: str,
                   part_number_marker: int = None,
                   max_parts: int = 1000,
                   generic_input: GenericInput = None) -> ListPartsOutput:
        """ 列举段

        :param bucket: 桶名
        :param key: 对象名称
        :param upload_id: 初始化分片任务返回的段任务ID，用于唯一标识上传的分片属于哪个对象。
        :param part_number_marker: 指定PartNumber的起始位置，只列举PartNumber大于此值的段。
        :param max_parts: 响应中最大的分片数量
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: ListPartsOutput
        """
        params = _get_list_parts_params(max_parts, part_number_marker, upload_id)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Get.value, params=params,
                         generic_input=generic_input)

        return ListPartsOutput(resp)

    def put_bucket_cors(self, bucket: str, cors_rule: [], generic_input: GenericInput = None) -> PutBucketCorsOutput:
        """ 为指定桶设置跨域请求配置

        :param bucket: 桶名
        :param cors_rule: 跨域请求规则
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketCorsOutput
        """
        data = to_put_bucket_cors_request(cors_rules=cors_rule)
        data = json.dumps(data)
        headers = {"Content-MD5": to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}
        params = {'cors': ''}
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, params=params, headers=headers,
                         data=data, generic_input=generic_input)

        return PutBucketCorsOutput(resp)

    def get_bucket_cors(self, bucket: str, generic_input: GenericInput = None) -> GetBucketCorsOutput:
        """ 获取指定 bucket 的 CORS 规则

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketCorsOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={'cors': ''},
                         generic_input=generic_input)

        return GetBucketCorsOutput(resp)

    def delete_bucket_cors(self, bucket: str, generic_input: GenericInput = None) -> DeleteBucketCorsOutput:
        """ 删除指定 bucket 的 CORS 规则

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteBucketCorsOutput
        """

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params={'cors': ''},
                         generic_input=generic_input)

        return DeleteBucketCorsOutput(resp)

    def list_objects_type2(self, bucket: str,
                           prefix: str = None,
                           delimiter: str = None,
                           start_after: str = None,
                           continuation_token: str = None,
                           reverse: bool = None,
                           max_keys: int = 1000,
                           encoding_type: str = None,
                           list_only_once: bool = False,
                           generic_input: GenericInput = None,
                           fetch_meta: bool = None) -> ListObjectType2Output:
        """ 列举 bucket 中所有 objects 信息

        :param bucket: 桶名
        :param prefix: 前缀
        :param delimiter: 分组字符
        :param start_after: 设置从 start_after 之后按字典序开始返回 Object
        :param continuation_token: 指定list操作需要从此token开始
        :param reverse: 是否反转
        :param max_keys: 指定每次返回 object 的最大数量
        :param encoding_type: 返回key编码类型
        :param list_only_once: 是否只列举一次
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :param fetch_meta: 是否获取对象的自定义meta
        :return: ListObjectType2Output
        """
        params = _get_list_object_v2_params(delimiter, start_after, continuation_token, reverse, max_keys,
                                            encoding_type, prefix, fetch_meta)

        if list_only_once:
            resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params=params,
                             generic_input=generic_input)
            return ListObjectType2Output(resp, self.disable_encoding_meta)

        iterator = ListObjectsIterator(self._req, max_keys, bucket=bucket, method=HttpMethodType.Http_Method_Get.value,
                                       params=params, func='list_objects_type2',
                                       disable_encoding_meta=self.disable_encoding_meta)
        result_arr = []
        for iterm in iterator:
            result_arr.append(iterm)
        return result_arr.pop(0).combine(result_arr)

    def put_symlink(self, bucket: str, key: str, symlink_target_key: str, symlink_target_bucket: str = None,
                    storage_class: StorageClassType = None, acl: ACLType = None, meta: Dict = None,
                    forbid_overwrite: bool = None, generic_input: GenericInput = None):
        """设置对象软链接

        :param bucket: 桶名
        :param key: 对象名
        :param symlink_target_key: 目标对象名
        :param symlink_target_bucket: 目标桶
        :param storage_class: 存储类型
        :param acl: 对象ACL.default（默认）：Object遵循所在存储空间的访问权限。
                            private：Object是私有资源。只有Bucket的拥有者和授权用户有该Bucket的读写权限，其他用户没有权限操作该Bucket。
                            public-read：Bucket是公共读资源。只有Bucket的拥有者和授权用户有该Bucket的读写权限，其他用户只有该Bucket的读权限。请谨慎使用该权限。
                            public-read-write：Bucket是公共读写资源。所有用户都有该Bucket的读写权限。请谨慎使用该权限。
                            authenticated-read：认证用户读。
                            bucket-owner-read：桶所有者读。
                            bucket-owner-full-control：桶所有者完全权限。
        :param meta: 对象元数据
        :param forbid_overwrite: 是否禁止覆盖同名对象，True表示禁止覆盖，False表示允许覆盖
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutSymlinkOutput
        """

        headers = _get_put_symlink_headers(symlink_target_key, symlink_target_bucket, acl, storage_class, meta,
                                           forbid_overwrite, self.disable_encoding_meta)

        params = {'symlink': ''}

        resp = self._req(bucket, key, HttpMethodType.Http_Method_Put.value,
                         headers=headers, params=params, generic_input=generic_input)

        return PutSymlinkOutput(resp)

    def get_symlink(self, bucket: str, key: str, version_id: str = None, generic_input: GenericInput = None):
        """获取对象软链接

        :param bucket: 桶名
        :param key: 对象名
        :param version_id: 版本号
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetSymlinkOutput
        """

        params = {'symlink': ''}
        if version_id:
            params["versionId"] = version_id

        resp = self._req(bucket, key, HttpMethodType.Http_Method_Get.value, params=params, generic_input=generic_input)

        return GetSymlinkOutput(resp)

    def put_bucket_storage_class(self, bucket: str,
                                 storage_class: StorageClassType,
                                 generic_input: GenericInput = None) -> PutBucketStorageClassOutput:
        """ 设置 bucket 的存储类型

        :param bucket: 桶名
        :param storage_class: 存储类型
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketStorageClassOutput
        """

        check_enum_type(storage_class=storage_class)

        headers = {}
        if storage_class:
            headers['x-tos-storage-class'] = storage_class.value
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, params={'storageClass': ''},
                         headers=headers, generic_input=generic_input)
        return PutBucketStorageClassOutput(resp)

    def get_bucket_location(self, bucket: str, generic_input: GenericInput = None) -> GetBucketLocationOutput:
        """ 获取 bucket 的location信息

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketLocationOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={'location': ''},
                         generic_input=generic_input)
        return GetBucketLocationOutput(resp)

    def put_bucket_lifecycle(self, bucket: str, rules: [],
                             generic_input: GenericInput = None,
                             allow_same_action_overlap: bool = None) -> PutBucketLifecycleOutput:
        """ 设置 bucket 的生命周期规则

        :param bucket: 桶名
        :param rules: 生命周期规则
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :param allow_same_action_overlap: 是否支持前缀重叠
        :return: PutBucketLifecycleOutput
        """
        data = to_put_bucket_lifecycle(rules)
        data = json.dumps(data)
        if allow_same_action_overlap:
            allow_same_action_overlap = str(allow_same_action_overlap).lower()
        headers = {"Content-MD5": to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest())),
                   "x-tos-allow-same-action-overlap": allow_same_action_overlap}
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, data=data, headers=headers,
                         params={'lifecycle': ''}, generic_input=generic_input)

        return PutBucketLifecycleOutput(resp)

    def get_bucket_lifecycle(self, bucket: str, generic_input: GenericInput = None) -> GetBucketLifecycleOutput:
        """ 获取 bucket 的生命周期规则

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketLifecycleOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={'lifecycle': ''},
                         generic_input=generic_input)
        return GetBucketLifecycleOutput(resp)

    def delete_bucket_lifecycle(self, bucket: str, generic_input: GenericInput = None) -> DeleteBucketLifecycleOutput:
        """ 删除 桶的 生命周期规则

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteBucketLifecycleOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params={'lifecycle': ''},
                         generic_input=generic_input)
        return DeleteBucketLifecycleOutput(resp)

    def put_bucket_policy(self, bucket: str, policy: str, generic_input: GenericInput = None) -> PutBucketPolicyOutPut:
        """ 设置 bucket 的授权规则

        :param bucket: 桶名
        :param policy: 授权规则
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketPolicyOutPut
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, params={'policy': ''}, data=policy,
                         generic_input=generic_input)
        return PutBucketPolicyOutPut(resp)

    def get_bucket_policy(self, bucket: str, generic_input: GenericInput = None) -> GetBucketPolicyOutput:
        """ 获取 bucket 授权规则

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketPolicyOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={'policy': ''},
                         generic_input=generic_input)
        return GetBucketPolicyOutput(resp)

    def delete_bucket_policy(self, bucket, generic_input: GenericInput = None) -> DeleteBucketPolicy:
        """ 删除 bucket 授权规则

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteBucketPolicy
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params={'policy': ''},
                         generic_input=generic_input)
        return DeleteBucketPolicy(resp)

    def put_bucket_mirror_back(self, bucket: str, rules: [],
                               generic_input: GenericInput = None) -> PutBucketMirrorBackOutPut:
        """ 设置 bucket 的镜像回源规则

        :param bucket: 桶名
        :param rules: 镜像回源规则
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketMirrorBackOutPut
        """
        data = to_put_bucket_mirror_back(rules)
        data = json.dumps(data)

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, params={'mirror': ''}, data=data,
                         generic_input=generic_input)

        return PutBucketMirrorBackOutPut(resp)

    def get_bucket_mirror_back(self, bucket, generic_input: GenericInput = None) -> GetBucketMirrorBackOutput:
        """ 获取 bucket 的镜像回源规则

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketMirrorBackOutput
        """

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={'mirror': ''},
                         generic_input=generic_input)
        return GetBucketMirrorBackOutput(resp)

    def delete_bucket_mirror_back(self, bucket, generic_input: GenericInput = None) -> DeleteBucketMirrorBackOutput:
        """ 删除 bucket 的镜像回源规则

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteBucketMirrorBackOutput
        """

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params={'mirror': ''},
                         generic_input=generic_input)
        return DeleteBucketMirrorBackOutput(resp)

    def put_bucket_tagging(self, bucket: str, tag_set: [], generic_input: GenericInput = None):
        """ 设置桶标签
        :param bucket: 桶名
        :param tag_set: 标签集合
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketTaggingOutput
        """
        data = to_put_tagging(tag_set)
        data = json.dumps(data)
        headers = {"Content-MD5": to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, params={'tagging': ''},
                         data=data, headers=headers, generic_input=generic_input)
        return PutBucketTaggingOutput(resp)

    def get_bucket_tagging(self, bucket: str, generic_input: GenericInput = None):
        """ 获取桶标签
        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketTaggingOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={'tagging': ''},
                         generic_input=generic_input)
        return GetBucketTaggingOutput(resp)

    def delete_bucket_tagging(self, bucket: str, generic_input: GenericInput = None):
        """ 删除桶标签
        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteBucketTaggingOutput
        """

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params={'tagging': ''},
                         generic_input=generic_input)
        return DeleteBucketTaggingOutput(resp)

    def put_object_tagging(self, bucket: str, key: str, tag_set: [],
                           version_id: str = None, generic_input: GenericInput = None) -> PutObjectTaggingOutput:
        """ 为 object 添加标签

        :param bucket: 桶名
        :param key: 对象名
        :param tag_set: 标签集合
        :param version_id: 版本号
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutObjectTaggingOutput
        """
        params = {'tagging': ''}
        if version_id:
            params['versionId'] = version_id

        data = to_put_tagging(tag_set)
        data = json.dumps(data)
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, params=params, data=data, key=key,
                         generic_input=generic_input)
        return PutObjectTaggingOutput(resp)

    def get_object_tagging(self, bucket: str, key: str,
                           version_id: str = None, generic_input: GenericInput = None) -> GetObjectTaggingOutPut:
        """ 获取 object 标签

        :param bucket: 桶名
        :param key: 对象名
        :param version_id: 版本号
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetObjectTaggingOutPut
        """
        params = {'tagging': ''}
        if version_id:
            params['versionId'] = version_id
        resp = self._req(bucket=bucket, key=key, params=params, method=HttpMethodType.Http_Method_Get.value,
                         generic_input=generic_input)
        return GetObjectTaggingOutPut(resp)

    def delete_object_tagging(self, bucket: str, key: str,
                              version_id: str = None, generic_input: GenericInput = None) -> DeleteObjectTaggingOutput:
        """ 删除 object 标签

        :param bucket: 桶名
        :param key: 对象名
        :param version_id: 版本号
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteObjectTaggingOutput
        """
        params = {'tagging': ''}
        if version_id:
            params['versionId'] = version_id
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params=params, key=key,
                         generic_input=generic_input)
        return DeleteObjectTaggingOutput(resp)

    def put_bucket_acl(self, bucket: str,
                       acl: ACLType = None,
                       grant_full_control: str = None,
                       grant_read: str = None,
                       grant_read_acp: str = None,
                       grant_write: str = None,
                       grant_write_acp: str = None,
                       owner: Owner = None,
                       grants: [] = None,
                       generic_input: GenericInput = None) -> PutBucketACLOutput:
        """ 设计 bucket 的 acl 规则

        :param bucket: 桶名
        :param acl: 对象ACL.default（默认）：Object遵循所在存储空间的访问权限。
                            private：Object是私有资源。只有Bucket的拥有者和授权用户有该Bucket的读写权限，其他用户没有权限操作该Bucket。
                            public-read：Bucket是公共读资源。只有Bucket的拥有者和授权用户有该Bucket的读写权限，其他用户只有该Bucket的读权限。请谨慎使用该权限。
                            public-read-write：Bucket是公共读写资源。所有用户都有该Bucket的读写权限。请谨慎使用该权限。
                            authenticated-read：认证用户读。
                            bucket-owner-read：桶所有者读。
                            bucket-owner-full-control：桶所有者完全权限。
        :param grant_full_control:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read_acp:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_write: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_write_acp: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param owner: 桶的拥有者
        :param grants: 访问控制列表.
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketACLOutput
        """
        check_enum_type(acl=acl)
        params = {'acl': ''}
        headers = _get_put_bucket_acl_headers(acl, grant_full_control, grant_read, grant_read_acp, grant_write,
                                              grant_write_acp)

        data = None

        if grants:
            body = to_put_acl_request(owner, grants)
            data = json.dumps(body)

        resp = self._req(bucket=bucket, params=params, method=HttpMethodType.Http_Method_Put.value, headers=headers,
                         data=data, generic_input=generic_input)
        return PutBucketACLOutput(resp)

    def get_bucket_acl(self, bucket: str, generic_input: GenericInput = None) -> GetBucketACLOutput:
        """ 获取 bucket 的 acl 规则

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketACLOutput
        """
        params = {'acl': ''}
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params=params,
                         generic_input=generic_input)

        return GetBucketACLOutput(resp)

    def fetch_object(self, bucket: str, key: str, url: str,
                     acl: ACLType = None,
                     grant_full_control: str = None,
                     grant_read: str = None,
                     grant_read_acp: str = None,
                     grant_write_acp: str = None,
                     storage_class: StorageClassType = None,
                     ssec_algorithm: str = None,
                     ssec_key: str = None,
                     ssec_key_md5: str = None,
                     meta: Dict = None,
                     ignore_same_key: bool = False,
                     hex_md5: str = None,  # deprecated
                     generic_input: GenericInput = None,
                     content_md5: str = None) -> FetchObjectOutput:
        """ fetch 拉取对象

        :param bucket: 桶名
        :param key: 对象名
        :param url: 获取地址
        :param acl: 对象ACL.default（默认）：Object遵循所在存储空间的访问权限。
                            private：Object是私有资源。只有Bucket的拥有者和授权用户有该Bucket的读写权限，其他用户没有权限操作该Bucket。
                            public-read：Bucket是公共读资源。只有Bucket的拥有者和授权用户有该Bucket的读写权限，其他用户只有该Bucket的读权限。请谨慎使用该权限。
                            public-read-write：Bucket是公共读写资源。所有用户都有该Bucket的读写权限。请谨慎使用该权限。
                            authenticated-read：认证用户读。
                            bucket-owner-read：桶所有者读。
                            bucket-owner-full-control：桶所有者完全权限。
        :param grant_full_control:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read_acp:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_write_acp: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param storage_class: 对象存储类型
        :param ssec_algorithm: 指定加密目标对象使用的算法，比如AES256。
        :param ssec_key: 指定加密目标对象的加密密钥。
        :param ssec_key_md5: 该头域表示加密目标对象使用的密钥的MD5值。MD5值用于消息完整性检查，确认加密密钥传输过程中没有出错。
        :param meta: 对象元数据
        :param ignore_same_key: 是否忽略相同的对象名
        :param hex_md5: deprecated，该参数不再使用，请用content_md5，deprecated
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :param content_md5: 对象md5值
        :return: FetchObjectOutput
        """

        data = to_fetch_object(url, key, ignore_same_key, hex_md5, content_md5)
        data = json.dumps(data)
        headers = _get_fetch_headers(storage_class, acl, grant_full_control, grant_read, grant_read_acp,
                                     grant_write_acp, meta, ssec_algorithm, ssec_key, ssec_key_md5,
                                     self.disable_encoding_meta)
        headers['Content-Length'] = str(len(data))
        resp = self._req(bucket=bucket, key=key, params={'fetch': ''}, headers=headers,
                         method=HttpMethodType.Http_Method_Post.value, data=data, generic_input=generic_input)

        return FetchObjectOutput(resp)

    def put_fetch_task(self, bucket: str, key: str, url: str,
                       acl: ACLType = None,
                       grant_full_control: str = None,
                       grant_read: str = None,
                       grant_read_acp: str = None,
                       grant_write_acp: str = None,
                       storage_class: StorageClassType = None,
                       ssec_algorithm: str = None,
                       ssec_key: str = None,
                       ssec_key_md5: str = None,
                       meta: Dict = None,
                       ignore_same_key: bool = False,
                       hex_md5: str = None,
                       generic_input: GenericInput = None,
                       content_md5: str = None,
                       callback_url: str = None,
                       callback_host: str = None,
                       callback_body: str = None,
                       callback_body_type: str = None) -> PutFetchTaskOutput:
        """ 添加 fetch 拉起对象任务

        :param bucket: 桶名
        :param key: 对象名
        :param url: 获取地址
        :param acl: 对象ACL.default（默认）：Object遵循所在存储空间的访问权限。
                            private：Object是私有资源。只有Bucket的拥有者和授权用户有该Bucket的读写权限，其他用户没有权限操作该Bucket。
                            public-read：Bucket是公共读资源。只有Bucket的拥有者和授权用户有该Bucket的读写权限，其他用户只有该Bucket的读权限。请谨慎使用该权限。
                            public-read-write：Bucket是公共读写资源。所有用户都有该Bucket的读写权限。请谨慎使用该权限。
                            authenticated-read：认证用户读。
                            bucket-owner-read：桶所有者读。
                            bucket-owner-full-control：桶所有者完全权限。
        :param grant_full_control:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_read_acp:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param grant_write_acp: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param storage_class: 对象存储类型
        :param ssec_algorithm: 指定加密目标对象使用的算法，比如AES256。
        :param ssec_key: 指定加密目标对象的加密密钥。
        :param ssec_key_md5: 该头域表示加密目标对象使用的密钥的MD5值。MD5值用于消息完整性检查，确认加密密钥传输过程中没有出错。
        :param meta: 对象元数据
        :param ignore_same_key: 是否忽略相同的对象名
        :param hex_md5: deprecated，该参数不再使用，请用content_md5，deprecated
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :param content_md5: 对象md5值
        :param callback_url
        :param callback_host
        :param callback_body
        :param callback_body_type
        :return: PutFetchTaskOutput
        """

        headers = _get_fetch_headers(storage_class, acl, grant_full_control, grant_read, grant_read_acp,
                                     grant_write_acp, meta, ssec_algorithm, ssec_key, ssec_key_md5,
                                     self.disable_encoding_meta)
        data = to_put_fetch_object(url, key, ignore_same_key, hex_md5, content_md5, callback_url, callback_host,
                                   callback_body, callback_body_type)
        data = json.dumps(data)

        resp = self._req(bucket=bucket, params={'fetchTask': ''}, headers=headers,
                         method=HttpMethodType.Http_Method_Post.value, data=data, generic_input=generic_input)

        return PutFetchTaskOutput(resp)

    def get_fetch_task(self, bucket: str, task_id: str,
                       generic_input: GenericInput = None) -> GetFetchTaskOutput:
        """ 获取 fetch 任务

        :param bucket: 桶名
        :param task_id: 任务id
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetFetchTaskOutput
        """

        param = {'fetchTask': '', 'taskId': task_id}
        resp = self._req(bucket=bucket, params=param, method=HttpMethodType.Http_Method_Get.value,
                         generic_input=generic_input)
        return GetFetchTaskOutput(resp)

    def put_bucket_replication(self, bucket: str, role: str,
                               rules: list, generic_input: GenericInput = None) -> PutBucketReplicationOutput:
        """ 设置桶的跨区域复制规则

        :param bucket: 桶名
        :param role:   角色名
        :param rules: 规则
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketReplicationOutput
        """
        data = to_put_replication(role, rules)
        data = json.dumps(data)
        headers = {"Content-MD5": to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}
        resp = self._req(bucket=bucket, data=data, params={'replication': ''}, headers=headers,
                         method=HttpMethodType.Http_Method_Put.value, generic_input=generic_input)
        return PutBucketReplicationOutput(resp)

    def get_bucket_replication(self, bucket, rule_id=None,
                               generic_input: GenericInput = None) -> GetBucketReplicationOutput:
        """ 获取桶的跨区域复制规则

        :param bucket: 桶名
        :param rule_id: 规则编号
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketReplicationOutput
        """
        params = {'replication': '', 'progress': ''}
        if rule_id:
            params['rule-id'] = rule_id
        resp = self._req(bucket=bucket, params=params, method=HttpMethodType.Http_Method_Get.value,
                         generic_input=generic_input)
        return GetBucketReplicationOutput(resp)

    def delete_bucket_replication(self, bucket: str,
                                  generic_input: GenericInput = None) -> DeleteBucketReplicationOutput:
        """ 删除桶跨区域复制规则

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteBucketReplicationOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params={'replication': ''},
                         generic_input=generic_input)
        return DeleteBucketReplicationOutput(resp)

    def put_bucket_versioning(self, bucket: str, status: VersioningStatusType,
                              generic_input: GenericInput = None) -> PutBucketVersioningOutput:
        """ 设置桶的多版本状态

        :param bucket: 桶名
        :param status: 状态
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketVersioningOutput
        """
        data = {}
        if status:
            data['Status'] = status.value
        data = json.dumps(data)
        resp = self._req(bucket=bucket, method='PUT', data=data, params={'versioning': ''}, generic_input=generic_input)

        return PutBucketVersioningOutput(resp)

    def get_bucket_version(self, bucket, generic_input: GenericInput = None) -> GetBucketVersionOutput:
        """ 获取桶的多版本状态

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketVersionOutput
        """
        resp = self._req(bucket=bucket, method='GET', params={'versioning': ''}, generic_input=generic_input)
        return GetBucketVersionOutput(resp)

    def put_bucket_website(self, bucket: str,
                           redirect_all_requests_to: RedirectAllRequestsTo = None,
                           index_document: IndexDocument = None,
                           error_document: ErrorDocument = None,
                           routing_rules: RoutingRules = None,
                           generic_input: GenericInput = None) -> PutBucketWebsiteOutput:
        """ 静态网站配置

        :param: bucket: 桶名
        :param: redirect_all_requests_to: 所有请求都重定向
        :param: index_document: 主页
        :param: error_document: 错误页
        :param: routing_rules: 路由规则
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketWebsiteOutput
        """
        data = to_put_bucket_website(redirect_all_requests_to, index_document, error_document, routing_rules)
        data = json.dumps(data)
        headers = {"Content-MD5": to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, data=data, params={'website': ''},
                         headers=headers, generic_input=generic_input)

        return PutBucketWebsiteOutput(resp)

    def get_bucket_website(self, bucket: str, generic_input: GenericInput = None) -> GetBucketWebsiteOutput:
        """ 获取 静态网站配置

        :param: bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketWebsiteOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={'website': ''},
                         generic_input=generic_input)
        return GetBucketWebsiteOutput(resp)

    def delete_bucket_website(self, bucket, generic_input: GenericInput = None) -> PutBucketWebsiteOutput:
        """ 删除静态网站配置
        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketWebsiteOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params={'website': ''},
                         generic_input=generic_input)
        return PutBucketWebsiteOutput(resp)

    def put_bucket_notification(self, bucket: str, cloud_function_configurations: [] = None,
                                rocket_mq_configurations: [] = None,
                                generic_input: GenericInput = None) -> PutBucketNotificationOutput:
        """

        :param: bucket: 桶名
        :param: cloudFunctionConfigurations: 配置
        :param: rocket_mq_configurations: rocketMQ 配置
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketNotificationOutput
        """
        data = to_put_bucket_notification(cloud_function_configurations, rocket_mq_configurations)
        data = json.dumps(data)
        headers = {"Content-MD5": to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, params={'notification': ''},
                         data=data,
                         headers=headers,
                         generic_input=generic_input)
        return PutBucketNotificationOutput(resp)

    def get_bucket_notification(self, bucket, generic_input: GenericInput = None) -> GetBucketNotificationOutput:
        """

        :param: bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketNotificationOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={'notification': ''},
                         generic_input=generic_input)
        return GetBucketNotificationOutput(resp)

    def put_bucket_notification_type2(self, bucket: str, rule: [] = None, version: str = None,
                                      generic_input: GenericInput = None) -> PutBucketNotificationType2Output:
        """设置桶事件通知规则

        :param: bucket: 桶名
        :param: rules: 配置
        :param: version: 事件通知规则的版本号
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketNotificationType2Output
        """
        data = to_put_bucket_notification_type2(rule, version)
        data = json.dumps(data)
        headers = {"Content-MD5": to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, params={'notification_v2': ''},
                         data=data,
                         headers=headers,
                         generic_input=generic_input)
        return PutBucketNotificationType2Output(resp)

    def get_bucket_notification_type2(self, bucket,
                                      generic_input: GenericInput = None) -> GetBucketNotificationType2Output:
        """获取桶事件通知规则

        :param: bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketNotificationType2Output
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={'notification_v2': ''},
                         generic_input=generic_input)
        return GetBucketNotificationType2Output(resp)

    def put_bucket_custom_domain(self, bucket: str, rule: CustomDomainRule,
                                 generic_input: GenericInput = None) -> PutBucketCustomDomainOutput:
        """ 设置自定义域名

        :param: bucket: 桶名
        :param: rule: 规则
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketCustomDomainOutput
        """
        data = to_put_custom_domain(rule)
        data = json.dumps(data)
        headers = {"Content-MD5": to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, params={'customdomain': ''},
                         headers=headers, data=data, generic_input=generic_input)
        return PutBucketCustomDomainOutput(resp)

    def list_bucket_custom_domain(self, bucket: str,
                                  generic_input: GenericInput = None) -> ListBucketCustomDomainOutput:
        """ 列举自定义域名

        :param: bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: ListBucketCustomDomainOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={'customdomain': ''},
                         generic_input=generic_input)
        return ListBucketCustomDomainOutput(resp)

    def List_bucket_custom_domain(self, bucket: str,
                                  generic_input: GenericInput = None) -> ListBucketCustomDomainOutput:
        """ 列举自定义域名

        :param: bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: ListBucketCustomDomainOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={'customdomain': ''},
                         generic_input=generic_input)
        return ListBucketCustomDomainOutput(resp)

    def delete_bucket_custom_domain(self, bucket: str, domain: str,
                                    generic_input: GenericInput = None) -> DeleteCustomDomainOutput:
        """ 删除自定义域名

        :param: bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteCustomDomainOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params={'customdomain': domain},
                         generic_input=generic_input)
        return DeleteCustomDomainOutput(resp)

    def put_bucket_real_time_log(self, bucket: str, configuration: RealTimeLogConfiguration,
                                 generic_input: GenericInput = None):
        """ 配置实时日志
        :param: bucket: 桶名
        :param: configuration: 实时日志配置
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketRealTimeLogOutput
        """
        data = to_put_bucket_real_time_log(configuration)
        data = json.dumps(data)
        headers = {"Content-MD5": to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, params={'realtimeLog': ''},
                         headers=headers, data=data, generic_input=generic_input)
        return PutBucketRealTimeLogOutput(resp)

    def get_bucket_real_time_log(self, bucket: str, generic_input: GenericInput = None) -> GetBucketRealTimeLog:
        """ 获取实时日志

        :param: bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketRealTimeLogOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={'realtimeLog': ''},
                         generic_input=generic_input)
        return GetBucketRealTimeLog(resp)

    def delete_bucket_real_time_log(self, bucket: str, generic_input: GenericInput = None) -> DeleteBucketRealTimeLog:
        """ 删除桶实时日志配置

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteBucketRealTimeLog
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params={'realtimeLog': ''},
                         generic_input=generic_input)
        return DeleteBucketRealTimeLog(resp)

    def restore_object(self, bucket: str, key: str, days: int, version_id: str = None,
                       restore_job_parameters: RestoreJobParameters = None,
                       generic_input: GenericInput = None) -> RestoreObjectOutput:
        """ 取回对象
        :param bucket: 桶名
        :param key: 对象名
        :param version_id: 版本id
        :param days: 恢复天数
        :param restore_job_parameters: 取回方式
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: RestoreObjectOutput
        """
        data = to_restore_object(days, restore_job_parameters)
        data = json.dumps(data)

        headers = {"Content-MD5": to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}
        params = {"restore": ""}
        if version_id:
            params["versionId"] = version_id

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Post.value,
                         params=params, headers=headers, data=data, generic_input=generic_input)

        return RestoreObjectOutput(resp)

    def rename_object(self, bucket: str, key: str, new_key: str, generic_input: GenericInput = None):
        """ 重命名对象
        :param bucket: 桶名
        :param key: 对象名
        :param new_key: 新对象名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: RenameObjectOutput
        """
        _is_valid_object_name(new_key)
        params = {"rename": "", "name": new_key}
        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Put.value, params=params,
                         generic_input=generic_input)
        return RenameObjectOutput(resp)

    def get_bucket_rename(self, bucket: str, generic_input: GenericInput = None):
        """ 获取桶rename是否开启rename功能
        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketRenameOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params={"rename": ""},
                         generic_input=generic_input)
        return GetBucketRenameOutput(resp)

    def put_bucket_rename(self, bucket: str, rename_enable: bool, generic_input: GenericInput = None):
        """ 设置开启rename功能
        :param bucket: 桶名
        :param rename_enable: 是否开启桶rename功能
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketRenameOutput
        """
        data = {"RenameEnable": rename_enable}
        data = json.dumps(data)

        headers = {"Content-MD5": to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, data=data, headers=headers,
                         params={"rename": ""}, generic_input=generic_input)
        return PutBucketRenameOutput(resp)

    def delete_bucket_rename(self, bucket: str, generic_input: GenericInput = None):
        """ 删除桶rename功能
        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteBucketRenameOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params={"rename": ""},
                         generic_input=generic_input)
        return DeleteBucketRenameOutput(resp)

    def put_bucket_encryption(self, bucket: str, rule: BucketEncryptionRule,
                              generic_input: GenericInput = None) -> PutBucketEncryptionOutput:
        """ 设置桶加密规则

        :param bucket: 桶名
        :param rule: 规则
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: PutBucketEncryptionOutput
        """
        data = to_bucket_encrypt(rule)
        data = json.dumps(data)
        headers = {"Content-MD5": to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}
        resp = self._req(bucket=bucket, data=data, params={'encryption': ''}, headers=headers,
                         method=HttpMethodType.Http_Method_Put.value, generic_input=generic_input)
        return PutBucketEncryptionOutput(resp)

    def get_bucket_encryption(self, bucket, generic_input: GenericInput = None) -> GetBucketEncryptionOutput:
        """ 获取桶加密规则

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: GetBucketEncryptionOutput
        """

        resp = self._req(bucket=bucket, params={'encryption': ''}, method=HttpMethodType.Http_Method_Get.value,
                         generic_input=generic_input)
        return GetBucketEncryptionOutput(resp)

    def delete_bucket_encryption(self, bucket: str,
                                 generic_input: GenericInput = None) -> DeleteBucketEncryptionOutput:
        """ 删除桶加密规则

        :param bucket: 桶名
        :param generic_input: 通用请求参数，比如request_date设置签名UTC时间，代表本次请求Header中指定的 X-Tos-Date 头域
        :return: DeleteBucketEncryptionOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params={'encryption': ''},
                         generic_input=generic_input)
        return DeleteBucketEncryptionOutput(resp)

    def set_object_expires(self,bucket: str,
                           key: str,
                           object_expires:int,
                           version_id: str = None,
                           generic_input: GenericInput = None)-> SetObjectExpiresOutput:
        """ 设置对象生命周期
        :param bucket: 桶名
        :param key: 对象名
        :param object_expires: 过期时间，设置为N表示N天后过期，设置为0表示清除对象TTL，设置为负数非法
        :param version_id: 版本号
        :param generic_input: 通用请求参数
        :return: SetObjectExpiresOutput
        """
        _is_valid_object_name(key)

        params = {'objectExpires': ''}
        if version_id:
            params['versionId'] = version_id

        data = {"ObjectExpires": object_expires}
        data = json.dumps(data)

        resp = self._req(bucket,key,HttpMethodType.Http_Method_Post.value,data,params=params,generic_input=generic_input)

        return SetObjectExpiresOutput(resp)

    def put_bucket_inventory(self,bucket: str,
                             bucket_inventory_configuration:BucketInventoryConfiguration,
                             generic_input: GenericInput = None) -> PutBucketInventoryOutput:
        """ 设置桶清单配置
        :param bucket: 桶名
        :param bucket_inventory_configuration: 桶清单规则
        :param generic_input: 通用请求参数
        :return: PutBucketInventoryOutput
        """
        params = {'inventory': ''}
        if bucket_inventory_configuration:
            params['id'] = bucket_inventory_configuration.inventory_id
        data = bucket_inventory_configuration.to_json()
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, params=params,data=data, generic_input=generic_input)
        return PutBucketInventoryOutput(resp)

    def get_bucket_inventory(self,bucket: str,inventory_id:str,generic_input: GenericInput = None) ->GetBucketInventoryOutput:
        """ 查看某个存储桶中指定桶清单规则
        :param bucket: 桶名
        :param inventory_id: 桶清单名称
        :param generic_input: 通用请求参数
        :return: GetBucketInventoryOutput
        """
        params = {'inventory': '',"id":inventory_id}
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params=params,  generic_input=generic_input)
        return GetBucketInventoryOutput(resp)

    def list_bucket_inventory(self,bucket: str,continuation_token:str = None,generic_input: GenericInput = None)->ListBucketInventoryOutput:
        """ 批量获取存储桶中的所有桶清单的规则
        :param bucket: 桶名
        :param continuation_token: 获取超过 100 条桶清单规则时，携带 continuation-token 的请求消息格式，使得本次返回的桶清单从上一次请求返回的桶清单后继续进行列举
        :param generic_input: 通用请求参数
        :return: ListBucketInventoryOutput
        """
        params = {'inventory': ''}
        if continuation_token:
            params['continuation-token'] = continuation_token
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params=params,generic_input=generic_input)
        return ListBucketInventoryOutput(resp)

    def delete_bucket_inventory(self,bucket: str,inventory_id:str,generic_input: GenericInput = None)->DeleteBucketInventoryOutput:
        """ 删除桶清单配置
        :param bucket:桶名
        :param inventory_id: 桶清单名称
        :param generic_input: 通用请求参数
        :return: DeleteBucketInventoryOutput
        """
        params = {'inventory': '',"id":inventory_id}
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value, params=params,
                         generic_input=generic_input)
        return DeleteBucketInventoryOutput(resp)

    def simple_query(self,account_id:str,dataset_name:str,sort:str=None,order:QueryOrderType=None,max_results:int=100,next_token:str=None,
                     with_fields:List[str]=None,query:QueryRequest=None,aggregations:List[AggregationRequest]=None,
                     generic_input: GenericInput = None)->SimpleQueryOutput:
        """  标量精确查询
        :param account_id: 租户ID
        :param dataset_name: 数据集名称，同一个账户下唯一
        :param sort: 排序字段列表,多个排序字段可使用半角逗号（,）分隔，例如：Size, Filename
        :param order: 排序字段的排序方式
        :param max_results: 返回文件元数据的最大个数
        :param next_token: 用于翻页的 token
        :param with_fields: 仅返回特定字段的值，而不是全部已有的元信息字段
        :param query: 查询参数条件
        :param aggregations: 聚合字段信息列表。当您使用聚合查询时，仅返回聚合结果，不再返回匹配到的元信息列表
        :param generic_input: 通用请求参数
        :return: SimpleQueryOutput
        """
        params = {'mode': 'SimpleQuery'}
        data = to_simple_query(dataset_name,sort,order,max_results,next_token,with_fields,query,aggregations)
        resp = self._req(key="datasetquery",method=HttpMethodType.Http_Method_Post.value,data=data,params=params,
                         generic_input=generic_input,account_id=account_id,is_control_req=True)
        return SimpleQueryOutput(resp)

    def semantic_query(self,account_id:str,dataset_name:str,semantic_query_input:str,semantic_query_type:SemanticQueryType,
                       max_results:int=100,with_fields:List[str]=None,query:QueryRequest=None,generic_input: GenericInput = None)->SemanticQueryOutput:
        """  向量混合查询
        :param account_id: 租户ID
        :param dataset_name: 数据集名称，同一个账户下唯一
        :param semantic_query_input: 语义
        :param semantic_query_type: 语义搜索类型
        :param max_results: 返回文件元数据的最大个数
        :param with_fields: 仅返回特定字段的值，而不是全部已有的元信息字段
        :param query: 查询参数条件，可包含 SubQueries
        :param generic_input: 通用请求参数
        :return: SemanticQueryOutput
        """
        params = {'mode': 'SemanticQuery'}
        data = to_semantic_query(dataset_name,semantic_query_input,semantic_query_type,max_results,with_fields,query)
        resp = self._req(key="datasetquery", method=HttpMethodType.Http_Method_Post.value, data=data, params=params,
                         generic_input=generic_input, account_id=account_id, is_control_req=True)
        return SemanticQueryOutput(resp)



    def _req(self, bucket=None, key=None, method=None, data=None, headers=None, params=None, func=None,
             generic_input=None,account_id=None,is_control_req=None):
        consume_body()
        # 获取调用方法的名称
        func_name = func or traceback.extract_stack()[-2][2]
        if key is not None and is_control_req is None:
            _is_valid_object_name(key)
        key = to_str(key)
        if is_control_req and not account_id:
            raise exceptions.TosClientError("account_id can't be empty")

        headers = self._to_case_insensitive_dict(headers)
        params = self._sanitize_dict(params)

        if is_control_req:
            headers["x-tos-account-id"] = account_id

        if headers.get('x-tos-content-sha256') is None:
            headers['x-tos-content-sha256'] = UNSIGNED_PAYLOAD

        # 通过变量赋值,防止动态调整 auth endpoint 出现并发问题
        auth = self.auth
        endpoint = self.endpoint
        control_endpoint = self.control_endpoint
        if not self.is_custom_domain and bucket is not None:
            _is_valid_bucket_name(bucket)
        req_bucket = None if self.is_custom_domain else bucket

        req_url = self._make_virtual_host_url(req_bucket, key) if is_control_req is None else self._make_control_url(account_id, key)
        req_host = _get_virtual_host(req_bucket, endpoint) if is_control_req is None else _get_control_host(account_id, control_endpoint)
        req = Request(method, req_url,
                      _make_virtual_host_uri(key),
                      req_host,
                      data=data,
                      params=params,
                      headers=headers,
                      generic_input=generic_input)

        # 若为网络流对象删除headers中的content-length，防止签名计算错误
        if isinstance(data, _IterableAdapter) and headers.get('content-length'):
            del req.headers['content-length']

        # 若auth 为空即为匿名请求，则不计算签名
        if auth is not None:
            auth.sign_request(req)

        if 'User-Agent' not in req.headers:
            req.headers['User-Agent'] = self.user_agent

        # 通过变量赋值，防止动态调整 max_retry_count 出现并发问题
        retry_count = self.max_retry_count
        rsp = None
        host = headers['Host']
        for i in range(0, retry_count + 1):
            info = LogInfo()
            # 采用指数避让策略
            if i != 0:
                sleep_time = self._get_sleep_time(rsp, i)
                get_logger().info('in-request: sleep {}s'.format(sleep_time))
                time.sleep(sleep_time)
                req.headers['x-sdk-retry-count'] = 'attempt=' + str(i) + '; max=' + str(retry_count)
                req = _signed_req(auth, req, host)
            try:
                # 对于网络流的对象, 删除header中的 host 元素
                # 对于能获取大小的流对象，但size==0, 删除header中的 host 元素
                if isinstance(data, _IterableAdapter) or (isinstance(data, _ReaderAdapter) and data.size == 0):
                    del req.headers['Host']
                # 由于TOS的重定向场景尚未明确, 目前关闭重定向功能
                stream = False if method == HttpMethodType.Http_Method_Head.value else True
                res = self.session.request(method,
                                           req.url,
                                           data=req.data,
                                           headers=req.headers,
                                           params=req.params,
                                           stream=stream,
                                           timeout=(self.connection_time, self.socket_timeout),
                                           verify=self.enable_verify_ssl,
                                           proxies=self.proxies,
                                           allow_redirects=False)
                rsp = Response(res)
                if rsp.status >= 300 or (rsp.status == 203 and func_name in CALLBACK_FUNCTION):
                    raise exceptions.make_server_error(rsp,key)

                content_length = get_value(rsp.headers, 'content-length', int)
                if content_length is not None and content_length == 0:
                    rsp.read()
                info.success(func_name, rsp)
                return rsp

            except (requests.RequestException, TosServerError) as e:
                get_logger().info('Exception: %s', e)
                if isinstance(e, TosServerError):
                    can_retry = _handler_retry_policy(req.data, method, func_name, server_exp=e)
                    exp = e
                else:
                    can_retry = _handler_retry_policy(req.data, method, func_name, client_exp=e)
                    exp = TosClientError('http request timeout', e)

                if can_retry and i < retry_count:
                    get_logger().info(
                        'in-request: retry success data:{} method:{} func_name:{}, exp:{}'.format(req.data, method,
                                                                                                  func_name, exp))
                    continue
                get_logger().info(
                    'in-request: retry fail data:{} method:{} func_name:{}, exp:{}'.format(req.data, method,
                                                                                           func_name, e))

                exp.request_url = req.get_request_url()
                info.fail(func_name, exp)

    def _get_sleep_time(self, rsp, retry_count):
        sleep_time = SLEEP_BASE_TIME * math.pow(2, retry_count - 1)
        if sleep_time > 60:
            sleep_time = 60
        if rsp and (rsp.status == 429 or rsp.status == 503) and 'retry-after' in rsp.headers:
            try:
                sleep_time = max(int(rsp.headers['retry-after']), sleep_time)
            except Exception as e:
                get_logger().warning('try to parse retry-after from headers error: {}'.format(e))
        return sleep_time

    def _to_case_insensitive_dict(self, headers: dict):
        self._sanitize_dict(headers)
        return CaseInsensitiveDict(headers)

    def _sanitize_dict(self, d: dict):
        if d:
            for k, v in d.items():
                d[k] = v if isinstance(v, str) else v.decode() if isinstance(v, bytes) else str(v)
        return d

    def _open_dns_cache(self):
        dns_cache_time = self.dns_cache_time
        start_succeed = _dns_cache.async_refresh_cache(dns_cache_time)

        def get_connect(host, port, cache_entry,
                        timeout,
                        source_address,
                        socket_options):
            if cache_entry is None:
                info = resolve_ip_list(host, port)
                if info and len(info) > 0:
                    cache_entry = _dns_cache.add(host, port, info, int(time.time()) + dns_cache_time)
                    return create_connection(cache_entry, timeout, source_address, socket_options)
            else:
                get_logger().info('in-request cache dns host: {}, port: {}'.format(host, port))
                return create_connection(cache_entry, timeout, source_address, socket_options)

        def create_connection(cache_entry, timeout, source_address, socket_options):
            for res in cache_entry.copy_ip_list():
                af, socktype, proto, canonname, sa = res
                sock = None
                try:
                    sock = socket.socket(af, socktype, proto)
                    # If provided, set socket level options before connecting.
                    _set_socket_options(sock, socket_options)

                    if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                        sock.settimeout(timeout)
                    if source_address:
                        sock.bind(source_address)
                    sock.connect(sa)
                    return sock
                except socket.error:
                    cache_entry.remove(res)
                    if sock is not None:
                        sock.close()

            return None

        def patched_create_connection(address,
                                      timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                                      source_address=None,
                                      socket_options=None, ):
            """Wrap urllib3's create_connection to resolve the name elsewhere"""
            # resolve hostname to an ip address; use your own
            # resolver here, as otherwise the system resolver will be used.
            global _dns_cache
            host, port = address

            if utils.is_ip(host):
                get_logger().info('in-request: ip request {} port {}'.format(host, port))
                return _orig_create_connection(address, timeout, source_address, socket_options)

            cache_entry = _dns_cache.get_ip_list(host, port)
            conn = get_connect(host, port, cache_entry, timeout, source_address, socket_options)
            # cache_entry 查询 DNS
            return conn if conn else _orig_create_connection(address, timeout, source_address, socket_options)

        if start_succeed:
            connection.create_connection = patched_create_connection

        return start_succeed


def get_real_host(host):
    arr = host.split('.')
    if len(arr) == 4 and arr[1].startswith('tos-cn'):
        arr.pop(0)
        real_host = '.'.join(arr)
        return real_host
    return host


def hook_request_log(r, *args, **kwargs):
    get_logger().debug(
        'in-request: method:{} host:{} requestURI:{} used time: {}'.format(r.request.method, r.request.url,
                                                                           r.request.path_url,
                                                                           r.elapsed.total_seconds()))


def _is_valid_expires(expires):
    """
    过期时间最大为7天
    """
    if 1 <= expires <= 604800:
        return True
    else:
        return False


def _is_valid_object_name(object_name):
    """
    - 对象名命名规范
    - 对象名字符长度不能0；
    - 对象名不允许为 . 由于 requests 库中 _remove_path_dot_segments 方法会将 虚拟主机请求 {bucket}.{host}/. 强制转化为 {bucket}.{host}/ 导致最后签名报错
    SDK 会对依照该规范做校验，如果用户指定的对象名与规范不匹配则报错客户端校验失败。
    """
    if len(object_name) < 1:
        raise exceptions.TosClientError('invalid object name, object name is empty')

    if object_name == '.' or object_name == '..':
        raise exceptions.TosClientError("invalid object name, the object name can not use '.'")


def _is_valid_bucket_name(bucket_name):
    """
    桶命名规范：
    - 桶名字符长度为 3~63 个字符；
    - 桶名字符集包括：小写字母 a-z、数字 0-9 和连字符 '-'；
    - 桶名不能以连字符 '-' 作为开头或结尾；
    SDK 会对依照该规范做校验，如果用户指定的桶名与规范不匹配则报错客户端校验失败
    """
    if len(bucket_name) < 3 or len(bucket_name) > 63:
        raise exceptions.TosClientError('invalid bucket name, the length must be [3, 63]')

    if bucket_name[0] == '-' or bucket_name[len(bucket_name) - 1] == '-':
        raise exceptions.TosClientError(
            "invalid bucket name, the bucket name can be neither starting with ' - ' nor ending with ' - '")

    for i in range(0, len(bucket_name)):
        if not ('a' <= bucket_name[i] <= 'z' or '0' <= bucket_name[i] <= '9' or bucket_name[i] == '-'):
            raise exceptions.TosClientError('invalid bucket name, the character set is illegal')


def _get_parts_of_task(total_size, part_size):
    parts = []
    num_parts = utils.get_number(total_size, part_size)

    for i in range(num_parts):
        if i == num_parts - 1:
            start = i * part_size
            end = total_size
        else:
            start = i * part_size
            end = part_size + start

        parts.append(_PartToDo(i + 1, start, end))

    return parts


def _handler_retry_policy(body, method, fun_name, client_exp: requests.RequestException = None,
                          server_exp: TosServerError = None, skip=False) -> bool:
    get_logger().info(
        'in-request do retry with, body:{}, method:{}, func:{} server_exp:{}, client_exp'.format(body, method, fun_name,
                                                                                                 server_exp,
                                                                                                 client_exp))
    if skip or _is_func_can_retry(method, fun_name, client_exp, server_exp):
        if _is_wrapper_data(body):
            if body.can_reset:
                body.reset()
                return True
            return False
        return True
    return False


def _is_func_can_retry(method, fun_name,
                       client_exp: requests.RequestException = None,
                       server_exp: TosServerError = None) -> bool:
    if client_exp:
        return True
    if server_exp and (server_exp.status_code >= 500 or server_exp.status_code == 429 or server_exp.status_code == 408):
        # 对GET、HEAD直接返回
        if method in ["GET", "HEAD"]:
            return True

        # 对于PUT、DELETE、POST 请求方法的白名单
        if fun_name in WHITE_LIST_FUNCTION:
            return True
    return False


def _is_wrapper_data(data):
    if data is None:
        return False
    return isinstance(data, _ReaderAdapter) or isinstance(data, SizeAdapter) or isinstance(data, _IterableAdapter)
