# -*- coding: utf-8 -*-
import base64
import hashlib
import json
import logging
import math
import os
import platform
import shutil
import socket
import sys
import threading
import time
import traceback
import urllib.parse
from datetime import datetime
from typing import Dict

import requests
from requests.structures import CaseInsensitiveDict
from urllib3.util import connection
from urllib3.util.connection import allowed_gai_family, _set_socket_options

from tos import TosClient
from tos.__version__ import __version__
from . import exceptions, utils
from .auth import Auth
from .checkpoint import (CheckPointStore, _BreakpointDownloader,
                         _BreakpointUploader)
from .client import _make_virtual_host_url, _make_virtual_host_uri, _get_virtual_host, _get_host, _get_scheme
from .consts import (GMT_DATE_FORMAT, SLEEP_BASE_TIME, UNSIGNED_PAYLOAD,
                     WHITE_LIST_FUNCTION)
from .convertor import (convert_list_object_versions_output)
from .enum import (ACLType, AzRedundancyType, DataTransferType, HttpMethodType,
                   MetadataDirectiveType, StorageClassType, UploadEventType)
from .exceptions import TosClientError, TosServerError
from .http import Request, Response
from .json_utils import (to_complete_multipart_upload_request,
                         to_put_object_acl_request, to_delete_multi_objects_request)
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
                      _PartToDo)
from .utils import (SizeAdapter, _cal_upload_callback, _make_copy_source,
                    _make_range_string, _make_upload_part_file_content,
                    _ReaderAdapter, generate_http_proxies, get_content_type,
                    get_parent_directory_from_File, get_value, init_content,
                    is_utf8_with_trigger, meta_header_encode, to_bytes, to_str,
                    to_unicode, init_path, DnsCacheService, check_enum_type, check_part_size, check_part_number,
                    check_client_encryption_algorithm, check_server_encryption_algorithm, LogInfo, gen_key)

logger = logging.getLogger(__name__)
_dns_cache = DnsCacheService()
USER_AGENT = 'tos-python-sdk/{0}({1}/{2};{3})'.format(__version__, sys.platform, platform.machine(),
                                                      platform.python_version())

BASE_RETRY_DELAY_TIME = 500


def _get_create_bucket_headers(ACL: ACLType, AzRedundancy: AzRedundancyType, GrantFullControl, GrantRead, GrantReadACP,
                               GrantWrite,
                               GrantWriteACP, StorageClass: StorageClassType):
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
    return headers


def _get_copy_object_headers(ACL, CacheControl, ContentDisposition, ContentEncoding, ContentLanguage,
                             ContentType, CopySource, CopySourceIfMatch, CopySourceIfModifiedSince,
                             CopySourceIfNoneMatch, CopySourceIfUnmodifiedSince, Expires, GrantFullControl,
                             GrantRead, GrantReadACP, GrantWriteACP, Metadata, MetadataDirective,
                             SSECustomerAlgorithm, SSECustomerKey, SSECustomerKeyMD5, server_side_encryption,
                             website_redirect_location, storage_class: StorageClassType):
    headers = {}
    if Metadata:
        for k in Metadata:
            headers['x-tos-meta-' + k] = Metadata[k]
        headers = meta_header_encode(headers)
    if isinstance(CopySource, str):
        headers['x-tos-copy-source'] = CopySource
    elif isinstance(CopySource, dict):
        copy_source = CopySource['Bucket'] + '/' + CopySource['Key']
        if 'VersionId' in CopySource:
            copy_source = copy_source + '?versionId=' + CopySource['VersionId']
        headers['x-tos-copy-source'] = copy_source
    if MetadataDirective:
        headers['x-tos-metadata-directive'] = MetadataDirective.value
    if CacheControl:
        headers['cache-control'] = CacheControl
    if ContentDisposition:
        headers['content-disposition'] = urllib.parse.quote(ContentDisposition)
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
        headers['x-tos-server-side-encryption-customer-algorithm'] = SSECustomerAlgorithm
    if SSECustomerKey:
        headers['x-tos-server-side-encryption-customer-key'] = SSECustomerKey
    if SSECustomerKeyMD5:
        headers['x-tos-server-side-encryption-customer-key-md5'] = SSECustomerKeyMD5
    if server_side_encryption:
        headers['x-tos-server-side-encryption'] = server_side_encryption
    if website_redirect_location:
        headers['x-tos-website-redirect-location'] = website_redirect_location
    if storage_class:
        headers['x-tos-storage-class'] = storage_class.value
    return headers


def _get_list_object_params(Delimiter, EncodingType, Marker, MaxKeys, Prefix, Reverse):
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
    return params


def _get_list_object_version_params(Delimiter, EncodingType, KeyMarker, MaxKeys, Prefix, VersionIdMarker):
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


def _get_upload_part_copy_headers(CopySource, CopySourceIfMatch, CopySourceIfModifiedSince,
                                  CopySourceIfNoneMatch, CopySourceIfUnmodifiedSince, CopySourceRange,
                                  CopySourceSSECAlgorithm, CopySourceSSECKey, CopySourceSSECKeyMD5):
    headers = {}
    if isinstance(CopySource, str):
        headers['x-tos-copy-source'] = CopySource
    elif isinstance(CopySource, dict):
        copy_source = CopySource['Bucket'] + '/' + CopySource['Key']
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
        headers['x-tos-server-side-encryption-customer-algorithm'] = CopySourceSSECAlgorithm
    if CopySourceSSECKey:
        headers['x-tos-server-side-encryption-customer-key'] = CopySourceSSECKey
    if CopySourceSSECKeyMD5:
        headers['x-tos-server-side-encryption-customer-key-md5'] = CopySourceSSECKeyMD5
    return headers


def _get_put_object_headers(recognize_content_type, ACL, CacheControl, ContentDisposition, ContentEncoding,
                            ContentLanguage,
                            ContentLength, ContentMD5, ContentSha256, ContentType, Expires, GrantFullControl,
                            GrantRead, GrantReadACP, GrantWriteACP, Key, Metadata, SSECustomerAlgorithm,
                            SSECustomerKey, SSECustomerKeyMD5, ServerSideEncryption, StorageClass,
                            WebsiteRedirectLocation):
    headers = {}
    if Metadata:
        for k in Metadata:
            headers['x-tos-meta-' + k] = Metadata[k]
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
        headers['content-disposition'] = urllib.parse.quote(ContentDisposition)
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
    return headers


def _get_object_headers(IfMatch, IfModifiedSince, IfNoneMatch, IfUnmodifiedSince, Range, SSECustomerAlgorithm,
                        SSECustomerKey, SSECustomerKeyMD5):
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

    return headers


def _get_object_params(ResponseCacheControl, ResponseContentDisposition, ResponseContentEncoding,
                       ResponseContentLanguage, ResponseContentType, ResponseExpires, VersionId):
    params = {}
    if VersionId:
        params['versionId'] = VersionId
    if ResponseCacheControl:
        params['response-cache-control'] = ResponseCacheControl
    if ResponseContentDisposition:
        params['response-content-disposition'] = urllib.parse.quote(ResponseContentDisposition)
    if ResponseContentEncoding:
        params['response-content-encoding'] = ResponseContentEncoding
    if ResponseContentLanguage:
        params['response-content-language'] = ResponseContentLanguage
    if ResponseContentType:
        params['response-content-type'] = ResponseContentType
    if ResponseExpires:
        params['response-expires'] = ResponseExpires.strftime(GMT_DATE_FORMAT)
    return params


def _get_append_object_headers_params(recognize_content_type, ACL, CacheControl, ContentDisposition,
                                      ContentEncoding, ContentLanguage,
                                      ContentLength, ContentType, Expires, GrantFullControl, GrantRead,
                                      GrantReadACP, GrantWriteACP, Key, Metadata, StorageClass,
                                      WebsiteRedirectLocation):
    headers = {}
    if Metadata:
        for k in Metadata:
            headers['x-tos-meta-' + k] = Metadata[k]
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
        headers['content-disposition'] = urllib.parse.quote(ContentDisposition)
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
    return headers


def _get_create_multipart_upload_headers(recognize_content_type, ACL, CacheControl, ContentDisposition, ContentEncoding,
                                         ContentLanguage, ContentType,
                                         Expires, GrantFullControl, GrantRead, GrantReadACP,
                                         GrantWriteACP, Key, Metadata, SSECustomerAlgorithm, SSECustomerKey,
                                         SSECustomerKeyMD5, ServerSideEncryption, WebsiteRedirectLocation,
                                         StorageClass: StorageClassType):
    headers = {}
    if Metadata:
        for k in Metadata:
            headers['x-tos-meta-' + k] = Metadata[k]
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
        headers['content-disposition'] = urllib.parse.quote(ContentDisposition)
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

    return headers


def _get_set_object_meta_headers(recognize_content_type, cache_control, content_disposition, content_encoding,
                                 content_language,
                                 content_type, expires, key, meta):
    headers = {}
    if meta:
        for k in meta:
            headers['x-tos-meta-' + k] = meta[k]
        headers = meta_header_encode(headers)
    if cache_control:
        headers['cache-control'] = cache_control
    if content_disposition:
        headers['content-disposition'] = urllib.parse.quote(content_disposition)
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
    headers = {}
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
    return headers


def _get_upload_part_headers(content_length, content_md5, server_side_encryption, ssec_algorithm, ssec_key,
                             ssec_key_md5):
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

    return headers


def _valid_upload_checkpoint(bucket, store: CheckPointStore, key: str, modify_time, part_size) -> bool:
    if os.path.exists(store.path(bucket, key)):
        content = store.get(key=key, bucket=bucket)
        if content and content["file_info"]['last_modified'] == modify_time and content['part_size'] == part_size:
            return True

    return False


def _valid_download_checkpoint(bucket, store: CheckPointStore, key: str, etag: str, part_size) -> bool:
    if os.path.exists(store.path(bucket, key)):
        content = store.get(key=key, bucket=bucket)
        if content:
            object_info = content['object_info']
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


class TosClientV2(TosClient):
    def __init__(self, ak, sk, endpoint, region,
                 security_token=None,
                 auto_recognize_content_type=True,
                 max_retry_count=3,
                 request_timeout=60,
                 max_connections=1024,
                 enable_crc=True,
                 connection_time=10,
                 enable_verify_ssl=True,
                 dns_cache_time=0,
                 proxy_host: str = None,
                 proxy_port: int = None,
                 proxy_username: str = None,
                 proxy_password: str = None,
                 auth=None):

        """创建client

        :param ak: Access Key ID: 访问密钥ID，用于标识用户
        :param sk: Secret Access Key: 与访问密钥ID结合使用的密钥，用于加密签名
        :param security_token: 临时鉴权 Token
        :param endpoint: TOS 服务端域名，完整格式：https://{host}:{port}
        :param region: TOS 服务端所在区域
        :param auto_recognize_content_type: 使用自动识别 MIME 类型，默认为 true，代表开启自动识别 MIME 类型能力
        :param max_retry_count: 请求失败后最大的重试次数。默认3次
        :param 建立连接超时时间，单位：毫秒，默认 10000 毫秒
        :param request_timeout: 一次 HTTP 请求总超时时间，单位：毫秒，默认 60000 毫秒
        :param connection_time: 建立连接超时时间，单位：毫秒，默认 10000 毫秒
        :param max_connections: 连接池中允许打开的最大 HTTP 连接数，默认 1024
        :param enable_crc: 是否开启上传后客户端 CRC 校验，默认为 true
        :param enable_verify_ssl: 是否开启 SSL 证书校验，默认为 true
        :param dns_cache_time: DNS 缓存的有效期，单位：毫秒，小与等于 0 时代表关闭 DNS 缓存，默认为 0
        :param proxy_host: 代理服务器的主机地址，当前只支持 http 协议
        :param proxy_port: 代理服务器的端口
        :param proxy_username: 连接代理服务器时使用的用户名
        :param proxy_password: 代理服务使用的密码
        :param auth: 用户自定义auth
        :return TosClientV2:
        """
        if auth:
            super(TosClientV2, self).__init__(auth=auth,
                                              endpoint=endpoint,
                                              recognize_content_type=auto_recognize_content_type,
                                              connection_pool_size=max_connections,
                                              connect_timeout=connection_time)
        else:
            super(TosClientV2, self).__init__(auth=Auth(ak, sk, region, sts=security_token),
                                              endpoint=endpoint,
                                              recognize_content_type=auto_recognize_content_type,
                                              connection_pool_size=max_connections,
                                              connect_timeout=connection_time)
        self.max_retry_count = max_retry_count
        self.dns_cache_time = dns_cache_time
        self.request_timeout = request_timeout
        self.connection_time = connection_time
        self.enable_verify_ssl = enable_verify_ssl
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.enable_crc = enable_crc
        self.proxies = generate_http_proxies(proxy_host, proxy_port, proxy_username, proxy_password)

        # 控制动态调整初始参数
        self.lock = threading.RLock()
        # 通过 hook 机制实现in-request log
        self.session.hooks['response'].append(hook_request_log)

        # 开启DNS缓存
        if self.dns_cache_time is not None and self.dns_cache_time > 0:
            self._open_dns_cache()

    # def set_keys(self, new_ak=None, new_sk=None, new_security_token=None):
    #     """ 动态调整Access Key、Secret Access Key、 security_token。若相关参数未设置，则默认使用对应初始 Clinet2 值
    #
    #     :param new_ak: Access Key ID: 访问密钥ID，用于标识用户
    #     :param new_sk: Secret Access Key: 与访问密钥ID结合使用的密钥，用于加密签名
    #     :param new_security_token: 临时鉴权 Token
    #     """
    #     with self.lock:
    #         ak, sk, sts, region = self.auth.copy()
    #         auth = Auth(new_ak or ak, new_sk or sk, new_security_token or sts)
    #         self.auth = auth
    #
    # def set_endpoint_region(self, new_endpoint, new_region):
    #     """ 动态调整 new_endpoint new_region
    #     :param new_endpoint: TOS 服务端域名，完整格式：https://{host}:{port}
    #     :param new_region: TOS 服务端所在区域
    #     """
    #     with self.lock:
    #         if new_region:
    #             ak, sk, sts, region = self.auth.copy()
    #             auth = Auth(ak, sk, new_region or region, sts)
    #             self.auth = auth
    #         self.endpoint = new_endpoint or self.endpoint

    def pre_signed_url(self, http_method: HttpMethodType, bucket: str,
                       key: str = None,
                       expires: int = 3600,
                       header: Dict = None,
                       query: Dict = None,
                       alternative_endpoint: str = None):
        """生成签名url

        :param http_method: http方法
        :param bucket: 桶名
        :param key: 对象名
        :param expires: 过期时间（单位：秒），链接在当前时间再过expires秒后过期
        :param header: 需要签名的头部信息
        :param query: 需要签名的http查询参数
        :param alternative_endpoint:
        :return 签名url:如果该参数不为空，则声称的 signed url 使用该参数作为域名，而不是使用 TOS Client 初始化参数中的 endpoint
        """
        if not _is_valid_expires(expires):
            raise TosClientError('expires invalid')
        key = to_str(key)
        params = query or {}
        header = header or {}
        endpoint = alternative_endpoint or self.endpoint
        req = Request(
            http_method.value,
            _make_virtual_host_url(_get_host(endpoint), _get_scheme(endpoint), bucket, key),
            _make_virtual_host_uri(key),
            _get_virtual_host(bucket, endpoint),
            params=params,
            headers=header
        )
        signed_url = self.auth.sign_url(req, expires)
        signed_header = req.headers.copy()
        signed_header['host'] = signed_header['Host']
        signed_header.pop('Host')
        return PreSignedURLOutput(signed_url, signed_header)

    def create_bucket(self, bucket: str,
                      acl: ACLType = None,
                      grant_full_control: str = None,
                      grant_read: str = None,
                      grant_read_acp: str = None,
                      grant_write: str = None,
                      grant_write_acp: str = None,
                      storage_class: StorageClassType = None,
                      az_redundancy: AzRedundancyType = None) -> CreateBucketOutput:
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
        :return: CreateBucketOutput
        """

        _is_valid_bucket_name(bucket)

        check_enum_type(acl=acl, storage_class=storage_class, az_redundancy=az_redundancy)

        headers = _get_create_bucket_headers(acl, az_redundancy,
                                             grant_full_control,
                                             grant_read, grant_read_acp, grant_write,
                                             grant_write_acp, storage_class)

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Put.value, headers=headers)

        return CreateBucketOutput(resp)

    def head_bucket(self, bucket: str) -> HeadBucketOutput:
        """查询桶元数据

        此接口用于判断桶是否存在和是否有桶的访问权限。
        如果桶不存在或者没有访问桶的权限，此接口会返回404 Not Found或403 Forbidden状态码的TosServerError。

        :param bucket: 桶名
        :return: HeadBucketOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Head.value)

        return HeadBucketOutput(resp)

    def delete_bucket(self, bucket: str):
        """删除桶.

        删除已经创建的桶，删除桶之前，要保证桶是空桶，即桶中的对象和段数据已经被清除掉。

        :param bucket: 桶名
        :return: DeleteBucketOutput
        """
        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Delete.value)

        return DeleteBucketOutput(resp)

    def list_buckets(self) -> ListBucketsOutput:
        """ 列举桶

        :return: ListBucketsOutput
        """
        resp = self._req(method=HttpMethodType.Http_Method_Get.value)
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
                    storage_class: StorageClassType = None):
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
        :return: CopyObjectOutput
        """
        check_enum_type(acl=acl, metadata_directive=metadata_directive, storage_class=storage_class)

        check_client_encryption_algorithm(copy_source_ssec_algorithm)

        check_server_encryption_algorithm(server_side_encryption)

        copy_source = _make_copy_source(src_bucket, src_key, src_version_id)

        headers = _get_copy_object_headers(acl, cache_control, content_disposition, content_encoding, content_language,
                                           content_type, copy_source, copy_source_if_match,
                                           copy_source_if_modified_since,
                                           copy_source_if_none_match, copy_source_if_unmodified_since, expires,
                                           grant_full_control, grant_read, grant_read_acp, grant_write_acp, meta,
                                           metadata_directive, copy_source_ssec_algorithm, copy_source_ssec_key,
                                           copy_source_ssec_key_md5, server_side_encryption, website_redirect_location,
                                           storage_class)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Put.value, headers=headers)

        return CopyObjectOutput(resp)

    def delete_object(self, bucket: str, key: str, version_id: str = None):
        """删除对象

        :param bucket: 桶名
        :param key: 对象名
        :param version_id: 版本号
        :return: DeleteObjectOutput
        """
        params = {}
        if version_id:
            params = {'versionId': version_id}
        resp = self._req(bucket=bucket, key=key, params=params, method=HttpMethodType.Http_Method_Delete.value)

        return DeleteObjectOutput(resp)

    def delete_multi_objects(self, bucket: str, objects: [], quiet: bool = False):
        """批量删除对象

        在开启版本控制的桶中，在调用DeleteMultiObjects接口来批量删除对象时，如果在Delete请求中未指定versionId，
        将插入删除标记。如果指定了versionId，将永久删除该对象的指定版本。

        批量删除对象支持的响应方式可以通过quiet进行设置。quiet为false时，是指在返回响应时，
        不管对象是否删除成功都将删除结果包含在响应里；quiet为true时，是指在返回响应时，只返回删除失败的对象结果，
        没有返回的认为删除成功。

        :param bucket: 桶名
        :param objects: 对象名
        :param quiet: 版本号
        :return: DeleteObjectsOutput
        """

        data = to_delete_multi_objects_request(objects, quiet)
        data = json.dumps(data)

        headers = {'Content-MD5': to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))}

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Post.value, data=data, headers=headers,
                         params={'delete': ''})

        return DeleteObjectsOutput(resp)

    def get_object_acl(self, bucket: str, key: str,
                       version_id: str = None) -> GetObjectACLOutput:
        """获取对象的acl

        :param bucket: 桶名
        :param key: 对象名
        :param version_id: 版本号
        :return: GetObjectACLOutput

        """
        params = {'acl': ''}
        if version_id:
            params['versionId'] = version_id
        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Get.value, params=params)

        return GetObjectACLOutput(resp)

    def head_object(self, bucket: str, key: str,
                    version_id: str = None,
                    if_match: str = None,
                    if_modified_since: datetime = None,
                    if_none_match: str = None,
                    if_unmodified_since: datetime = None,
                    ssec_algorithm: str = None,
                    ssec_key: str = None,
                    ssec_key_md5: str = None) -> HeadObjectOutput:

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

        :return: HeadObjectOutput
        """
        check_client_encryption_algorithm(ssec_algorithm)

        headers = _get_object_headers(if_match, if_modified_since, if_none_match, if_unmodified_since, None,
                                      ssec_algorithm, ssec_key, ssec_key_md5)

        params = {}

        if version_id:
            params['versionId'] = version_id
        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Head.value, params=params,
                         headers=headers)

        return HeadObjectOutput(resp)

    def list_objects(self, bucket: str,
                     prefix: str = None,
                     delimiter: str = None,
                     marker: str = None,
                     max_keys: int = None,
                     reverse: bool = None,
                     encoding_type: str = None) -> ListObjectsOutput:
        """列举对象

        :param bucket: 桶名
        :param delimiter: 目录分隔符
        :param encoding_type: 返回key编码类型
        :param marker: 分页标志
        :param max_keys: 最大返回数
        :param prefix: 前缀
        :param reverse: 反向
        :return: ListObjectsOutput
        """
        params = _get_list_object_params(delimiter, encoding_type, marker, max_keys, prefix, reverse)

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params=params)

        return ListObjectsOutput(resp)

    def list_object_versions(self, bucket: str,
                             prefix: str = None,
                             delimiter: str = None,
                             key_marker: str = None,
                             version_id_marker: str = None,
                             max_keys: int = None,
                             encoding_type: str = None):
        """列举多版本对象

        :param bucket: 桶名
        :param delimiter: 分隔符
        :param encoding_type: 返回key编码类型
        :param key_marker: 分页标志
        :param max_keys: 最大返回值
        :param prefix: 前缀
        :param version_id_marker: 版本号分页标志
        :return: ListObjectVersionsOutput
        """
        params = _get_list_object_version_params(delimiter, encoding_type, key_marker, max_keys, prefix,
                                                 version_id_marker)

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params=params)

        return convert_list_object_versions_output(resp)

    def put_object_acl(self, bucket: str, key: str,
                       version: str = None,
                       acl: ACLType = None,
                       grant_full_control: str = None,
                       grant_read: str = None,
                       grant_read_acp: str = None,
                       grant_write_acp: str = None,
                       owner: Owner = None,
                       grants: [] = None) -> PutObjectACLOutput:
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
            body = to_put_object_acl_request(owner, grants)
            data = json.dumps(body)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Put.value, params=params,
                         headers=headers, data=data)

        return PutObjectACLOutput(resp)

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
                   content=None) -> PutObjectOutput:
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
        :param content: 数据
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
                                          server_side_encryption, storage_class, website_redirect_location)

        if content:
            content = init_content(content)

            if data_transfer_listener:
                content = utils.add_progress_listener_func(content, data_transfer_listener)

            if rate_limiter:
                content = utils.add_rate_limiter_func(content, rate_limiter)

            if self.enable_crc:
                content = utils.add_crc_func(content)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Put.value, data=content,
                         headers=headers)

        try:

            result = PutObjectOutput(resp)
            if data_transfer_listener:
                data_transfer_listener(content.len, content.len, 0, DataTransferType.Data_Transfer_Succeed)
            if self.enable_crc:
                if content:
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
                             rate_limiter=None,
                             ) -> PutObjectOutput:
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
                                   data_transfer_listener, rate_limiter, f)

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
                      pre_hash_crc64_ecma: int = 0
                      ):
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
        :param pre_hash_crc64_ecma: 上一次crc值，第一次上传设置为0
        """

        check_enum_type(acl=acl, storage_class=storage_class)

        _is_valid_object_name(key)

        params = {'append': '', 'offset': offset}

        headers = _get_append_object_headers_params(self.recognize_content_type, acl, cache_control,
                                                    content_disposition,
                                                    content_encoding,
                                                    content_language, content_length, content_type,
                                                    expires, grant_full_control, grant_read, grant_read_acp,
                                                    grant_write_acp, key, meta, storage_class,
                                                    website_redirect_location)

        if content:
            content = init_content(content)

            if data_transfer_listener:
                content = utils.add_progress_listener_func(content, data_transfer_listener)

            if rate_limiter:
                content = utils.add_rate_limiter_func(content, rate_limiter)

            if content and self.enable_crc and pre_hash_crc64_ecma is not None:
                content = utils.add_crc_func(content, init_crc=pre_hash_crc64_ecma)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Post.value, data=content,
                         headers=headers, params=params)

        result = AppendObjectOutput(resp)

        if self.enable_crc and result.hash_crc64_ecma is not None and pre_hash_crc64_ecma is not None:
            utils.check_crc('put object', content.crc, result.hash_crc64_ecma, resp.request_id)

        return result

    def set_object_meta(self, bucket: str, key: str,
                        version_id: str = None,
                        cache_control: str = None,
                        content_disposition: str = None,
                        content_encoding: str = None,
                        content_language: str = None,
                        content_type: str = None,
                        expires: datetime = None,
                        meta: Dict = None):
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
        :return: SetObjectMetaOutput
        """

        headers = _get_set_object_meta_headers(self.recognize_content_type, cache_control, content_disposition,
                                               content_encoding,
                                               content_language, content_type, expires, key, meta)

        params = {'metadata': ''}

        if version_id:
            params['versionId'] = version_id

        resp = self._req(bucket, key, HttpMethodType.Http_Method_Post.value,
                         headers=headers, params=params)

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
                   rate_limiter=None) -> GetObjectOutput:
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
        :return: GetObjectOutput
        """
        check_client_encryption_algorithm(ssec_algorithm)

        r = _make_range_string(range_start, range_end)

        headers = _get_object_headers(if_match, if_modified_since, if_none_match, if_unmodified_since, r,
                                      ssec_algorithm, ssec_key, ssec_key_md5)

        params = _get_object_params(response_cache_control, response_content_disposition, response_content_encoding,
                                    response_content_language, response_content_type, response_expires, version_id)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Get.value, headers=headers,
                         params=params)

        return GetObjectOutput(resp, progress_callback=data_transfer_listener, rate_limiter=rate_limiter,
                               enable_crc=self.enable_crc)

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
                           rate_limiter=None):
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
        :return: GetObjectOutput
        """

        check_client_encryption_algorithm(ssec_algorithm)

        with open(file_path, 'wb') as f:
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
                                     rate_limiter=rate_limiter
                                     )
            shutil.copyfileobj(result, f)

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
                                storage_class: StorageClassType = None) -> CreateMultipartUploadOutput:
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
                                                       server_side_encryption, website_redirect_location, storage_class)

        params = {'uploads': ''}
        if encoding_type:
            params['encoding-type'] = encoding_type

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Post.value, params=params,
                         headers=headers)

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
                    cancel_hook=None):

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
        if checkpoint_file and os.path.isdir(checkpoint_file):
            dir = checkpoint_file
        else:
            dir = get_parent_directory_from_File(os.path.abspath(file_path))

        store = CheckPointStore(dir, file_path)

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
                                                                  storage_class=storage_class)
            except (TosClientError, TosServerError) as e:
                if upload_event_listener:
                    _cal_upload_callback(upload_event_listener,
                                         UploadEventType.Upload_Event_Create_Multipart_Upload_Failed, e, bucket, key,
                                         "", store.path(bucket, key), None)
                raise e

            upload_id = create_mult_upload.upload_id

            _cal_upload_callback(upload_event_listener, UploadEventType.Upload_Event_Create_Multipart_Upload_Succeed,
                                 None, bucket, key, upload_id, store.path(bucket, key), None)

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

            parts = _get_parts_to_upload(size, part_size, [])

        uploader = _BreakpointUploader(self, bucket=bucket, key=key, file_path=file_path, store=store,
                                       task_num=task_num, parts_to_update=parts, upload_id=upload_id,
                                       record=record, datatransfer_listener=data_transfer_listener,
                                       upload_event_listener=upload_event_listener, cancel_hook=cancel_hook,
                                       rate_limiter=rate_limiter)

        result = uploader.upload()

        return UploadFileOutput(result, ssec_algorithm, ssec_key_md5, upload_id, record['encoding_type'])

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
                      cancel_hook=None):
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
        :return: HeadObjectOutput
        """
        check_client_encryption_algorithm(ssec_algorithm)

        # 校验待下载的本地文件路径有效性
        if not file_path:
            raise TosClientError('tos: file_path = {0} is invalid'.format(file_path))

        init_path(file_path)

        # 下载对象有效性
        result = self.head_object(bucket, key, version_id=version_id, if_match=if_match,
                                  if_modified_since=if_modified_since,
                                  if_none_match=if_none_match, if_unmodified_since=if_unmodified_since,
                                  ssec_algorithm=ssec_algorithm, ssec_key=ssec_key, ssec_key_md5=ssec_key_md5)

        dir = ""
        record = {}
        parts = []
        store = None

        if checkpoint_file and os.path.isdir(checkpoint_file):
            dir = checkpoint_file
        else:
            dir = get_parent_directory_from_File(os.path.abspath(file_path))

        if os.path.isfile(file_path):
            store = CheckPointStore(dir, file_path)
        else:
            store = CheckPointStore(dir, key)
            file_path = file_path + '/' + key

        if enable_checkpoint and _valid_download_checkpoint(bucket=bucket, store=store, key=key,
                                                            etag=result.etag, part_size=part_size):
            record = store.get(bucket=bucket, key=key)
            part_downloaded = []
            for p in record["parts_info"]:
                if p["is_completed"]:
                    part_downloaded.append(
                        DownloadPartInfo(p["part_number"], p["range_start"], p["range_end"], p["hash_crc64ecma"],
                                         p["is_completed"]))

            parts = _get_parts_to_download(size=result.content_length, part_size=part_size,
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
                    "object_size": result.content_length,
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
                record['if_modified_since'] = int(if_modified_since.timestamp())

            if if_none_match:
                record['if_none_match'] = if_none_match

            if if_unmodified_since:
                record['if_unmodified_since'] = if_unmodified_since.timestamp()
            parts = _get_parts_to_download(size=result.content_length, part_size=part_size, parts_downloaded=[])

        downloader = _BreakpointDownloader(client=self, bucket=bucket, key=key, file_path=file_path, store=store,
                                           task_num=task_num, parts_to_download=parts, record=record, etag=result.etag,
                                           datatransfer_listener=data_transfer_listener,
                                           download_event_listener=download_event_listener, rate_limiter=rate_limiter,
                                           cancel_hook=cancel_hook)

        downloader.download(result.hash_crc64_ecma)

        return result

    def upload_part(self, bucket: str, key: str, upload_id: str, part_number: int,
                    content_md5: str = None,
                    ssec_algorithm: str = None,
                    ssec_key: str = None,
                    ssec_key_md5: str = None,
                    server_side_encryption: str = None,
                    content_length: int = None,
                    content=None,
                    data_transfer_listener=None,
                    rate_limiter=None) -> UploadPartOutput:

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
        :param rate_limiter: 限速度
        以此实现io like 数据的超时重试
        :return: UploadPartOutput
        """
        check_client_encryption_algorithm(ssec_algorithm)

        check_server_encryption_algorithm(server_side_encryption)

        headers = _get_upload_part_headers(content_length, content_md5, server_side_encryption, ssec_algorithm,
                                           ssec_key, ssec_key_md5)

        if content:
            content = init_content(content)

            if data_transfer_listener:
                content = utils.add_progress_listener_func(content, data_transfer_listener)

            if rate_limiter:
                content = utils.add_rate_limiter_func(content, rate_limiter)

            if self.enable_crc:
                content = utils.add_crc_func(content)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Put.value,
                         params={'uploadId': upload_id, 'partNumber': part_number},
                         data=content, headers=headers)

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
                              offset: int = 0) -> UploadPartOutput:
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
                                    rate_limiter=rate_limiter
                                    )

    def complete_multipart_upload(self, bucket: str, key: str, upload_id: str, parts) -> CompleteMultipartUploadOutput:
        """ 合并段

        :param bucket: 桶名
        :param key: 对象名
        :param upload_id: 分段任务编号
        :param parts: 完成的分段任务
        :return: CompleteMultipartUploadOutput
        """
        body = to_complete_multipart_upload_request(parts)
        data = json.dumps(body)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Post.value,
                         params={'uploadId': upload_id}, data=data)

        return CompleteMultipartUploadOutput(resp)

    def abort_multipart_upload(self, bucket: str, key: str, upload_id: str) -> AbortMultipartUpload:
        """取消分片上传

        :param bucket: 桶名
        :param key: 对象名
        :param upload_id: 分片任务id
        :return: RequestResult
        """

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Delete.value,
                         params={'uploadId': upload_id})

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
                         copy_source_ssec_key_md5: str = None) -> UploadPartCopyOutput:
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
        :param copy_source_if_match: 只有当源对象的Etag与此参数指定的值相等时才进行复制对象操作。
        :param copy_source_if_modified_since: 如果自指定时间以来对象已被修改，则复制该对象。
        :param copy_source_if_none_match: 只有当源对象的Etag与此参数指定的值不相等时才进行复制对象操作。
        :param copy_source_if_unmodified_since: 如果自指定时间以来对象未被修改，则复制该对象。
        :param copy_source_ssec_key: SSE-C方式下使用该头域，指定解密源对象的加密密钥。此头域提供的加密密钥必须是创建源对象时使用的密钥。
        :param copy_source_ssec_key_md5: SSE-C方式下使用该头域，该头域表示解密源对象使用的密钥的MD5值。MD5值用于消息完整性检查，确认加密密钥传输过程中没有出错。
        :param copy_source_ssec_algorithm: ssec 加密算法

        return: UploadPartCopyOutput
        """
        check_client_encryption_algorithm(copy_source_ssec_algorithm)

        copy_source = _make_copy_source(src_bucket=src_bucket, src_key=src_key, src_version_id=src_version_id)

        copy_source_range = _make_range_string(copy_source_range_start, copy_source_range_end)

        headers = _get_upload_part_copy_headers(copy_source, copy_source_if_match, copy_source_if_modified_since,
                                                copy_source_if_none_match, copy_source_if_unmodified_since,
                                                copy_source_range, copy_source_ssec_algorithm, copy_source_ssec_key,
                                                copy_source_ssec_key_md5)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Put.value,
                         params={'uploadId': upload_id, 'partNumber': part_number},
                         headers=headers)

        return UploadPartCopyOutput(resp, part_number)

    def list_multipart_uploads(self, bucket: str,
                               prefix: str = None,
                               delimiter: str = None,
                               key_marker: str = None,
                               upload_id_marker: str = None,
                               max_uploads: int = 1000,
                               encoding_type: str = None) -> ListMultipartUploadsOutput:
        """列举正在进行的分片上传任务

        :param bucket: 桶名称
        :param prefix: 用于指定列举返回对象的前缀名称。可以使用此参数对桶中对象进行分组管理（类似文件夹功能）。
        :param delimiter: 用于对Object名称进行分组的字符。所有名称包含指定的前缀且首次出现delimiter字符之间的Object作为一组元素CommonPrefixes。
        :param key_marker: 与参数upload-id-marker一起使用
        :param upload_id_marker: 与参数key-marker一起使用
        :param max_uploads: 限定列举返回的分片上传任务数量，最大1000，默认1000。
        :param encoding_type: 指定对响应中的内容进行编码，指定编码的类型。如果请求中设置了encoding-type，
        那响应中的Delimiter、KeyMarker、Prefix（包括CommonPrefixes中的Prefix）、NextKeyMarker和Key会被编码。

        :return: ListMultipartUploadsOutput
        """
        params = _get_list_multipart_uploads_params(delimiter, encoding_type, key_marker, max_uploads, prefix,
                                                    upload_id_marker)

        resp = self._req(bucket=bucket, method=HttpMethodType.Http_Method_Get.value, params=params)

        return ListMultipartUploadsOutput(resp)

    def list_parts(self, bucket: str, key: str, upload_id: str,
                   part_number_marker: int = None,
                   max_parts: int = 1000) -> ListPartsOutput:
        """ 列举段

        :param bucket: 桶名
        :param key: 对象名称
        :param upload_id: 初始化分片任务返回的段任务ID，用于唯一标识上传的分片属于哪个对象。
        :param part_number_marker: 指定PartNumber的起始位置，只列举PartNumber大于此值的段。
        :param max_parts: 响应中最大的分片数量
        :return: ListPartsOutput
        """
        params = _get_list_parts_params(max_parts, part_number_marker, upload_id)

        resp = self._req(bucket=bucket, key=key, method=HttpMethodType.Http_Method_Get.value, params=params)

        return ListPartsOutput(resp)

    def _req(self, bucket=None, key=None, method=None, data=None, headers=None, params=None, func=None):
        # 获取调用方法的名称
        func_name = func or traceback.extract_stack()[-2][2]
        exp = None
        info = LogInfo()
        if key:
            try:
                _is_valid_object_name(key)
            except TosClientError as e:
                info.fail(func_name, e)

        key = to_str(key)

        headers = CaseInsensitiveDict(headers)

        if headers.get('x-tos-content-sha256') is None:
            headers['x-tos-content-sha256'] = UNSIGNED_PAYLOAD

        # 通过变量赋值,防止动态调整 auth endpoint 出现并发问题
        auth = self.auth
        endpoint = self.endpoint
        req = Request(method, self._make_virtual_host_url(bucket, key),
                      _make_virtual_host_uri(key),
                      _get_virtual_host(bucket, endpoint),
                      data=data,
                      params=params,
                      headers=headers)
        auth.sign_request(req)

        if 'User-Agent' not in req.headers:
            req.headers['User-Agent'] = USER_AGENT

        # 通过变量赋值，防止动态调整 max_retry_count 出现并发问题
        retry_count = self.max_retry_count
        for i in range(0, retry_count + 1):
            # 采用指数避让策略
            if i != 0:
                sleep_time = SLEEP_BASE_TIME * math.pow(2, i - 1)
                logger.info('in-request: sleep {}s'.format(sleep_time))
                time.sleep(sleep_time)
            try:
                # 由于TOS的重定向场景尚未明确, 目前关闭重定向功能
                res = self.session.request(method,
                                           req.url,
                                           data=req.data,
                                           headers=req.headers,
                                           params=req.params,
                                           stream=True,
                                           timeout=(self.connection_time, self.request_timeout),
                                           verify=self.enable_verify_ssl,
                                           proxies=self.proxies,
                                           allow_redirects=False)
                rsp = Response(res)
                if rsp.status >= 300:
                    raise exceptions.make_server_error(rsp)

                content_length = get_value(rsp.headers, 'content-length', int)
                if content_length is not None and content_length == 0:
                    rsp.read()
                info.success(func_name, rsp)
                return rsp

            except (requests.RequestException, TosServerError) as e:
                can_retry = False
                logger.info('Exception: %s', e)
                if isinstance(e, TosServerError):
                    can_retry = _handler_retry_policy(req.data, method, func_name, server_exp=e)
                    exp = e
                else:
                    # 客户端异常重试 交给requests 底层库实现
                    can_retry = _handler_retry_policy(req.data, method, func_name, client_exp=e)
                    exp = TosClientError('http request timeout', e)
                if can_retry:
                    logger.info(
                        'in-request: retry success data:{} method:{} func_name:{}, exp:{}'.format(req.data,
                                                                                                  method,
                                                                                                  func_name, exp))
                    continue
                else:
                    logger.info(
                        'in-request: retry fail data:{} method:{} func_name:{}, exp:{}'.format(req.data,
                                                                                               method,
                                                                                               func_name, e))
                    info.fail(func_name, exp)
                    raise exp
        info.fail(func_name, exp)
        raise exp

    def _open_dns_cache(self):
        _orig_create_connection = connection.create_connection

        def get_connect(host, port, cache_entry,
                        timeout,
                        source_address,
                        socket_options):
            if cache_entry is None:
                family = allowed_gai_family()
                info = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)

                if info and len(info) > 0:
                    expire = self.dns_cache_time
                    _dns_cache.add(host, port, info, int(time.time()) + expire)
                    cache_entry = _dns_cache.get_ip_list(host, port)
                    return create_connection(cache_entry, timeout, source_address, socket_options)

            else:
                logger.info('in-request cache dns host: {}, port: {}'.format(host, port))
                return create_connection(cache_entry, timeout, source_address, socket_options)

        def create_connection(cache, timeout, source_address, socket_options):
            for res in cache.copy_ip_list():
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
                    cache.remove(res)
                    if sock is not None:
                        sock.close()
                        sock = None

            _dns_cache.remove(gen_key(cache.host, cache.port))

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
                logger.info('in-request: ip request {} port {}'.format(host, port))
                return _orig_create_connection(address, timeout, source_address, socket_options)

            virtual_host = host
            real_host = get_real_host(virtual_host)
            if real_host:
                cache_entry_real = _dns_cache.get_ip_list(real_host, port)
                real_conn = get_connect(real_host, port, cache_entry_real, timeout, source_address, socket_options)
                if real_conn:
                    return real_conn

            cache_entry_virtual = _dns_cache.get_ip_list(virtual_host, port)
            virtual_conn = get_connect(host, port, cache_entry_virtual, timeout, source_address, socket_options)
            if virtual_conn:
                return virtual_conn

            # cache_entry_real 和 cache_entry_virtual 都为空 查询 DNS
            return _orig_create_connection(address, timeout, source_address, socket_options)

        if patched_create_connection.__name__ != connection.create_connection.__name__:
            connection.create_connection = patched_create_connection


def get_real_host(host):
    arr = host.split('.')
    if len(arr) == 4 and arr[1].startswith('tos-cn'):
        arr.pop(0)
        real_host = '.'.join(arr)
        return real_host
    return None


def hook_request_log(r, *args, **kwargs):
    logger.debug('in-request: method:{} host:{} requestURI:{} used time: {}'.format(r.request.method, r.request.url,
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
    - 对象名字符长度为 1~696 个字符；
    - 对象名字符集允许所有 UTF-8 编码的字符，但 <32 以及 =127 的 ASCII 码字符除外（这类字符都是不可见字符，空格 =32 是允许的）；
    - 对象名不能以正斜杠 '/' 或反斜杠 '\' 开头；
    - 对象名不允许为 . 由于 requests 库中 _remove_path_dot_segments 方法会将 虚拟主机请求 {bucket}.{host}/. 强制转化为 {bucket}.{host}/ 导致最后签名报错
    SDK 会对依照该规范做校验，如果用户指定的对象名与规范不匹配则报错客户端校验失败。
    """
    if len(object_name) < 1 or len(object_name) > 696:
        raise exceptions.TosClientError('invalid object name, the length must be [1, 696]')

    if object_name == '.' or object_name == '..':
        raise exceptions.TosClientError("invalid object name, the object name can not use '.'")

    if not is_utf8_with_trigger(object_name.encode("utf-8")):
        raise exceptions.TosClientError('invalid object name, the character set is illegal')

    if object_name[0] == '/' or object_name[0] == '\\':
        raise exceptions.TosClientError("invalid object name, the object name can not start with '/' or '\\'")


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
    logger.info(
        'in-request do retry with, body:{}, method:{}, func:{} server_exp:{}, client_exp'.format(body, method,
                                                                                                 fun_name,
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
    if client_exp and (not isinstance(client_exp, requests.ReadTimeout)):
        return True
    if server_exp and (server_exp.status_code >= 500 or server_exp.status_code == 429):
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
    return isinstance(data, _ReaderAdapter) or isinstance(data, SizeAdapter)
