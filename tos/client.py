# -*- coding: utf-8 -*-
import base64
import functools
import hashlib
import json
import logging
import warnings
from datetime import datetime
from hashlib import sha256
from typing import Dict
from typing import IO
from typing import Union
from urllib.parse import quote

import requests
from deprecated import deprecated
from requests.structures import CaseInsensitiveDict

from tos.__version__ import __version__
from . import exceptions
from .consts import CONNECT_TIMEOUT, PAYLOAD_BUFFER, EMPTY_SHA256_HASH, GMT_DATE_FORMAT
from .convertor import convert_list_buckets_result, convert_list_objects_result, convert_list_object_versions_result, \
    convert_list_multipart_uploads_result, convert_list_parts_result, convert_create_multipart_upload_result, \
    convert_upload_part_copy_result, convert_complete_multipart_upload_result, convert_copy_object_result, \
    convert_get_object_acl_result, convert_delete_objects_result
from .http import Request, Response
from .models import RequestResult, HeadBucketResult, CreateBucketResult, HeadObjectResult, \
    PutObjectResult, GetObjectResult, AppendObjectResult
from .utils import to_bytes, to_str, get_value, get_content_type

logger = logging.getLogger(__name__)

USER_AGENT = 'volc-tos-sdk-python/{0}'.format(__version__)

REGION_MAP = {'cn-beijing': 'tos-cn-beijing.volces.com', 'cn-guangzhou': 'tos-cn-guangzhou.volces.com',
              'cn-shanghai': 'tos-cn-shanghai.volces.com'}


def _is_valid_region(region: str):
    return region == 'cn-beijing' or region == 'cn-guangzhou' or region == 'cn-shanghai'


def _if_map(region: str, endpoint: str):
    if _is_valid_region(region):
        return REGION_MAP[region]
    else:
        return endpoint


class TosClient():
    def __init__(self, auth, endpoint, connect_timeout=None, connection_pool_size=10, recognize_content_type=True):
        self.auth = auth
        self.endpoint = self._format_endpoint(_if_map(auth.region, endpoint))
        self.host = self._get_host(endpoint)
        self.scheme = self._get_scheme(endpoint)
        self.timeout = connect_timeout or CONNECT_TIMEOUT
        self.recognize_content_type = recognize_content_type

        self.session = requests.Session()
        self.session.mount('http://', requests.adapters.HTTPAdapter(pool_connections=connection_pool_size,
                                                                    pool_maxsize=connection_pool_size))
        self.session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=connection_pool_size,
                                                                     pool_maxsize=connection_pool_size))

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def generate_presigned_url(self, Method: str, Bucket: str = None, Key: str = None, Params: Dict = None,
                               ExpiresIn: int = None):
        """
        ??????????????????url
        :param: Bucket: ??????
        :param: Key: ?????????
        :param: Params: ???????????????HTTP????????????
        :param: ExpiresIn: ????????????????????????, ?????????1?????????3600??????
        :param: HttpMethod: HTTP ????????? ???'GET', 'PUT' ???
        :return: ????????????url
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        key = to_str(Key)
        params = Params or {}
        req = Request(
            Method,
            self._make_virtual_host_url(Bucket, key),
            self._make_virtual_host_uri(key),
            self._get_virtual_host(Bucket, self.endpoint),
            params=params,
        )
        return self.auth._sign_url(req, ExpiresIn)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def create_bucket(self, Bucket: str, ACL: str = None, GrantFullControl: str = None, GrantRead: str = None,
                      GrantReadACP: str = None, GrantWrite: str = None, GrantWriteACP: str = None):
        """
        ??????bucket
        :param Bucket: ??????
        :param ACL: 'private'|'public-read'|'public-read-write'|'authenticated-read'|'bucket-owner-read'|
        'bucket-owner-full-control'
        :param GrantFullControl: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantRead: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantReadACP: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantWrite: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantWriteACP: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'

        :return: CreateBucketResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        headers = {}
        if ACL:
            headers['x-tos-acl'] = ACL

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

        resp = self._req(bucket=Bucket, method='PUT', headers=headers)
        logger.info(
            'create_bucket, bucket: {0}, req id: {1}, status code: {2}'.format(Bucket, resp.request_id, resp.status))
        return CreateBucketResult(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def delete_bucket(self, Bucket: str):
        """
        ????????????bucket???bucket?????????????????????????????????
        :param Bucket: ??????

        :return: RequestResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        resp = self._req(bucket=Bucket, method='DELETE')
        logger.info(
            'delete_bucket, bucket: {0}, req id: {1}, status code: {2}'.format(Bucket, resp.request_id, resp.status))
        return RequestResult(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def head_bucket(self, Bucket: str):
        """
        ????????????bucket??????
        :param Bucket: ??????
        :return: Response
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        resp = self._req(bucket=Bucket, method='HEAD')
        logger.info(
            'head_bucket, bucket: {0}, req id: {1}, status code: {2}'.format(Bucket, resp.request_id, resp.status))
        return HeadBucketResult(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def list_buckets(self):
        """
        ???????????????bucket

        :return: ListBucketResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        resp = self._req(method='GET')
        logger.info(
            'list_buckets, req id: {0}, status code: {1}'.format(resp.request_id, resp.status))
        return convert_list_buckets_result(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def list_objects(self, Bucket: str, Delimiter: str = None, EncodingType: str = None, Marker: str = None,
                     MaxKeys: int = None, Prefix: str = None):
        """
        ????????????
        :param Bucket: ??????
        :param Delimiter: ???????????????
        :param EncodingType: ??????key????????????
        :param Marker: ????????????
        :param MaxKeys: ???????????????
        :param Prefix: ??????

        :return: ListObjectsResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
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

        resp = self._req(bucket=Bucket, method='GET', params=params)
        logger.info(
            'list_objects, bucket: {0}, req id: {1}, status code: {2}'.format(Bucket, resp.request_id, resp.status))
        return convert_list_objects_result(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def list_object_versions(self, Bucket: str, Delimiter: str = None, EncodingType: str = None, KeyMarker: str = None,
                             MaxKeys: int = None, Prefix: str = None, VersionIdMarker: str = None):
        """
        ?????????????????????
        :param Bucket: ??????
        :param Delimiter: ?????????
        :param EncodingType: ??????key????????????
        :param KeyMarker: ????????????
        :param MaxKeys: ???????????????
        :param Prefix: ??????
        :param VersionIdMarker: ?????????????????????
        :return: ListObjectVersionsResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
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

        resp = self._req(bucket=Bucket, method='GET', params=params)
        logger.info(
            'list_object_versions, bucket: {0}, req id: {1}, status code: {2}'.format(Bucket, resp.request_id,
                                                                                      resp.status))
        return convert_list_object_versions_result(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def list_multipart_uploads(self, Bucket: str, Delimiter: str = None, EncodingType: str = None,
                               KeyMarker: str = None, MaxUploads: int = None, Prefix: str = None,
                               UploadIdMarker: str = None):
        """
        ????????????????????????????????????
        :param Bucket: ??????
        :param Delimiter: ???????????????
        :param EncodingType: 'url'
        :param KeyMarker: 'string'
        :param MaxUploads: ???????????????????????????
        :param Prefix: ??????
        :param UploadIdMarker: ????????????

        :return: ListMultipartUploadsResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
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

        resp = self._req(bucket=Bucket, method='GET', params=params)
        logger.info(
            'list_multipart_uploads, bucket: {0}, req id: {1}, status code: {2}'.format(Bucket, resp.request_id,
                                                                                        resp.status))
        return convert_list_multipart_uploads_result(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def list_parts(self, Bucket: str, Key: str, UploadId: str, MaxParts: int = None, PartNumberMarker: int = None):
        """
        ???????????????????????????
        :param Bucket: ??????
        :param Key: ?????????
        :param UploadId: ????????????id
        :param MaxParts: ???????????????????????????
        :param PartNumberMarker: ????????????

        :return: ListPartsResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        params = {'uploadId': UploadId}
        if MaxParts:
            params['max-parts'] = MaxParts
        if PartNumberMarker:
            params['part-number-marker'] = PartNumberMarker

        resp = self._req(bucket=Bucket, key=Key, method='GET', params=params)
        logger.info('list_parts, bucket: {0}, key: {1}, req id: {2}, status code: {3}'.format(
            Bucket, Key, resp.request_id, resp.status))
        return convert_list_parts_result(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def abort_multipart_upload(self, Bucket: str, Key: str, UploadId: str):
        """
        ??????????????????
        :param Bucket: ??????
        :param Key: ?????????
        :param UploadId: ????????????id

        :return: RequestResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        resp = self._req(bucket=Bucket, key=Key, method='DELETE', params={'uploadId': UploadId})
        logger.info(
            'abort_multipart_upload, bucket: {0}, key: {1}, uploadId: {2}, req id: {3}, status code: {4}'.format(
                Bucket, Key, UploadId, resp.request_id, resp.status))
        return RequestResult(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def create_multipart_upload(self, Bucket: str, Key: str, ACL: str = None, CacheControl: str = None,
                                ContentDisposition: str = None, ContentEncoding: str = None,
                                ContentLanguage: str = None, ContentType: str = None, Expires: datetime = None,
                                GrantFullControl: str = None, GrantRead: str = None, GrantReadACP: str = None,
                                GrantWriteACP: str = None, Metadata: Dict = None, SSECustomerAlgorithm: str = None,
                                SSECustomerKey: str = None, SSECustomerKeyMD5: str = None):
        """
        ?????????????????????
        :param Bucket: ??????
        :param Key: ?????????
        :param ACL: 'private'|'public-read'|'public-read-write'|'authenticated-read'|'bucket-owner-read'|
        'bucket-owner-full-control'
        :param CacheControl: ????????????
        :param ContentDisposition: ????????????
        :param ContentEncoding: ????????????
        :param ContentLanguage: ????????????
        :param ContentType: ????????????
        :param Expires: datetime(2021, 1, 1)
        :param GrantFullControl:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantRead:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantReadACP:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantWriteACP: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param Metadata: ??????????????????
        :param SSECustomerAlgorithm: 'AES256'
        :param SSECustomerKey: ????????????
        :param SSECustomerKeyMD5: ??????md5???

        :return: CreateMultipartUploadResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        headers = {}
        if Metadata:
            for k in Metadata:
                headers['x-tos-meta-' + k] = Metadata[k]

        if ACL:
            headers['x-tos-acl'] = ACL
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
            headers['content-disposition'] = ContentDisposition
        if ContentEncoding:
            headers['content-encoding'] = ContentEncoding
        if ContentLanguage:
            headers['content-language'] = ContentLanguage

        if ContentType:
            headers['content-type'] = ContentType
        elif self.recognize_content_type:
            headers['content-type'] = get_content_type(Key)

        if Expires:
            headers['expires'] = Expires.strftime(GMT_DATE_FORMAT)

        if SSECustomerAlgorithm:
            headers['x-tos-server-side-encryption-customer-algorithm'] = SSECustomerAlgorithm
        if SSECustomerKey:
            headers['x-tos-server-side-encryption-customer-key'] = SSECustomerKey
        if SSECustomerKeyMD5:
            headers['x-tos-server-side-encryption-customer-key-md5'] = SSECustomerKeyMD5

        resp = self._req(bucket=Bucket, key=Key, method='POST', params={'uploads': ''}, headers=headers)
        logger.info(
            'create_multipart_upload, bucket: {0}, key: {1}, req id: {2}, status code: {3}'.format(
                Bucket, Key, resp.request_id, resp.status))
        return convert_create_multipart_upload_result(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def upload_part(self, Bucket: str, Key: str, PartNumber: int, UploadId: str, Body: Union[bytes, IO] = None):
        """
        ????????????
        :param Bucket: ??????
        :param Key: ?????????
        :param PartNumber: ????????????????????????1
        :param UploadId: ????????????id
        :param Body: ??????

        :return: PutObjectResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        resp = self._req(bucket=Bucket, key=Key, method='PUT', params={'uploadId': UploadId, 'partNumber': PartNumber},
                         data=Body)
        logger.info(
            'upload_part, bucket: {0}, key: {1}, uploadId: {2}, partNumber: {3}, req id: {4}, status code: {5}'.format(
                Bucket, Key, UploadId, PartNumber, resp.request_id, resp.status))
        return PutObjectResult(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def upload_part_copy(self, Bucket: str, CopySource: Union[str, Dict], Key: str, PartNumber: int, UploadId: str,
                         CopySourceIfMatch: str = None, CopySourceIfModifiedSince: datetime = None,
                         CopySourceIfNoneMatch: str = None, CopySourceIfUnmodifiedSince: datetime = None,
                         CopySourceRange: str = None):
        """
        ????????????????????????????????????????????????????????????????????????
        :param Bucket: ????????????
        :param CopySource: ????????? 'string' or {'Bucket': 'string', 'Key': 'string', 'VersionId': 'string'}
        :param Key: ???????????????
        :param PartNumber: ???????????? ????????????1
        :param UploadId: ????????????id
        :param CopySourceIfMatch:
        :param CopySourceIfModifiedSince:
        :param CopySourceIfNoneMatch:
        :param CopySourceIfUnmodifiedSince:
        :param CopySourceRange:

        :return: UploadPartCopyResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
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

        resp = self._req(bucket=Bucket, key=Key, method='PUT', params={'uploadId': UploadId, 'partNumber': PartNumber},
                         headers=headers)
        logger.info(
            'upload_part_copy, bucket: {0}, key: {1}, uploadId: {2}, partNumber: {3}, req id: {4}, status code: {5}'.format(
                Bucket, Key, UploadId, PartNumber, resp.request_id, resp.status))
        return convert_upload_part_copy_result(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def complete_multipart_upload(self, Bucket: str, Key: str, UploadId: str, MultipartUpload: Dict = None):
        """
        ????????????
        :param Bucket: ??????
        :param Key: ?????????
        :param UploadId: ????????????id
        :param MultipartUpload: {
        'Parts': [
            {
                'ETag': 'string',
                'PartNumber': 123
            },
        ]
        }

        :return: CompleteMultipartUploadResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        data = json.dumps(MultipartUpload)
        resp = self._req(bucket=Bucket, key=Key, method='POST', params={'uploadId': UploadId}, data=data)
        logger.info(
            'complete_multipart_upload, bucket: {0}, key: {1}, uploadId: {2}, req id: {3}, status code: {4}'.format(
                Bucket, Key, UploadId, resp.request_id, resp.status))
        return convert_complete_multipart_upload_result(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def put_object(self, Bucket: str, Key: str, ACL: str = None, Body: Union[bytes, IO] = None,
                   CacheControl: str = None, ContentDisposition: str = None, ContentEncoding: str = None,
                   ContentMD5: str = None, ContentLanguage: str = None, ContentType: str = None,
                   Expires: datetime = None,
                   GrantFullControl: str = None, GrantRead: str = None, GrantReadACP: str = None,
                   GrantWriteACP: str = None, Metadata: Dict = None, SSECustomerAlgorithm: str = None,
                   SSECustomerKey: str = None, SSECustomerKeyMD5: str = None):
        """
        ????????????
        :param Bucket: ??????
        :param Key: ?????????
        :param ACL: 'private'|'public-read'|'public-read-write'|'authenticated-read'|'bucket-owner-read'|
        'bucket-owner-full-control'
        :param Body: ??????
        :param CacheControl: ????????????
        :param ContentDisposition: ????????????
        :param ContentEncoding: ????????????
        :param ContentLanguage: ????????????
        :param ContentType: ????????????
        :param Expires: datetime(2021, 1, 1)
        :param GrantFullControl:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantRead:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantReadACP:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantWriteACP: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param Metadata: ??????????????????
        :param SSECustomerAlgorithm: 'AES256'
        :param SSECustomerKey: ????????????
        :param SSECustomerKeyMD5: ??????md5???

        :return: PutObjectResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        headers = {}
        if Metadata:
            for k in Metadata:
                headers['x-tos-meta-' + k] = Metadata[k]
        if ACL:
            headers['x-tos-acl'] = ACL

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
            headers['content-disposition'] = ContentDisposition
        if ContentEncoding:
            headers['content-encoding'] = ContentEncoding
        if ContentLanguage:
            headers['content-language'] = ContentLanguage

        if ContentType:
            headers['content-type'] = ContentType
        elif self.recognize_content_type:
            headers['content-type'] = get_content_type(Key)

        if Expires:
            headers['expires'] = Expires.strftime(GMT_DATE_FORMAT)

        if SSECustomerAlgorithm:
            headers['x-tos-server-side-encryption-customer-algorithm'] = SSECustomerAlgorithm
        if SSECustomerKey:
            headers['x-tos-server-side-encryption-customer-key'] = SSECustomerKey
        if SSECustomerKeyMD5:
            headers['x-tos-server-side-encryption-customer-key-md5'] = SSECustomerKeyMD5

        resp = self._req(bucket=Bucket, key=Key, method='PUT', data=Body, headers=headers)
        logger.info(
            'put_object, bucket: {0}, key: {1}, req id: {2}, status code: {3}'.format(
                Bucket, Key, resp.request_id, resp.status))
        return PutObjectResult(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def get_object(self, Bucket: str, Key: str, IfMatch: str = None, IfModifiedSince: datetime = None,
                   IfNoneMatch: str = None, IfUnmodifiedSince: datetime = None, Range: str = None,
                   ResponseCacheControl: str = None, ResponseContentDisposition: str = None,
                   ResponseContentEncoding: str = None, ResponseContentLanguage: str = None,
                   ResponseContentType: str = None, ResponseExpires: datetime = None, VersionId: str = None,
                   SSECustomerAlgorithm: str = None, SSECustomerKey: str = None, SSECustomerKeyMD5: str = None):
        """
        ????????????
        :param Bucket: ??????
        :param Key: ?????????
        :param IfMatch: ????????????????????????????????????
        :param IfModifiedSince: datetime(2021, 1, 1)
        :param IfNoneMatch: ???????????????????????????????????????
        :param IfUnmodifiedSince: datetime(2021, 1, 1)
        :param Range: ????????????
        :param ResponseCacheControl: ???????????????Cache-Control
        :param ResponseContentDisposition: ???????????????Content-Disposition
        :param ResponseContentEncoding: ???????????????Content-Encoding
        :param ResponseContentLanguage: ???????????????Content-Language
        :param ResponseContentType: ???????????????Content-Type
        :param ResponseExpires: ???????????????Expires
        :param VersionId: ?????????
        :param SSECustomerAlgorithm: 'AES256'
        :param SSECustomerKey: ????????????
        :param SSECustomerKeyMD5: ??????md5???

        :return: RequestResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        headers = {}
        if IfMatch:
            headers['If-Match'] = IfMatch
        if IfModifiedSince:
            headers['If-Modified-Since'] = IfModifiedSince.strftime(GMT_DATE_FORMAT)
        if IfNoneMatch:
            headers['If-None-Match'] = IfNoneMatch
        if IfUnmodifiedSince:
            headers['If-Unmodified-Since'] = IfUnmodifiedSince.strftime(GMT_DATE_FORMAT)

        if Range:
            headers['Range'] = Range

        if SSECustomerAlgorithm:
            headers['x-tos-server-side-encryption-customer-algorithm'] = SSECustomerAlgorithm
        if SSECustomerKey:
            headers['x-tos-server-side-encryption-customer-key'] = SSECustomerKey
        if SSECustomerKeyMD5:
            headers['x-tos-server-side-encryption-customer-key-md5'] = SSECustomerKeyMD5

        params = {}
        if VersionId:
            params['versionId'] = VersionId
        if ResponseCacheControl:
            params['response-cache-control'] = ResponseCacheControl
        if ResponseContentDisposition:
            params['response-content-disposition'] = ResponseContentDisposition
        if ResponseContentEncoding:
            params['response-content-encoding'] = ResponseContentEncoding
        if ResponseContentLanguage:
            params['response-content-language'] = ResponseContentLanguage
        if ResponseContentType:
            params['response-content-type'] = ResponseContentType
        if ResponseExpires:
            params['response-expires'] = ResponseExpires.strftime(GMT_DATE_FORMAT)

        resp = self._req(bucket=Bucket, key=Key, method='GET', headers=headers, params=params)
        logger.info(
            'get_object, bucket: {0}, key: {1}, VersionId: {2}, req id: {3}, status code: {4}'.format(
                Bucket, Key, VersionId, resp.request_id, resp.status))
        return GetObjectResult(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def head_object(self, Bucket: str, Key: str, IfMatch: str = None, IfModifiedSince: datetime = None,
                    IfNoneMatch: str = None, IfUnmodifiedSince: datetime = None, Range: str = None,
                    VersionId: str = None, SSECustomerAlgorithm: str = None, SSECustomerKey: str = None,
                    SSECustomerKeyMD5: str = None):
        """
        ??????????????????
        :param Bucket: ??????
        :param Key: ?????????
        :param IfMatch: ????????????????????????????????????
        :param IfModifiedSince: datetime(2021, 1, 1)
        :param IfNoneMatch: ???????????????????????????????????????
        :param IfUnmodifiedSince: datetime(2021, 1, 1)
        :param Range: ????????????
        :param VersionId: ?????????
        :param SSECustomerAlgorithm: 'AES256'
        :param SSECustomerKey: ????????????
        :param SSECustomerKeyMD5: ??????md5???

        :return: HeadObjectResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        headers = {}
        if IfMatch:
            headers['If-Match'] = IfMatch
        if IfModifiedSince:
            headers['If-Modified-Since'] = IfModifiedSince.strftime(GMT_DATE_FORMAT)
        if IfNoneMatch:
            headers['If-None-Match'] = IfNoneMatch
        if IfUnmodifiedSince:
            headers['If-Unmodified-Since'] = IfUnmodifiedSince.strftime(GMT_DATE_FORMAT)
        if Range:
            headers['Range'] = Range
        if SSECustomerAlgorithm:
            headers['x-tos-server-side-encryption-customer-algorithm'] = SSECustomerAlgorithm
        if SSECustomerKey:
            headers['x-tos-server-side-encryption-customer-key'] = SSECustomerKey
        if SSECustomerKeyMD5:
            headers['x-tos-server-side-encryption-customer-key-md5'] = SSECustomerKeyMD5

        params = {}
        if VersionId:
            params['versionId'] = VersionId
        resp = self._req(bucket=Bucket, key=Key, method='HEAD', params=params, headers=headers)
        logger.info(
            'head_object, bucket: {0}, key: {1}, versionId: {2}, req id: {3}, status code: {4}'.format(
                Bucket, Key, VersionId, resp.request_id, resp.status))
        return HeadObjectResult(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def delete_object(self, Bucket: str, Key: str, VersionId: str = None):
        """
        ????????????
        :param Bucket: ??????
        :param Key: ?????????
        :param VersionId: ?????????

        :return: RequestResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        params = {}
        if VersionId:
            params = {'versionId': VersionId}
        resp = self._req(bucket=Bucket, key=Key, params=params, method='DELETE')
        logger.info(
            'delete_object, bucket: {0}, key: {1}, req id: {2}, status code: {3}'.format(
                Bucket, Key, resp.request_id, resp.status))
        return RequestResult(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def copy_object(self, Bucket: str, CopySource: Union[str, Dict], Key: str, ACL: str = None,
                    CacheControl: str = None,
                    ContentDisposition: str = None, ContentEncoding: str = None, ContentLanguage: str = None,
                    ContentType: str = None, CopySourceIfMatch: str = None, CopySourceIfModifiedSince: datetime = None,
                    CopySourceIfNoneMatch: str = None, CopySourceIfUnmodifiedSince: datetime = None,
                    Expires: datetime = None, GrantFullControl: str = None, GrantRead: str = None,
                    GrantReadACP: str = None, GrantWriteACP: str = None, Metadata: Dict = None,
                    MetadataDirective: str = None, SSECustomerAlgorithm: str = None, SSECustomerKey: str = None,
                    SSECustomerKeyMD5: str = None):
        """
        ????????????
        :param Bucket: ????????????
        :param CopySource:
        :param Key: ???????????????
        :param ACL: private'|'public-read'|'public-read-write'|'authenticated-read'|'bucket-owner-read'|
        'bucket-owner-full-control'
        :param CacheControl: ????????????
        :param ContentDisposition: ????????????
        :param ContentEncoding: ????????????
        :param ContentLanguage: ????????????
        :param ContentType: ????????????
        :param CopySourceIfMatch: ????????????????????????????????????
        :param CopySourceIfModifiedSince: datetime(2021, 1, 1)
        :param CopySourceIfNoneMatch: ???????????????????????????????????????
        :param CopySourceIfUnmodifiedSince: datetime(2021, 1, 1)
        :param Expires: datetime(2021, 1, 1)
        :param GrantFullControl:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantRead:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantReadACP:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantWriteACP: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param Metadata: ??????????????????
        :param MetadataDirective: 'COPY'|'REPLACE'
        :param SSECustomerAlgorithm: 'AES256'
        :param SSECustomerKey: ????????????
        :param SSECustomerKeyMD5: ??????md5???

        :return: CopyObjectResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        headers = {}

        if isinstance(CopySource, str):
            headers['x-tos-copy-source'] = CopySource
        elif isinstance(CopySource, dict):
            copy_source = CopySource['Bucket'] + '/' + CopySource['Key']
            if 'VersionId' in CopySource:
                copy_source = copy_source + '?versionId=' + CopySource['VersionId']
            headers['x-tos-copy-source'] = copy_source

        if MetadataDirective:
            headers['x-tos-metadata-directive'] = MetadataDirective

        if Metadata:
            for k in Metadata:
                headers['x-tos-meta-' + k] = Metadata[k]

        if CacheControl:
            headers['cache-control'] = CacheControl
        if ContentDisposition:
            headers['content-disposition'] = ContentDisposition
        if ContentEncoding:
            headers['content-encoding'] = ContentEncoding
        if ContentLanguage:
            headers['content-language'] = ContentLanguage
        if ContentType:
            headers['content-type'] = ContentType
        if Expires:
            headers['expires'] = Expires.strftime(GMT_DATE_FORMAT)

        if ACL:
            headers['x-tos-acl'] = ACL
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

        resp = self._req(bucket=Bucket, key=Key, method='PUT', headers=headers)
        logger.info(
            'copy_object, bucket: {0}, key: {1}, req id: {2}, status code: {3}'.format(Bucket, Key, resp.request_id,
                                                                                       resp.status))
        return convert_copy_object_result(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def append_object(self, Bucket: str, Key: str, Offset: str, ACL: str = None, Body: Union[bytes, IO] = None,
                      CacheControl: str = None, ContentDisposition: str = None, ContentEncoding: str = None,
                      ContentMD5: str = None, ContentLanguage: str = None, ContentType: str = None,
                      Expires: datetime = None,
                      GrantFullControl: str = None, GrantRead: str = None, GrantReadACP: str = None,
                      GrantWriteACP: str = None, Metadata: Dict = None, SSECustomerAlgorithm: str = None,
                      SSECustomerKey: str = None, SSECustomerKeyMD5: str = None):
        """
        ???????????????
        :param Bucket: ??????
        :param Key: ?????????
        :param ACL: 'private'|'public-read'|'public-read-write'|'authenticated-read'|'bucket-owner-read'|
        'bucket-owner-full-control'
        :param Body: ??????
        :param CacheControl: ????????????
        :param ContentDisposition: ????????????
        :param ContentEncoding: ????????????
        :param ContentLanguage: ????????????
        :param ContentType: ????????????
        :param Expires: datetime(2021, 1, 1)
        :param GrantFullControl:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantRead:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantReadACP:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantWriteACP: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param Metadata: ??????????????????
        :param SSECustomerAlgorithm: 'AES256'
        :param SSECustomerKey: ????????????
        :param SSECustomerKeyMD5: ??????md5???

        :return: AppanedObjectResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        params = {'append': ''}
        params['offset'] = Offset
        headers = {}
        if Metadata:
            for k in Metadata:
                headers['x-tos-meta-' + k] = Metadata[k]
        if ACL:
            headers['x-tos-acl'] = ACL

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
            headers['content-disposition'] = ContentDisposition
        if ContentEncoding:
            headers['content-encoding'] = ContentEncoding
        if ContentLanguage:
            headers['content-language'] = ContentLanguage

        if ContentType:
            headers['content-type'] = ContentType
        elif self.recognize_content_type:
            headers['content-type'] = get_content_type(Key)

        if Expires:
            headers['expires'] = Expires.strftime(GMT_DATE_FORMAT)

        if SSECustomerAlgorithm:
            headers['x-tos-server-side-encryption-customer-algorithm'] = SSECustomerAlgorithm
        if SSECustomerKey:
            headers['x-tos-server-side-encryption-customer-key'] = SSECustomerKey
        if SSECustomerKeyMD5:
            headers['x-tos-server-side-encryption-customer-key-md5'] = SSECustomerKeyMD5

        resp = self._req(bucket=Bucket, key=Key, method='POST', data=Body, headers=headers, params=params)
        logger.info(
            'append_object, bucket: {0}, key: {1}, req id: {2}, status code: {3}'.format(
                Bucket, Key, resp.request_id, resp.status))
        return AppendObjectResult(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def put_object_acl(self, Bucket: str, Key: str, ACL: str = None, AccessControlPolicy: Dict = None,
                       GrantFullControl: str = None, GrantRead: str = None, GrantReadACP: str = None,
                       GrantWrite: str = None, GrantWriteACP: str = None, VersionId: str = None):
        """
        ????????????acl
        :param Bucket: ??????
        :param Key: ?????????
        :param ACL: 'private'|'public-read'|'public-read-write'|'authenticated-read'|'bucket-owner-read'|
        'bucket-owner-full-control'
        :param AccessControlPolicy:
        {
            "Grants": [
                {
                    "Grantee": {
                        "ID": "string",
                        "Type": "CanonicalUser"|"Group",
                        "Canned": "AuthenticatedUsers"|"AllUsers"
                    },
                    "Permission": "FULL_CONTROL"|"WRITE"|"WRITE_ACP"|"READ"|"READ_ACP"
                },
            ],
            "Owner":{
                "ID":"xxx",
                "DisplayName":"xxx"
            }
        }
        :param GrantFullControl:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantRead:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantReadACP:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantWrite:  'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param GrantWriteACP: 'id="xxx",canned="AllUsers"|"AuthenticatedUsers"'
        :param VersionId: ?????????

        :return: RequestResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        params = {'acl': ''}
        if VersionId:
            params['versionId'] = VersionId

        headers = {}
        if ACL:
            headers['x-tos-acl'] = ACL

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

        data = None
        if AccessControlPolicy:
            data = json.dumps(AccessControlPolicy)

        resp = self._req(bucket=Bucket, key=Key, method='PUT', params=params, headers=headers, data=data)
        logger.info(
            'put_object_acl, bucket: {0}, key: {1}, versionId: {2}, req id: {3}, status code: {4}'.format(
                Bucket, Key, VersionId, resp.request_id, resp.status))
        return RequestResult(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def get_object_acl(self, Bucket: str, Key: str, VersionId: str = None):
        """
        ???????????????acl
        :param Bucket: ??????
        :param Key: ?????????
        :param VersionId: ?????????
        :return: GetObjectAclResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        params = {'acl': ''}
        if VersionId:
            params['versionId'] = VersionId
        resp = self._req(bucket=Bucket, key=Key, method='GET', params=params)
        logger.info(
            'get_object_acl, bucket: {0}, key: {1}, versionId: {2}, req id: {3}, status code: {4}'.format(
                Bucket, Key, VersionId, resp.request_id, resp.status))
        return convert_get_object_acl_result(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def set_object_metadata(self, Bucket: str, Key: str, ObjectMetadata: Dict = {}):
        """
        ?????????????????????
        :param Bucket: ??????
        :param Key: ?????????
        :param ObjectMetadata: ?????????????????????
        :return:
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        resp = self._req(bucket=Bucket, key=Key, method='Post', headers=ObjectMetadata, params={'metadata': ''})
        logger.info(
            'set_object_metadata, bucket: {0}, req id: {1}, status code: {2}'.format(Bucket, resp.request_id,
                                                                                     resp.status))
        return RequestResult(resp)

    @deprecated(version='2.1.0', reason="please use TosClientV2")
    def delete_objects(self, Bucket: str, Delete: Dict):
        """
        ??????????????????
        :param Bucket: ??????
        :param Delete: {
        'Objects': [
            {
                'Key': 'string',
                'VersionId': 'string'
            },
        ],
        'Quiet': True|False
        }

        :return: DeleteObjectsResult
        """
        warnings.warn("please use TosClientV2", DeprecationWarning)
        data = json.dumps(Delete)

        headers = {}
        headers['Content-MD5'] = to_str(base64.b64encode(hashlib.md5(to_bytes(data)).digest()))
        resp = self._req(bucket=Bucket, method='POST', data=data, headers=headers, params={'delete': ''})
        logger.info(
            'delete_objects, bucket: {0}, req id: {1}, status code: {2}'.format(Bucket, resp.request_id, resp.status))
        return convert_delete_objects_result(resp)

    def _format_endpoint(self, endpoint):
        if not endpoint.startswith('http://') and not endpoint.startswith('https://'):
            return 'https://' + endpoint
        else:
            return endpoint

    def _make_uri(self, bucket=None, key=None):
        if bucket and not key:
            return '/{0}'.format(bucket)
        if bucket and key:
            return '/{0}/{1}'.format(bucket, key)
        return '/'

    def _make_virtual_host_url(self, bucket=None, key=None):
        url = self.host
        if bucket and key:
            url = '{0}.{1}/{2}'.format(bucket, self.host, quote(key, '/~'))
        elif bucket and not key:
            url = '{0}.{1}'.format(bucket, self.host)

        return self._format_endpoint(self.scheme + url)

    def _make_virtual_host_uri(self, key=None):
        if key:
            return '/{0}'.format(key)
        return '/'

    def _get_host(self, endpoint):
        if endpoint.startswith('http://'):
            return endpoint[7:]
        if endpoint.startswith('https://'):
            return endpoint[8:]
        return endpoint

    def _get_scheme(self, endpoint):
        if endpoint.startswith('http://'):
            return 'http://'
        if endpoint.startswith('https://'):
            return 'https://'
        return 'http://'

    def _get_virtual_host(self, bucket, endpoint):
        if bucket:
            return bucket + '.' + self._get_host(endpoint)
        else:
            return self._get_host(endpoint)

    def _cal_content_sha256(self, data):
        if data and hasattr(data, 'seek'):
            position = data.tell()
            read_chunksize = functools.partial(data.read,
                                               PAYLOAD_BUFFER)
            checksum = sha256()
            for chunk in iter(read_chunksize, b''):
                checksum.update(chunk)
            hex_checksum = checksum.hexdigest()
            data.seek(position)
            return hex_checksum
        elif data:
            return sha256(data).hexdigest()
        else:
            return EMPTY_SHA256_HASH

    def _req(self, bucket=None, key=None, method=None, data=None, headers=None, params=None):
        key = to_str(key)
        data = to_bytes(data)

        headers = CaseInsensitiveDict(headers)

        if headers.get('x-tos-content-sha256') is None:
            headers['x-tos-content-sha256'] = self._cal_content_sha256(data)

        req = Request(method, self._make_virtual_host_url(bucket, key),
                      self._make_virtual_host_uri(key),
                      self._get_virtual_host(bucket, self.endpoint),
                      data=data,
                      params=params,
                      headers=headers)
        self.auth._sign_request(req)

        if 'User-Agent' not in req.headers:
            req.headers['User-Agent'] = USER_AGENT
        res = self.session.request(method,
                                   req.url,
                                   data=req.data,
                                   headers=req.headers,
                                   params=req.params,
                                   stream=True,
                                   timeout=self.timeout)

        rsp = Response(res)
        if rsp.status >= 300:
            e = exceptions.make_exception(rsp)
            logger.info('Exception: %s' % e)
            raise e

        content_length = get_value(rsp.headers, 'content-length', int)
        if content_length is not None and content_length == 0:
            rsp.read()

        return rsp
