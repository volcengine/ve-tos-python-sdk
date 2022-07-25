# -*- coding: utf-8 -*-

import datetime
import json
import unittest
from unittest import mock

import pytz

from tests.common import MockResponse, TosTestCase


class TestMultipart(TosTestCase):
    @mock.patch('requests.Session.request')
    def test_create_multipart_upload(self, mock_request):
        mock_data = {
            'UploadId': 'uploadId',
            'Bucket': self.bucket_name,
            'Key': self.key_name,
        }
        mock_request.return_value = MockResponse(body=json.dumps(mock_data))

        res = self.client.create_multipart_upload(Bucket=self.bucket_name, Key=self.key_name)
        self.assertEqual(res.upload_id, 'uploadId')
        self.assertEqual(res.bucket, self.bucket_name)
        self.assertEqual(res.key, self.key_name)

    @mock.patch('requests.Session.request')
    def test_upload_part(self, mock_request):
        mock_request.return_value = MockResponse(headers={
            'ETag': '"etag"',
            'x-tos-server-side-encryption-customer-algorithm': 'AES256',
            'x-tos-server-side-encryption-customer-key': 'key',
            'x-tos-server-side-encryption-customer-key-md5': 'md5',
        })

        res = self.client.upload_part(Bucket=self.bucket_name, Key=self.key_name, PartNumber=1, UploadId='uploadId',
                                      Body=b'data')
        self.assertEqual(res.etag, 'etag')
        self.assertEqual(res.sse_customer_algorithm, 'AES256')
        self.assertEqual(res.sse_customer_key, 'key')
        self.assertEqual(res.sse_customer_key_md5, 'md5')

    @mock.patch('requests.Session.request')
    def test_upload_part_copy(self, mock_request):
        mock_data = {
            'ETag': '\"etag\"',
            'LastModified': '2021-01-01T00:00:00.000Z',
        }
        mock_request.return_value = MockResponse(body=json.dumps(mock_data))

        copy_source = {
            'Bucket': 'src-bucket',
            'Key': 'src-key',
            'VersionId': 'version-id'
        }
        res = self.client.upload_part_copy(Bucket=self.bucket_name, CopySource=copy_source, Key=self.key_name,
                                           PartNumber=1,
                                           UploadId='uploadId')
        self.assertEqual(res.etag, 'etag')
        self.assertEqual(res.last_modified, datetime.datetime(2021, 1, 1, tzinfo=pytz.utc))

    @mock.patch('requests.Session.request')
    def test_complete_multipart_upload(self, mock_request):
        mock_data = {
            'Location': self.location,
            'Bucket': self.bucket_name,
            'Key': self.key_name,
            'ETag': '"etag"'
        }
        mock_request.return_value = MockResponse(body=json.dumps(mock_data))

        upload = {
            'Parts': [
                {
                    'ETag': 'etag-1',
                    'PartNumber': 1
                },
                {
                    'ETag': 'etag-2',
                    'PartNumber': 2
                },
            ]
        }
        res = self.client.complete_multipart_upload(Bucket=self.bucket_name, Key=self.key_name, UploadId='upload-id',
                                                    MultipartUpload=upload)
        self.assertEqual(res.location, self.location)
        self.assertEqual(res.bucket, self.bucket_name)
        self.assertEqual(res.key, self.key_name)
        self.assertEqual(res.etag, 'etag')

    @mock.patch('requests.Session.request')
    def test_list_multipart_uploads(self, mock_request):
        upload_id = 'upload-id'
        delimiter = '/'
        encoding_type = 'url'
        key_marker = 'key-marker'
        next_key_marker = 'next-key-marker'
        max_uploads = 10
        prefix = 'abc'
        upload_id_marker = 'upload-marker'
        next_upload_id_marker = 'next-upload-marker'
        storage_class = 'STANDARD'
        mock_data = {
            'Bucket': self.bucket_name,
            'UploadIdMarker': upload_id_marker,
            'NextKeyMarker': next_key_marker,
            'NextUploadIdMarker': next_upload_id_marker,
            'Delimiter': delimiter,
            'Prefix': prefix,
            'MaxUploads': max_uploads,
            'IsTruncated': True,
            'CommonPrefixes': [{
                'Prefix': prefix
            }],
            'Uploads': [{
                'Key': self.key_name,
                'UploadId': upload_id,
                'StorageClass': storage_class,
                'Initiated': '2021-01-01T00:00:00.000Z',
                'Owner': {
                    'ID': 'id',
                    'DisplayName': 'name'
                },

            }]
        }
        mock_request.return_value = MockResponse(body=json.dumps(mock_data))

        res = self.client.list_multipart_uploads(Bucket=self.bucket_name, Delimiter=delimiter,
                                                 EncodingType=encoding_type, KeyMarker=key_marker,
                                                 MaxUploads=max_uploads, Prefix=prefix, UploadIdMarker=upload_id_marker)
        self.assertEqual(res.bucket, self.bucket_name)
        self.assertEqual(res.upload_id_marker, upload_id_marker)
        self.assertEqual(res.next_key_marker, next_key_marker)
        self.assertEqual(res.next_upload_id_marker, next_upload_id_marker)
        self.assertEqual(res.delimiter, delimiter)
        self.assertEqual(res.prefix, prefix)
        self.assertEqual(res.max_uploads, max_uploads)
        self.assertEqual(res.is_truncated, True)

        self.assertEqual(len(res.upload_list), 1)
        self.assertEqual(res.upload_list[0].key, self.key_name)
        self.assertEqual(res.upload_list[0].initiated, datetime.datetime(2021, 1, 1, tzinfo=pytz.utc))
        self.assertEqual(res.upload_list[0].storage_class, storage_class)
        self.assertEqual(res.upload_list[0].upload_id, upload_id)
        self.assertEqual(res.upload_list[0].owner.id, 'id')
        self.assertEqual(res.upload_list[0].owner.name, 'name')

        self.assertEqual(len(res.common_prefix_list), 1)
        self.assertEqual(res.common_prefix_list[0].prefix, prefix)

    @mock.patch('requests.Session.request')
    def test_list_parts(self, mock_request):
        upload_id = 'upload-id'
        max_parts = 10
        part_number_marker = 11
        next_part_number_marker = 21
        storage_class = 'STANDARD'
        mock_data = {
            'Bucket': self.bucket_name,
            'Key': self.key_name,
            'UploadId': upload_id,
            'PartNumberMarker': part_number_marker,
            'NextPartNumberMarker': next_part_number_marker,
            'MaxParts': max_parts,
            'StorageClass': storage_class,
            'IsTruncated': True,
            'Owner': {
                'ID': 'id',
                'DisplayName': 'name'
            },
            'Parts': [
                {
                    'PartNumber': 11,
                    'LastModified': '2021-01-01T00:00:00.000Z',
                    'ETag': '"etag-1"',
                    'Size': 100
                }
            ]
        }
        mock_request.return_value = MockResponse(body=json.dumps(mock_data))

        res = self.client.list_parts(Bucket=self.bucket_name, Key=self.key_name, UploadId=upload_id, MaxParts=max_parts,
                                     PartNumberMarker=part_number_marker)
        self.assertEqual(res.bucket, self.bucket_name)
        self.assertEqual(res.key, self.key_name)
        self.assertEqual(res.upload_id, upload_id)
        self.assertEqual(res.part_number_marker, part_number_marker)
        self.assertEqual(res.next_part_number_marker, next_part_number_marker)
        self.assertEqual(res.max_parts, max_parts)
        self.assertEqual(res.storage_class, storage_class)
        self.assertEqual(res.is_truncated, True)

        self.assertEqual(res.owner.id, 'id')
        self.assertEqual(res.owner.name, 'name')

        self.assertEqual(len(res.part_list), 1)
        self.assertEqual(res.part_list[0].part_number, 11)
        self.assertEqual(res.part_list[0].last_modified, datetime.datetime(2021, 1, 1, tzinfo=pytz.utc))
        self.assertEqual(res.part_list[0].etag, 'etag-1')
        self.assertEqual(res.part_list[0].size, 100)

    @mock.patch('requests.Session.request')
    def test_abort_multipart_upload(self, mock_request):
        mock_request.return_value = MockResponse(status_code=204)

        res = self.client.abort_multipart_upload(Bucket=self.bucket_name, Key=self.key_name, UploadId='upload-id')
        self.assertEqual(res.status, 204)


if __name__ == '__main__':
    unittest.main()
