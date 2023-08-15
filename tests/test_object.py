# -*- coding: utf-8 -*-

import datetime
import json
import unittest
from unittest import mock

import pytz
from tos.exceptions import TosError

from tests.common import MockResponse, TosTestCase


class TestObject(TosTestCase):
    @mock.patch('requests.Session.request')
    def test_put_object(self, mock_request):
        mock_request.return_value = MockResponse(headers={
            'ETag': '"etag"',
            'x-tos-server-side-encryption-customer-algorithm': 'AES256',
            'x-tos-server-side-encryption-customer-key': 'key',
            'x-tos-server-side-encryption-customer-key-md5': 'eb5875f724a1a982'
        })

        res = self.client.put_object(Bucket=self.bucket_name, Key=self.key_name, Body=b'aaa.txt')
        self.assertEqual(res.etag, 'etag')
        self.assertEqual(res.sse_customer_algorithm, 'AES256')
        self.assertEqual(res.sse_customer_key, 'key')
        self.assertEqual(res.sse_customer_key_md5, 'eb5875f724a1a982')

    @mock.patch('requests.Session.request')
    def test_get_object(self, mock_request):
        mock_request.return_value = MockResponse(headers={'content-range': 'bytes=0-100'})

        res = self.client.get_object(Bucket=self.bucket_name, Key=self.key_name)
        self.assertEqual(res.status, 200)
        self.assertEqual(res.content_range, 'bytes=0-100')

    @mock.patch('requests.Session.request')
    def test_get_object_not_found(self, mock_request):
        mock_request.return_value = MockResponse(status_code=404)

        try:
            self.client.get_object(Bucket=self.bucket_name, Key=self.key_name)
            self.assertTrue(False)
        except TosError as e:
            self.assertEqual(e.status, 404)

    @mock.patch('requests.Session.request')
    def test_head_object(self, mock_request):
        mock_request.return_value = MockResponse(headers={
            'ETag': '"etag"',
            'content-type': 'text/html',
            'content-length': '100',
            'x-tos-server-side-encryption-customer-algorithm': 'AES256',
            'x-tos-server-side-encryption-customer-key': 'key',
            'x-tos-server-side-encryption-customer-key-md5': 'eb5875f724a1a982',
            'x-tos-meta-key': 'self-value',
            'last-modified': 'Fri, 01 Jan 2021 00:00:00 GMT',
            'expires': 'Fri, 01 Jan 2021 00:00:00 GMT'
        })

        res = self.client.head_object(Bucket=self.bucket_name, Key=self.key_name)
        self.assertEqual(res.content_type, 'text/html')
        self.assertEqual(res.content_length, 100)
        self.assertEqual(res.etag, 'etag')
        self.assertEqual(res.sse_customer_algorithm, 'AES256')
        self.assertEqual(res.sse_customer_key, 'key')
        self.assertEqual(res.sse_customer_key_md5, 'eb5875f724a1a982')

        self.assertEqual(res.metadata['key'], 'self-value')
        self.assertEqual(res.last_modified, datetime.datetime(2021, 1, 1, tzinfo=pytz.utc))
        self.assertEqual(res.expires, datetime.datetime(2021, 1, 1, tzinfo=pytz.utc))

    @mock.patch('requests.Session.request')
    def test_delete_object(self, mock_request):
        mock_request.return_value = MockResponse(status_code=204)

        res = self.client.delete_object(Bucket=self.bucket_name, Key=self.key_name, VersionId='df78ca5')
        self.assertEqual(res.status, 204)

    @mock.patch('requests.Session.request')
    def test_copy_object(self, mock_request):
        body = {
            'ETag': '"etag"',
            'LastModified': '2021-01-01T00:00:00.000Z',
        }
        mock_request.return_value = MockResponse(body=json.dumps(body))

        copySource = {
            'Bucket': 'src-bkt',
            'Key': 'src-key',
            'VersionId': 'src_id'
        }
        res = self.client.copy_object(Bucket=self.bucket_name, CopySource=copySource, Key=self.key_name)
        self.assertEqual(res.etag, 'etag')
        self.assertEqual(res.last_modified, datetime.datetime(2021, 1, 1, tzinfo=pytz.utc))

    @mock.patch('requests.Session.request')
    def test_append_object(self, mock_request):
        mock_request.return_value = MockResponse(headers={
            'ETag': '"etag"',
            'x-tos-server-side-encryption-customer-algorithm': 'AES256',
            'x-tos-server-side-encryption-customer-key': 'key',
            'x-tos-server-side-encryption-customer-key-md5': 'eb5875f724a1a982'
        })

        res = self.client.append_object(Bucket=self.bucket_name, Key=self.key_name, Offset=100, Body=b'aaa')
        self.assertEqual(res.etag, 'etag')
        self.assertEqual(res.sse_customer_algorithm, 'AES256')
        self.assertEqual(res.sse_customer_key, 'key')
        self.assertEqual(res.sse_customer_key_md5, 'eb5875f724a1a982')

    @mock.patch('requests.Session.request')
    def test_put_object_acl(self, mock_request):
        mock_request.return_value = MockResponse()

        res = self.client.put_object_acl(self.bucket_name, self.key_name, ACL='public-read', VersionId='df78ca5')
        self.assertEqual(res.status, 200)

    @mock.patch('requests.Session.request')
    def test_get_object_acl(self, mock_request):
        acl = {
            'Grants': [
                {
                    'Grantee': {
                        'ID': 'acl id',
                        'DisplayName': 'acl name',
                        'Type': 'Group',
                        'Canned': 'AllUsers'
                    },
                    'Permission': 'FULL_CONTROL'
                },
            ],
            'Owner': {
                'ID': 'id',
                'DisplayName': 'name'
            }
        }
        mock_request.return_value = MockResponse(body=json.dumps(acl))

        res = self.client.get_object_acl(self.bucket_name, self.key_name, VersionId='df78ca5')
        self.assertEqual(res.owner.id, 'id')
        self.assertEqual(res.owner.name, 'name')
        self.assertEqual(len(res.grant_list), 1)
        self.assertEqual(res.grant_list[0].permission, 'FULL_CONTROL')
        self.assertEqual(res.grant_list[0].grantee.id, 'acl id')
        self.assertEqual(res.grant_list[0].grantee.display_name, 'acl name')
        self.assertEqual(res.grant_list[0].grantee.type, 'Group')
        self.assertEqual(res.grant_list[0].grantee.canned, 'AllUsers')

    @mock.patch('requests.Session.request')
    def test_delete_objects(self, mock_request):
        mock_data = {
            'Deleted': [{
                'Key': 'key1',
                'VersionId': 'versionId1',
            }],
            'Error': [{
                'Code': 'NoSuchKey',
                'Message': 'No such key',
                'Key': 'key2',
                'VersionId': 'versionId2'
            }]
        }
        mock_request.return_value = MockResponse(body=json.dumps(mock_data))

        delete = {
            'Objects': [
                {
                    'Key': 'key1',
                    'VersionId': 'versionId1'
                },
                {
                    'Key': 'key2',
                    'VersionId': 'versionId2'
                }
            ],
            'Quiet': False
        }
        res = self.client.delete_objects(Bucket=self.bucket_name, Delete=delete)
        self.assertEqual(len(res.deleted_list), 1)
        self.assertEqual(res.deleted_list[0].key, 'key1')
        self.assertEqual(res.deleted_list[0].version_id, 'versionId1')
        self.assertEqual(len(res.error_list), 1)
        self.assertEqual(res.error_list[0].code, 'NoSuchKey')
        self.assertEqual(res.error_list[0].message, 'No such key')
        self.assertEqual(res.error_list[0].key, 'key2')
        self.assertEqual(res.error_list[0].version_id, 'versionId2')


if __name__ == '__main__':
    unittest.main()
