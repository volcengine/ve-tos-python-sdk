# -*- coding: utf-8 -*-

import datetime
import json
import unittest
from unittest import mock

import pytz

from tests.common import MockResponse, TosTestCase


class TestListObjects(TosTestCase):
    @mock.patch('requests.Session.request')
    def test_list_objects(self, mock_request):
        prefix = 'abc'
        marker = 'abcde'
        next_marker = 'abcdef'
        maxkeys = 10
        delimiter = '/'
        encoding_type = 'url'
        mock_data = {
            'Name': self.bucket_name,
            'Prefix': prefix,
            'Marker': marker,
            'MaxKeys': maxkeys,
            'NextMarker': next_marker,
            'Delimiter': delimiter,
            'EncodingType': encoding_type,
            'IsTruncated': True,
            'CommonPrefixes': [
                {
                    'Prefix': prefix
                }
            ],
            'Contents': [
                {
                    'Key': 'key1',
                    'LastModified': '2021-01-01T00:00:00.000Z',
                    'ETag': '\"etag\"',
                    'Size': 100,
                    'StorageClass': 'STANDARD',
                    'Owner': {
                        'ID': 'id',
                        'DisplayName': 'name'
                    }
                }
            ]
        }
        mock_request.return_value = MockResponse(body=json.dumps(mock_data))

        res = self.client.list_objects(Bucket=self.bucket_name, Delimiter=delimiter, MaxKeys=maxkeys, Prefix=prefix,
                                       Marker=marker, EncodingType=encoding_type)
        self.assertEqual(res.name, self.bucket_name)
        self.assertEqual(res.prefix, prefix)
        self.assertEqual(res.marker, marker)
        self.assertEqual(res.max_keys, maxkeys)
        self.assertEqual(res.next_marker, next_marker)
        self.assertEqual(res.delimiter, delimiter)
        self.assertEqual(res.encoding_type, encoding_type)
        self.assertEqual(res.is_truncated, True)

        self.assertEqual(len(res.common_prefix_list), 1)
        self.assertEqual(res.common_prefix_list[0].prefix, prefix)

        self.assertEqual(len(res.object_list), 1)
        self.assertEqual(res.object_list[0].key, 'key1')
        self.assertEqual(res.object_list[0].last_modified, datetime.datetime(2021, 1, 1, tzinfo=pytz.utc))
        self.assertEqual(res.object_list[0].etag, 'etag')
        self.assertEqual(res.object_list[0].size, 100)
        self.assertEqual(res.object_list[0].storage_class, 'STANDARD')
        self.assertEqual(res.object_list[0].owner.id, 'id')
        self.assertEqual(res.object_list[0].owner.name, 'name')

    @mock.patch('requests.Session.request')
    def test_list_object_versions(self, mock_request):
        prefix = 'abc'
        key_marker = 'abcde'
        next_key_marker = 'abcdef'
        maxkeys = 10
        delimiter = '/'
        encoding_type = 'url'
        version_id_marker = 'version_marker'
        next_version_id_marker = 'next_version_marker'
        mock_data = {
            'Name': self.bucket_name,
            'Prefix': prefix,
            'KeyMarker': key_marker,
            'MaxKeys': maxkeys,
            'NextKeyMarker': next_key_marker,
            'VersionIdMarker': version_id_marker,
            'NextVersionIdMarker': next_version_id_marker,
            'Delimiter': delimiter,
            'EncodingType': encoding_type,
            'IsTruncated': True,
            'CommonPrefixes': [
                {
                    'Prefix': prefix
                }
            ],
            'Versions': [
                {
                    'Key': 'key1',
                    'LastModified': '2021-01-01T00:00:00.000Z',
                    'ETag': '\"etag\"',
                    'Size': 100,
                    'StorageClass': 'STANDARD',
                    'VersionId': 'version_id',
                    'Owner': {
                        'ID': 'id',
                        'DisplayName': 'name'
                    }
                }
            ]
        }
        mock_request.return_value = MockResponse(body=json.dumps(mock_data))

        res = self.client.list_object_versions(Bucket=self.bucket_name, Delimiter=delimiter, MaxKeys=maxkeys,
                                               Prefix=prefix,
                                               KeyMarker=key_marker, EncodingType=encoding_type,
                                               VersionIdMarker=version_id_marker)
        self.assertEqual(res.name, self.bucket_name)
        self.assertEqual(res.prefix, prefix)
        self.assertEqual(res.key_marker, key_marker)
        self.assertEqual(res.max_keys, maxkeys)
        self.assertEqual(res.next_key_marker, next_key_marker)
        self.assertEqual(res.delimiter, delimiter)
        self.assertEqual(res.encoding_type, encoding_type)
        self.assertEqual(res.is_truncated, True)
        self.assertEqual(res.version_id_marker, version_id_marker)
        self.assertEqual(res.next_version_id_marker, next_version_id_marker)

        self.assertEqual(len(res.common_prefix_list), 1)
        self.assertEqual(res.common_prefix_list[0].prefix, prefix)

        self.assertEqual(len(res.version_list), 1)
        self.assertEqual(res.version_list[0].key, 'key1')
        self.assertEqual(res.version_list[0].last_modified, datetime.datetime(2021, 1, 1, tzinfo=pytz.utc))
        self.assertEqual(res.version_list[0].etag, 'etag')
        self.assertEqual(res.version_list[0].size, 100)
        self.assertEqual(res.version_list[0].storage_class, 'STANDARD')
        self.assertEqual(res.version_list[0].version_id, 'version_id')
        self.assertEqual(res.version_list[0].owner.id, 'id')
        self.assertEqual(res.version_list[0].owner.name, 'name')


if __name__ == '__main__':
    unittest.main()
