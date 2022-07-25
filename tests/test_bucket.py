# -*- coding: utf-8 -*-

import json
import unittest
from unittest import mock

from tests.common import MockResponse, TosTestCase


class TestBucket(TosTestCase):
    @mock.patch('requests.Session.request')
    def test_create_bucket(self, mock_request):
        mock_request.return_value = MockResponse(headers={'Location': self.location})

        res = self.client.create_bucket(self.bucket_name)
        self.assertEqual(res.location, self.location)

    @mock.patch('requests.Session.request')
    def test_head_bucket(self, mock_request):
        mock_request.return_value = MockResponse(headers={'x-tos-bucket-region': self.region})

        res = self.client.head_bucket(self.bucket_name)
        self.assertEqual(res.region, self.region)

    @mock.patch('requests.Session.request')
    def test_list_buckets(self, mock_request):
        mock_data = {
            'Owner': {
                'ID': 'id-test',
                'Name': 'name-test'
            },
            'Buckets': [
                {
                    'Name': 'bkt1',
                    'Location': self.location,
                    'CreationDate': self.date,
                    'ExtranetEndpoint': 'tos-ext.volces.com',
                    'IntranetEndpoint': 'tos-int.volces.com'
                },
                {
                    'Name': 'bkt2',
                    'Location': self.location,
                    'CreationDate': self.date,
                    'ExtranetEndpoint': 'tos-ext.volces.com',
                    'IntranetEndpoint': 'tos-int.volces.com'
                }
            ]
        }
        mock_request.return_value = MockResponse(body=json.dumps(mock_data))

        res = self.client.list_buckets()
        self.assertEqual(res.owner.id, 'id-test')
        self.assertEqual(res.owner.name, 'name-test')
        self.assertEqual(len(res.bucket_list), 2)
        self.assertEqual(res.bucket_list[0].name, 'bkt1')
        self.assertEqual(res.bucket_list[0].location, self.location)
        self.assertEqual(res.bucket_list[0].creation_date, self.date)
        self.assertEqual(res.bucket_list[0].extranet_endpoint, 'tos-ext.volces.com')
        self.assertEqual(res.bucket_list[0].intranet_endpoint, 'tos-int.volces.com')

        self.assertEqual(res.bucket_list[1].name, 'bkt2')
        self.assertEqual(res.bucket_list[1].location, self.location)
        self.assertEqual(res.bucket_list[1].creation_date, self.date)
        self.assertEqual(res.bucket_list[1].extranet_endpoint, 'tos-ext.volces.com')
        self.assertEqual(res.bucket_list[1].intranet_endpoint, 'tos-int.volces.com')

        mock_data = {
            'Owner': {
                'ID': 'id-test',
                'Name': 'name-test'
            }
        }
        mock_request.return_value = MockResponse(body=json.dumps(mock_data))
        res = self.client.list_buckets()
        self.assertEqual(res.owner.id, 'id-test')
        self.assertEqual(res.owner.name, 'name-test')
        self.assertEqual(len(res.bucket_list), 0)

    @mock.patch('requests.Session.request')
    def test_delete_bucket(self, mock_request):
        mock_request.return_value = MockResponse(status_code=204)

        res = self.client.delete_bucket(Bucket=self.bucket_name)
        self.assertEqual(res.status, 204)


if __name__ == '__main__':
    unittest.main()
