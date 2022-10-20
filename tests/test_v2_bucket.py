# -*- coding: utf-8 -*-
import datetime
import json
import os
import random
import re
import string
import time as tim
import unittest

import tos
from tos import TosClientV2, set_logger
from tos.enum import ACLType, StorageClassType, RedirectType, StatusType
from tos.exceptions import TosClientError, TosServerError
from tos.models2 import CORSRule, Rule, Condition, Redirect, PublicSource, SourceEndpoint, MirrorHeader, \
    BucketLifeCycleRule, BucketLifeCycleExpiration, BucketLifeCycleNoCurrentVersionExpiration, \
    Tag, BucketLifeCycleTransition, \
    BucketLifeCycleNonCurrentVersionTransition

from tests.common import TosTestBase, random_string, random_bytes


class TestBucket(TosTestBase):
    def test_bucket(self):
        bucket_name = self.bucket_name + "basic"
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket_name)
        self.retry_assert(lambda: self.bucket_name + "basic" in (b.name for b in self.client.list_buckets().buckets))

        head_out = self.client.head_bucket(bucket=bucket_name)
        self.assertIsNotNone(head_out.region)
        self.assertEqual(head_out.storage_class, StorageClassType.Storage_Class_Standard)
        key = 'a.txt'
        self.client.put_object(bucket_name, key=key, content="contenet")

        with self.assertRaises(TosServerError):
            self.client.delete_bucket(bucket_name)

    def test_bucket_with_storage_class(self):
        bucket_name = self.bucket_name + "storage-class"
        self.client.create_bucket(bucket_name, storage_class=StorageClassType.Storage_Class_Ia)
        self.retry_assert(lambda: bucket_name in (b.name for b in self.client.list_buckets().buckets))

        key = 'a.txt'
        self.client.put_object(bucket_name, key=key, content="content")
        head_bucket_out = self.client.head_bucket(bucket_name)
        self.assertEqual(head_bucket_out.storage_class, StorageClassType.Storage_Class_Ia)
        self.assertIsNotNone(head_bucket_out.region)

        with self.assertRaises(TosServerError):
            self.client.delete_bucket(bucket_name)

        list_objects_out = self.client.list_objects(bucket_name)
        self.assertEqual(1, len(list_objects_out.contents))

        self.assertEqual(list_objects_out.contents[0].storage_class.value, StorageClassType.Storage_Class_Ia.value)

        with self.assertRaises(TosServerError):
            self.client.delete_bucket(bucket_name)

        self.client.delete_object(bucket_name, key)
        self.client.delete_bucket(bucket_name)

        with self.assertRaises(TosServerError):
            self.client.head_bucket(bucket_name + "test")

    def test_create_bucket_with_illegal_name(self):
        # 测试桶名在3-63个字符内
        with self.assertRaises(TosClientError):
            name = ""
            for i in range(64):
                name = name + '1'
            self.client.create_bucket(name)
        with self.assertRaises(TosClientError):
            self.client.create_bucket("12")

        with self.assertRaises(TosClientError):
            self.client.create_bucket("12A3")
        with self.assertRaises(TosClientError):
            self.client.create_bucket("12_3")

        with self.assertRaises(TosClientError):
            self.client.create_bucket("_123")

        with self.assertRaises(TosClientError):
            self.client.create_bucket("123_")

    def test_list_bucket(self):
        bucket_name = self.bucket_name + "listbucket"
        self.bucket_delete.append(bucket_name)

        self.client.create_bucket(bucket=bucket_name)
        list_out = self.client.list_buckets()
        self.assertTrue(len(list_out.buckets) > 1)
        self.assertTrue(bucket_name in (b.name for b in self.client.list_buckets().buckets))
        self.assertIsNotNone(list_out.owner)

    def test_bucket_info(self):
        bucket_name = self.bucket_name + "-info"
        self.bucket_delete.append(bucket_name)
        with self.assertRaises(TosServerError):
            self.client.head_bucket(bucket_name)

        out = self.client.create_bucket(bucket_name, storage_class=StorageClassType.Storage_Class_Ia)
        self.retry_assert(lambda: bucket_name in (b.name for b in self.client.list_buckets().buckets))

        list_bucket_out = self.client.list_buckets()
        self.assertTrue(len(list_bucket_out.buckets) >= 1)
        self.assertTrue(len(list_bucket_out.owner.id) > 0)
        self.assertTrue(len(list_bucket_out.id2) > 0)
        self.assertTrue(len(list_bucket_out.request_id) > 0)
        self.assertTrue(list_bucket_out.status_code == 200)

        bucket = list_bucket_out.buckets[0]
        self.assertTrue(len(bucket.name) > 0)
        self.assertTrue(len(bucket.location) > 0)
        self.assertTrue(len(bucket.creation_date) > 0)
        self.assertTrue(len(bucket.extranet_endpoint) > 0)
        self.assertTrue(len(bucket.intranet_endpoint) > 0)
        owner = list_bucket_out.owner
        self.assertTrue(len(owner.id) > 0)

    def test_bucket_with_acl(self):
        bucket_name = self.bucket_name + "-acl"
        self.bucket_delete.append(bucket_name)
        for acl in ACLType:
            if acl is not ACLType.ACL_Bucket_Owner_Entrusted:
                self.client.create_bucket(bucket_name + acl.value, acl=acl)
                self.client.delete_bucket(bucket_name + acl.value)

    def test_bucket_cors(self):
        bucket_name = self.bucket_name + 'cors'
        self.client.create_bucket(bucket_name)
        cors_rules = []
        for i in range(0, 2):
            cors_rules.append(CORSRule(
                allowed_origins=["example*.com" + str(i)],
                allowed_methods=['PUT'],
                allowed_headers=['*'],
                expose_headers=['x-tos-test'],
                max_age_seconds=100
            ))
        out = self.client.put_bucket_cors(bucket=bucket_name, cors_rule=cors_rules)
        self.assertIsNotNone(out.id2)
        self.assertIsNotNone(out.request_id)
        out_get = self.client.get_bucket_cors(bucket=bucket_name)
        self.assertTrue(len(out_get.cors_rules), 2)
        self.client.delete_bucket_cors(bucket=bucket_name)
        with self.assertRaises(TosServerError):
            self.client.get_bucket_cors(bucket=bucket_name)

        self.client.delete_bucket(bucket=bucket_name)

    def test_put_bucket_storage_class(self):
        bucket_name = self.bucket_name + 'storage-class'
        self.client.create_bucket(bucket_name)
        self.client.put_bucket_storage_class(bucket=bucket_name, storage_class=StorageClassType.Storage_Class_Ia)
        out = self.client.head_bucket(bucket=bucket_name)
        self.assertEqual(out.storage_class, StorageClassType.Storage_Class_Ia)
        self.client.delete_bucket(bucket=bucket_name)

    def test_get_location(self):
        bucket_name = self.bucket_name + 'location'
        self.client.create_bucket(bucket=bucket_name)
        out = self.client.get_bucket_location(bucket=bucket_name)
        self.assertIsNotNone(out.region)
        self.assertIsNotNone(out.extranet_endpoint)
        self.assertIsNotNone(out.intranet_endpoint)
        self.client.delete_bucket(bucket=bucket_name)

    def test_bucket_mirror(self):
        bucket_name = self.bucket_name + 'mirror'
        self.client.create_bucket(bucket=bucket_name)
        rules = []
        rules.append(Rule(
            id='1',
            condition=Condition(http_code=404, object_key_prefix="prefix"),
            redirect=Redirect(
                redirect_type=RedirectType.Mirror,
                fetch_source_on_redirect=True,
                public_source=PublicSource(SourceEndpoint(primary=['http://tosv.byted.org/obj/tostest/'])),
                pass_query=True,
                follow_redirect=True,
                mirror_header=MirrorHeader(pass_all=True, pass_headers=['aaa', 'bbb'], remove=['xxx', 'xxx'])
            )
        ))
        put_out = self.client.put_bucket_mirror_back(bucket=bucket_name, rules=rules)
        get_out = self.client.get_bucket_mirror_back(bucket=bucket_name)
        self.assertTrue(len(get_out.rules) == 1)
        delete_out = self.client.delete_bucket_mirror_back(bucket=bucket_name)
        self.client.delete_bucket(bucket=bucket_name)

    def test_bucket_policy(self):
        bucket_name = self.bucket_name + 'policy'
        policy = {
            "Statement": [
                {
                    "Sid": "internal public",
                    "Effect": "Allow",
                    "Action": ["*"],
                    "Principal": "*",
                    "Resource": [
                        "trn:tos:::{}/*".format(bucket_name),
                        "trn:tos:::{}".format(bucket_name),
                    ],
                }
            ]
        }
        policyStr = json.dumps(policy)
        self.client.create_bucket(bucket_name)
        put_out = self.client.put_bucket_policy(bucket_name, policy=policyStr)
        self.assertEqual(put_out.status_code, 204)
        get_out = self.client.get_bucket_policy(bucket_name)
        self.assertEqual(get_out.status_code, 200)
        delete_out = self.client.delete_bucket_policy(bucket_name)
        self.assertEqual(delete_out.status_code, 204)
        self.client.delete_bucket(bucket_name)

    def test_life_cycle(self):
        bucket_name = self.bucket_name + 'lifecycle'
        rules = []
        rules.append(BucketLifeCycleRule(
            id='1',
            prefix='test',
            status=StatusType.Status_Enable,
            expiration=BucketLifeCycleExpiration(
                date=datetime.datetime(2022, 11, 30),
                # days=70
            ),
            no_current_version_expiration=BucketLifeCycleNoCurrentVersionExpiration(
                no_current_days=70
            ),
            # abort_in_complete_multipart_upload=BucketLifeCycleAbortInCompleteMultipartUpload(
            #     days_after_init=10
            # ),
            tags=[Tag(key='1', value="2")],
            transitions=[BucketLifeCycleTransition(
                date=datetime.datetime(2022, 10, 30),
                # days=3,
                storage_class=StorageClassType.Storage_Class_Ia
            )],
            non_current_version_transitions=[BucketLifeCycleNonCurrentVersionTransition(
                storage_class=StorageClassType.Storage_Class_Ia,
                non_current_days=30
            )],
        ))
        self.client.create_bucket(bucket_name)
        self.client.put_bucket_lifecycle(bucket=bucket_name, rules=rules)
        out = self.client.get_bucket_lifecycle(bucket=bucket_name)
        self.client.delete_bucket_policy(bucket=bucket_name)
        self.client.delete_bucket(bucket=bucket_name)

    def test_put_bucket_acl(self):
        bucket_name = self.bucket_name + 'acl'
        self.client.create_bucket(bucket_name)
        put_bucket_acl_out = self.client.put_bucket_acl(bucket=bucket_name, grant_write='id={}'.format(2))
        get_bucket_acl_out = self.client.get_bucket_acl(bucket=bucket_name)
        self.client.delete_bucket(bucket=bucket_name)

    def retry_assert(self, func):
        for i in range(5):
            if func():
                return
            else:
                tim.sleep(i + 2)

        self.assertTrue(False)


if __name__ == "__main__":
    unittest.main()
