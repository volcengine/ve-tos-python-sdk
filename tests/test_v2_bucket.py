# -*- coding: utf-8 -*-
import datetime
import json
import time
import time as tim
import unittest

from pytz import UTC

import tos
from tests.common import TosTestBase, clean_and_delete_bucket
from tos.checkpoint import TaskExecutor
from tos.enum import ACLType, StorageClassType, RedirectType, StatusType, PermissionType, CannedType, GranteeType, \
    VersioningStatusType, ProtocolType, AzRedundancyType, StorageClassInheritDirectiveType, CertStatus
from tos.exceptions import TosClientError, TosServerError
from tos.models2 import CORSRule, Rule, Condition, Redirect, PublicSource, SourceEndpoint, MirrorHeader, \
    BucketLifeCycleRule, BucketLifeCycleExpiration, BucketLifeCycleNoCurrentVersionExpiration, \
    Tag, BucketLifeCycleTransition, \
    BucketLifeCycleNonCurrentVersionTransition, BucketLifeCycleAbortInCompleteMultipartUpload, ReplicationRule, \
    Destination, RedirectAllRequestsTo, IndexDocument, ErrorDocument, RoutingRules, RoutingRule, \
    RoutingRuleCondition, RoutingRuleRedirect, CustomDomainRule, RealTimeLogConfiguration, AccessLogConfiguration, \
    CloudFunctionConfiguration, Filter, FilterKey, FilterRule, RocketMQConfiguration, RocketMQConf, Transform, \
    ReplaceKeyPrefix

tos.set_logger()


class TestBucket(TosTestBase):

    def test_ua(self):
        assert 'v' in tos.clientv2.USER_AGENT

    def test_bucket(self):
        bucket_name = self.bucket_name + "basic"
        self.bucket_delete.append(bucket_name)
        out = self.client.create_bucket(bucket_name)
        self.assertIsNotNone(out.location)

        self.retry_assert(lambda: self.bucket_name + "basic" in (b.name for b in self.client.list_buckets().buckets))
        head_out = self.client.head_bucket(bucket=bucket_name)
        self.assertIsNotNone(head_out.region)
        self.assertEqual(head_out.storage_class, StorageClassType.Storage_Class_Standard)
        key = 'a.txt'
        self.client.put_object(bucket_name, key=key, content='content')

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

        self.client.create_bucket(bucket_name, az_redundancy=AzRedundancyType.Az_Redundancy_Multi_Az)
        self.bucket_delete.append(bucket_name)

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
        for bucket in list_out.buckets:
            self.assertIsNotNone(bucket.location)
            self.assertIsNotNone(bucket.name)
            self.assertIsNotNone(bucket.intranet_endpoint)
            self.assertIsNotNone(bucket.extranet_endpoint)
            self.assertIsNotNone(bucket.creation_date)
        self.assertIsNotNone(list_out.owner.id)

    def test_bucket_info(self):
        bucket_name = self.bucket_name + "-bucket-info"
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
        for acl in ACLType:
            if acl is not ACLType.ACL_Bucket_Owner_Entrusted and acl is not ACLType.ACL_Unknown:
                self.client.create_bucket(bucket_name + acl.value, acl=acl)
                self.client.delete_bucket(bucket_name + acl.value)

    def test_bucket_cors(self):
        bucket_name = self.bucket_name + 'cors'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        cors_rules = []
        cors_rules.append(CORSRule(
            allowed_origins=["example*.com"],
            allowed_methods=['PUT'],
            allowed_headers=['*'],
            expose_headers=['x-tos-test'],
            max_age_seconds=100
        ))
        cors_rules.append(CORSRule(
            allowed_origins=["example*1.com"],
            allowed_methods=['GET'],
            allowed_headers=['*'],
            expose_headers=['*'],
            max_age_seconds=200
        ))
        out = self.client.put_bucket_cors(bucket=bucket_name, cors_rule=cors_rules)
        self.assertIsNotNone(out.id2)
        self.assertIsNotNone(out.request_id)
        out_get = self.client.get_bucket_cors(bucket=bucket_name)
        self.assertTrue(len(out_get.cors_rules), 2)
        self.assertIsNotNone(out_get.request_id)
        self.assertEqual(out_get.cors_rules[0].max_age_seconds, 100)
        self.assertEqual(out_get.cors_rules[0].expose_headers[0], 'x-tos-test')
        self.assertEqual(out_get.cors_rules[0].allowed_headers[0], '*')
        self.assertEqual(out_get.cors_rules[0].allowed_methods[0], 'PUT')
        self.assertEqual(out_get.cors_rules[0].allowed_origins[0], 'example*.com')

        self.assertEqual(out_get.cors_rules[1].max_age_seconds, 200)
        self.assertEqual(out_get.cors_rules[1].expose_headers[0], '*')
        self.assertEqual(out_get.cors_rules[1].allowed_headers[0], '*')
        self.assertEqual(out_get.cors_rules[1].allowed_methods[0], 'GET')
        self.assertEqual(out_get.cors_rules[1].allowed_origins[0], 'example*1.com')

        out_delete = self.client.delete_bucket_cors(bucket=bucket_name)
        self.assertIsNotNone(out_delete.request_id)
        with self.assertRaises(TosServerError):
            self.client.get_bucket_cors(bucket=bucket_name)

    def test_put_bucket_storage_class(self):
        bucket_name = self.bucket_name + 'storage-class'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        put_out = self.client.put_bucket_storage_class(bucket=bucket_name,
                                                       storage_class=StorageClassType.Storage_Class_Ia)
        self.assertIsNotNone(put_out.request_id)
        out = self.client.head_bucket(bucket=bucket_name)
        self.assertEqual(out.storage_class, StorageClassType.Storage_Class_Ia)

        self.client.put_bucket_storage_class(bucket_name, StorageClassType.Storage_Class_Standard)
        self.assertEqual(self.client.head_bucket(bucket_name).storage_class, StorageClassType.Storage_Class_Standard)

        # self.client.put_bucket_storage_class(bucket_name, StorageClassType.Storage_Class_Archive_Fr)
        # self.assertEqual(self.client.head_bucket(bucket_name).storage_class, StorageClassType.Storage_Class_Archive_Fr)

    def test_get_location(self):
        bucket_name = self.bucket_name + 'location'
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket=bucket_name)
        out = self.client.get_bucket_location(bucket=bucket_name)
        self.assertIsNotNone(out.region)
        self.assertIsNotNone(out.extranet_endpoint)
        self.assertIsNotNone(out.intranet_endpoint)

    def test_bucket_mirror(self):
        bucket_name = self.bucket_name + 'mirror'
        self.client.create_bucket(bucket=bucket_name)
        rules = []
        rules.append(Rule(
            id='1',
            condition=Condition(http_code=404),
            redirect=Redirect(
                redirect_type=RedirectType.Mirror,
                fetch_source_on_redirect=True,
                public_source=PublicSource(SourceEndpoint(primary=['http://tosv.byted.org/obj/tostest/'])),
                pass_query=True,
                follow_redirect=True,
                mirror_header=MirrorHeader(pass_all=True, pass_headers=['aaa', 'bbb'], remove=['xxx', 'xxx']),
                transform=Transform(with_key_prefix='prefix', with_key_suffix='suffix',
                                    replace_key_prefix=ReplaceKeyPrefix(key_prefix='prefix1', replace_with='replace'))
            )
        ))
        put_out = self.client.put_bucket_mirror_back(bucket=bucket_name, rules=rules)
        self.assertIsNotNone(put_out.request_id)
        get_out = self.client.get_bucket_mirror_back(bucket=bucket_name)
        self.assertIsNotNone(get_out.request_id)
        self.assertTrue(len(get_out.rules) == 1)
        self.assertEqual(get_out.rules[0].id, '1')
        self.assertEqual(get_out.rules[0].condition.http_code, 404)
        self.assertEqual(get_out.rules[0].redirect.redirect_type, RedirectType.Mirror)
        self.assertEqual(get_out.rules[0].redirect.follow_redirect, True)
        self.assertEqual(get_out.rules[0].redirect.fetch_source_on_redirect, True)
        self.assertEqual(get_out.rules[0].redirect.mirror_header.pass_all, True)
        self.assertEqual(get_out.rules[0].redirect.mirror_header.pass_headers, ['aaa', 'bbb'])
        self.assertEqual(get_out.rules[0].redirect.mirror_header.remove, ['xxx', 'xxx'])
        self.assertEqual(get_out.rules[0].redirect.public_source.source_endpoint.primary,
                         ['http://tosv.byted.org/obj/tostest/'])
        self.assertEqual(get_out.rules[0].redirect.public_source.fixed_endpoint, None)
        self.assertEqual(get_out.rules[0].redirect.transform.with_key_prefix, 'prefix')
        self.assertEqual(get_out.rules[0].redirect.transform.with_key_suffix, 'suffix')
        self.assertEqual(get_out.rules[0].redirect.transform.replace_key_prefix.key_prefix, 'prefix1')
        self.assertEqual(get_out.rules[0].redirect.transform.replace_key_prefix.replace_with, 'replace')
        rules = []
        rules.append(Rule(
            id='2',
            condition=Condition(http_code=404),
            redirect=Redirect(
                redirect_type=RedirectType.Async,
                fetch_source_on_redirect=False,
                public_source=PublicSource(SourceEndpoint(primary=['http://test.com/obj/tostest2/'],
                                                          follower=['http://test.com/obj/tostest2/3']),
                                           fixed_endpoint=True),
                pass_query=False,
                follow_redirect=False,
                mirror_header=MirrorHeader(pass_all=False, pass_headers=['aaa2', 'bbb2'], remove=['xxxx', 'xxxx'])
            )
        ))
        put_out = self.client.put_bucket_mirror_back(bucket=bucket_name, rules=rules)
        get_out = self.client.get_bucket_mirror_back(bucket=bucket_name)
        self.assertEqual(get_out.rules[0].id, '2')
        self.assertEqual(get_out.rules[0].condition.http_code, 404)
        self.assertEqual(get_out.rules[0].redirect.redirect_type, RedirectType.Async)
        self.assertEqual(get_out.rules[0].redirect.follow_redirect, None)
        self.assertEqual(get_out.rules[0].redirect.fetch_source_on_redirect, None)
        self.assertEqual(get_out.rules[0].redirect.mirror_header.pass_all, None)
        self.assertEqual(get_out.rules[0].redirect.mirror_header.pass_headers, ['aaa2', 'bbb2'])
        self.assertEqual(get_out.rules[0].redirect.mirror_header.remove, ['xxxx', 'xxxx'])
        self.assertEqual(get_out.rules[0].redirect.public_source.source_endpoint.primary,
                         ['http://test.com/obj/tostest2/'])
        self.assertEqual(get_out.rules[0].redirect.public_source.source_endpoint.follower,
                         ['http://test.com/obj/tostest2/3'])
        self.assertEqual(get_out.rules[0].redirect.public_source.fixed_endpoint, True)

        delete_out = self.client.delete_bucket_mirror_back(bucket=bucket_name)
        self.assertIsNotNone(delete_out.request_id)
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
        self.assertIsNotNone(delete_out.request_id)
        with self.assertRaises(TosServerError):
            self.client.get_bucket_policy(bucket_name)
        self.client.delete_bucket(bucket_name)

    def test_life_cycle(self):
        bucket_name = self.bucket_name + 'lifecycle'
        rules = []
        rules.append(BucketLifeCycleRule(
            id='1',
            prefix='test',
            status=StatusType.Status_Enable,
            # 指定 Bucket的过期属性
            expiration=BucketLifeCycleExpiration(
                date=datetime.datetime(2022, 11, 30),
                # days=70
            ),
            tags=[Tag(key='1', value="2"), Tag('test', 'test')],
        ))
        self.client.create_bucket(bucket_name)
        self.client.put_bucket_lifecycle(bucket=bucket_name, rules=rules)
        out = self.client.get_bucket_lifecycle(bucket=bucket_name)
        self.assertEqual(len(out.rules[0].tags), 2)
        self.assertEqual(out.rules[0].tags[0].key, '1')
        self.assertEqual(out.rules[0].tags[0].value, '2')
        self.assertEqual(out.rules[0].tags[1].key, 'test')
        self.assertEqual(out.rules[0].tags[1].value, 'test')
        self.client.delete_bucket(bucket=bucket_name)

    def test_lifecycle_days(self):
        bucket_name = self.bucket_name + 'lifecycle'
        rules = []
        rules.append(BucketLifeCycleRule(
            id='1',
            prefix='test',
            status=StatusType.Status_Enable,
            # 指定 Bucket的过期属性
            expiration=BucketLifeCycleExpiration(
                days=70
            ),
            no_current_version_expiration=BucketLifeCycleNoCurrentVersionExpiration(
                no_current_days=70
            ),
            abort_in_complete_multipart_upload=BucketLifeCycleAbortInCompleteMultipartUpload(
                days_after_init=10
            ),
            transitions=[BucketLifeCycleTransition(
                days=20,
                storage_class=StorageClassType.Storage_Class_Ia
            )],
            non_current_version_transitions=[BucketLifeCycleNonCurrentVersionTransition(
                storage_class=StorageClassType.Storage_Class_Ia,
                non_current_days=30
            )],
        ))
        rules.append(BucketLifeCycleRule(
            id='2',
            prefix='log',
            status=StatusType.Status_Disable,
            # 指定 Bucket的过期属性
            expiration=BucketLifeCycleExpiration(
                days=60
            ),
            no_current_version_expiration=BucketLifeCycleNoCurrentVersionExpiration(
                no_current_days=60
            ),
            abort_in_complete_multipart_upload=BucketLifeCycleAbortInCompleteMultipartUpload(
                days_after_init=5
            ),
            transitions=[BucketLifeCycleTransition(
                days=10,
                storage_class=StorageClassType.Storage_Class_Ia
            )],
            non_current_version_transitions=[BucketLifeCycleNonCurrentVersionTransition(
                storage_class=StorageClassType.Storage_Class_Ia,
                non_current_days=10
            )],
        ))
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        self.client.put_bucket_lifecycle(bucket=bucket_name, rules=rules)
        out = self.client.get_bucket_lifecycle(bucket=bucket_name)
        self.assertEqual(len(out.rules), 2)
        # 检验 rule1的正确性
        rule1 = out.rules[0]
        self.assertEqual(rule1.id, '1')
        self.assertEqual(rule1.prefix, 'test')
        self.assertEqual(rule1.status, StatusType.Status_Enable)
        self.assertEqual(rule1.expiration.days, 70)
        self.assertEqual(rule1.no_current_version_expiration.no_current_days, 70)
        self.assertEqual(rule1.abort_in_complete_multipart_upload.days_after_init, 10)
        self.assertEqual(rule1.transitions[0].days, 20)
        self.assertEqual(rule1.transitions[0].storage_class, StorageClassType.Storage_Class_Ia)
        self.assertEqual(rule1.non_current_version_transitions[0].non_current_days, 30)
        self.assertEqual(rule1.non_current_version_transitions[0].storage_class, StorageClassType.Storage_Class_Ia)
        # 校验 rule2的正确性
        rule2 = out.rules[1]
        self.assertEqual(rule2.id, '2')
        self.assertEqual(rule2.prefix, 'log')
        self.assertEqual(rule2.status, StatusType.Status_Disable)
        self.assertEqual(rule2.expiration.days, 60)
        self.assertEqual(rule2.no_current_version_expiration.no_current_days, 60)
        self.assertEqual(rule2.abort_in_complete_multipart_upload.days_after_init, 5)
        self.assertEqual(rule2.transitions[0].days, 10)
        self.assertEqual(rule2.transitions[0].storage_class, StorageClassType.Storage_Class_Ia)
        self.assertEqual(rule2.non_current_version_transitions[0].non_current_days, 10)
        self.assertEqual(rule2.non_current_version_transitions[0].storage_class, StorageClassType.Storage_Class_Ia)
        delete_out = self.client.delete_bucket_lifecycle(bucket_name)
        self.assertIsNotNone(delete_out.request_id)

    def test_lifecycle_date(self):
        bucket_name = self.bucket_name + 'lifecycle'
        rules = []
        rules.append(BucketLifeCycleRule(
            id='1',
            prefix='test',
            status=StatusType.Status_Enable,
            # 指定 Bucket的过期属性
            expiration=BucketLifeCycleExpiration(
                date=datetime.datetime(2022, 11, 30)
            ),
            no_current_version_expiration=BucketLifeCycleNoCurrentVersionExpiration(
                no_current_days=70
            ),
            abort_in_complete_multipart_upload=BucketLifeCycleAbortInCompleteMultipartUpload(
                days_after_init=10
            ),
            transitions=[BucketLifeCycleTransition(
                date=datetime.datetime(2022, 10, 30),
                storage_class=StorageClassType.Storage_Class_Ia
            )],
            non_current_version_transitions=[BucketLifeCycleNonCurrentVersionTransition(
                storage_class=StorageClassType.Storage_Class_Ia,
                non_current_days=30
            )],
        ))
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        self.client.put_bucket_lifecycle(bucket=bucket_name, rules=rules)
        out = self.client.get_bucket_lifecycle(bucket=bucket_name)
        # 检验 rule1的正确性
        rule1 = out.rules[0]
        self.assertEqual(rule1.id, '1')
        self.assertEqual(rule1.prefix, 'test')
        self.assertEqual(rule1.status, StatusType.Status_Enable)
        self.assertEqual(rule1.expiration.date, datetime.datetime(2022, 11, 30, tzinfo=UTC))
        self.assertEqual(rule1.no_current_version_expiration.no_current_days, 70)
        self.assertEqual(rule1.abort_in_complete_multipart_upload.days_after_init, 10)
        self.assertEqual(rule1.transitions[0].date, datetime.datetime(2022, 10, 30, tzinfo=UTC))
        self.assertEqual(rule1.transitions[0].storage_class, StorageClassType.Storage_Class_Ia)
        self.assertEqual(rule1.non_current_version_transitions[0].non_current_days, 30)
        self.assertEqual(rule1.non_current_version_transitions[0].storage_class, StorageClassType.Storage_Class_Ia)

    def test_put_bucket_acl(self):
        bucket_name = self.bucket_name + '-acl'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        put_out = self.client.put_bucket_acl(bucket=bucket_name, grant_write='id={}'.format(2))
        self.assertIsNotNone(put_out.request_id)
        get_out = self.client.get_bucket_acl(bucket=bucket_name)
        self.assertIsNotNone(get_out.owner.id)
        self.assertEqual(get_out.grants[0].permission, PermissionType.Permission_Write)
        self.assertEqual(get_out.grants[0].grantee.id, '2')
        self.assertIsNotNone(get_out.grants[0].grantee.type, GranteeType.Grantee_User)

        self.client.put_bucket_acl(bucket_name, acl=ACLType.ACL_Public_Read)
        get_out = self.client.get_bucket_acl(bucket=bucket_name)
        self.assertIsNotNone(get_out.owner.id)
        self.assertEqual(get_out.grants[0].permission, PermissionType.Permission_Read)
        self.assertEqual(get_out.grants[0].grantee.canned, CannedType.Canned_All_Users)

        self.client.delete_bucket(bucket=bucket_name)

    def test_put_bucket_replication(self):
        bucket_name_src = self.bucket_name + 'replication'
        bucket_name_crr = self.bucket_name + '-crr'
        bucket_name_crr_2 = self.bucket_name + '-crr2'
        self.client.create_bucket(bucket_name_src)
        self.client2.create_bucket(bucket_name_crr)
        self.client2.create_bucket(bucket_name_crr_2)
        self.bucket_delete.append(bucket_name_src)
        self.bucket_delete.append(bucket_name_crr)
        self.bucket_delete.append(bucket_name_crr_2)
        rules = []
        rules.append(ReplicationRule(id='1',
                                     status=StatusType.Status_Enable,
                                     prefix_set=['prefix1', 'prefix2'],
                                     destination=Destination(bucket=bucket_name_crr, location=self.region2,
                                                             storage_class=StorageClassType.Storage_Class_Ia,
                                                             storage_class_inherit_directive=StorageClassInheritDirectiveType.Storage_Class_ID_Source_Object),
                                     historical_object_replication=StatusType.Status_Enable))

        rules.append(ReplicationRule(id='2',
                                     status=StatusType.Status_Enable,
                                     prefix_set=['prefix3', 'prefix4'],
                                     destination=Destination(bucket=bucket_name_crr_2, location=self.region2,
                                                             storage_class=StorageClassType.Storage_Class_Standard,
                                                             storage_class_inherit_directive=StorageClassInheritDirectiveType.Storage_Class_ID_Source_Object),
                                     historical_object_replication=StatusType.Status_Disable))

        put_out = self.client.put_bucket_replication(bucket_name_src, role='ServiceRoleforReplicationAccessTOS',
                                                     rules=rules)
        self.assertIsNotNone(put_out.request_id)
        out = self.client.get_bucket_replication(bucket_name_src, '1')
        self.assertIsNotNone(out.request_id)
        self.assertTrue(len(out.rules) == 1)
        self.assertEqual(out.rules[0].id, '1')
        self.assertEqual(out.rules[0].prefix_set, ['prefix1', 'prefix2'])
        self.assertEqual(out.rules[0].destination.bucket, bucket_name_crr)
        self.assertEqual(out.rules[0].destination.location, self.region2)
        self.assertEqual(out.rules[0].destination.storage_class, StorageClassType.Storage_Class_Ia)
        self.assertEqual(out.rules[0].destination.storage_class_inherit_directive,
                         StorageClassInheritDirectiveType.Storage_Class_ID_Source_Object)
        self.assertEqual(out.rules[0].historical_object_replication, StatusType.Status_Enable)
        self.assertIsNotNone(out.rules[0].progress)
        self.assertEqual(out.rules[0].progress.historical_object, 0.0)
        out = self.client.get_bucket_replication(bucket_name_src, '2')
        self.assertIsNotNone(out.request_id)
        self.assertTrue(len(out.rules) == 1)
        self.assertEqual(out.rules[0].id, '2')
        self.assertEqual(out.rules[0].prefix_set, ['prefix3', 'prefix4'])
        self.assertEqual(out.rules[0].destination.bucket, bucket_name_crr_2)
        self.assertEqual(out.rules[0].destination.location, self.region2)
        self.assertEqual(out.rules[0].destination.storage_class, StorageClassType.Storage_Class_Standard)
        self.assertEqual(out.rules[0].destination.storage_class_inherit_directive,
                         StorageClassInheritDirectiveType.Storage_Class_ID_Source_Object)
        self.assertEqual(out.rules[0].historical_object_replication, StatusType.Status_Disable)
        self.assertIsNotNone(out.rules[0].progress)
        self.assertEqual(out.rules[0].progress.historical_object, 0.0)

        out = self.client.get_bucket_replication(bucket_name_src)
        self.assertEqual(len(out.rules), 2)

        out = self.client.delete_bucket_replication(bucket_name_src)
        self.assertIsNotNone(out.request_id)

        with self.assertRaises(TosServerError):
            self.client.get_bucket_replication(bucket_name_src)

    def test_bucket_version(self):
        bucket_name = self.bucket_name + 'version'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        out = self.client.put_bucket_versioning(bucket_name, VersioningStatusType.Versioning_Status_Enabled)
        self.assertIsNotNone(out.request_id)
        time.sleep(30)
        out = self.client.get_bucket_version(bucket_name)
        self.assertIsNotNone(out.request_id)
        self.assertEqual(VersioningStatusType.Versioning_Status_Enabled, out.status)

        self.client.put_bucket_versioning(bucket_name, VersioningStatusType.Versioning_Status_Suspended)
        out = self.client.get_bucket_version(bucket_name)
        time.sleep(30)
        self.assertEqual(out.status, VersioningStatusType.Versioning_Status_Suspended)

    def test_bucket_website(self):
        bucket_name = self.bucket_name + 'website'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        rule1 = RoutingRule(condition=RoutingRuleCondition(key_prefix_equals='prefix'),
                            redirect=RoutingRuleRedirect(protocol=ProtocolType.Protocol_Http, host_name='test2.name',
                                                         replace_key_with='replace_key_with',
                                                         http_redirect_code=302))
        rule2 = RoutingRule(condition=RoutingRuleCondition(http_error_code_returned_equals=403),
                            redirect=RoutingRuleRedirect(protocol=ProtocolType.Protocol_Https, host_name='test3.name',
                                                         replace_key_prefix_with='replace_prefix2',
                                                         http_redirect_code=301))
        redirect_all = RedirectAllRequestsTo('test.com', 'http')
        index_document = IndexDocument('index.html', forbidden_sub_dir=True)
        error_document = ErrorDocument('error.html')
        routing_rules = RoutingRules([rule1, rule2])
        out = self.client.put_bucket_website(bucket=bucket_name, redirect_all_requests_to=redirect_all)
        self.assertIsNotNone(out.request_id)
        out = self.client.get_bucket_website(bucket=bucket_name)
        self.assertEqual(out.redirect_all_requests_to.protocol, 'http')
        self.assertEqual(out.redirect_all_requests_to.host_name, 'test.com')

        self.client.put_bucket_website(bucket_name, index_document=index_document, error_document=error_document,
                                       routing_rules=routing_rules)

        out = self.client.get_bucket_website(bucket_name)
        self.assertEqual(out.index_document.suffix, 'index.html')
        self.assertEqual(out.index_document.forbidden_sub_dir, True)

        self.assertEqual(out.error_document.key, 'error.html')
        self.assertEqual(len(out.routing_rules), 2)
        self.assertEqual(out.routing_rules[0].condition.key_prefix_equals, 'prefix')
        self.assertEqual(out.routing_rules[0].condition.http_error_code_returned_equals, None)
        self.assertEqual(out.routing_rules[0].redirect.host_name, 'test2.name')
        self.assertEqual(out.routing_rules[0].redirect.protocol, ProtocolType.Protocol_Http)
        self.assertEqual(out.routing_rules[0].redirect.http_redirect_code, 302)
        self.assertEqual(out.routing_rules[0].redirect.replace_key_with, 'replace_key_with')

        self.assertEqual(out.routing_rules[1].condition.http_error_code_returned_equals, 403)
        self.assertEqual(out.routing_rules[1].condition.key_prefix_equals, None)
        self.assertEqual(out.routing_rules[1].redirect.host_name, 'test3.name')
        self.assertEqual(out.routing_rules[1].redirect.protocol, ProtocolType.Protocol_Https)
        self.assertEqual(out.routing_rules[1].redirect.http_redirect_code, 301)
        self.assertEqual(out.routing_rules[1].redirect.replace_key_prefix_with, 'replace_prefix2')

        delete_out = self.client.delete_bucket_website(bucket_name)
        self.assertIsNotNone(delete_out.request_id)
        with self.assertRaises(TosServerError):
            out = self.client.get_bucket_website(bucket_name)

    # def test_put_bucket_custom_domain(self):
    #     bucket_name = self.bucket_name + '-custom-domain1'
    #     self.client2.create_bucket(bucket_name)
    #     self.bucket_delete.append(bucket_name)
    #     domain = CustomDomainRule(domain='example22.test.com', forbidden=True, forbidden_reason='test')
    #     domain2 = CustomDomainRule(domain='example33.test.com', forbidden=False, forbidden_reason='test2',
    #                                cert_status=CertStatus.Cert_Status_Bound)
    #     self.client2.put_bucket_custom_domain(bucket_name, domain)
    #     self.client2.put_bucket_custom_domain(bucket_name, domain2)
    #
    #     list_out = self.client2.List_bucket_custom_domain(bucket_name)
    #     self.assertEqual(list_out.rules[0].domain, 'example2.test.com')
    #     self.assertEqual(list_out.rules[1].domain, 'example3.test.com')
    #     out = self.client2.delete_bucket_custom_domain(bucket_name, domain='example2.test.com')
    #     self.assertIsNotNone(out.request_id)
    #     list_out = self.client2.List_bucket_custom_domain(bucket_name)
    #     self.assertEqual(len(list_out.rules), 1)
    #     self.client2.delete_bucket_custom_domain(bucket_name, domain='example3.test.com')
    #     with self.assertRaises(TosServerError):
    #         self.client2.List_bucket_custom_domain(bucket_name)

    def test_put_bucket_notification(self):
        bucket_name = self.bucket_name + '-notification'
        self.client2.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        cloud_config = CloudFunctionConfiguration(
            id='1',
            events=['tos:ObjectCreated:Put'],
            filter=Filter(
                key=FilterKey(
                    rules=[FilterRule(name='prefix', value='object')]
                )),
            cloud_function='zkru2tzw'
        )

        out = self.client2.put_bucket_notification(bucket_name, [cloud_config])
        self.assertIsNotNone(out.request_id)
        get_out = self.client2.get_bucket_notification(bucket_name)
        self.assertEqual(get_out.cloud_function_configurations[0].id, '1')
        self.assertEqual(get_out.cloud_function_configurations[0].events, ['tos:ObjectCreated:Put'])
        self.assertEqual(get_out.cloud_function_configurations[0].cloud_function, 'zkru2tzw')
        self.assertEqual(get_out.cloud_function_configurations[0].filter.key.rules[0].name, 'prefix')
        self.assertEqual(get_out.cloud_function_configurations[0].filter.key.rules[0].value, 'object')

    def test_put_bucket_notification_mq(self):
        bucket_name = self.bucket_name + '-notification-mq'
        self.client2.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        rocket_mq_config = RocketMQConfiguration(
            id='2',
            events=['tos:ObjectCreated:Post'],
            role='trn:iam::{}:role/{}'.format(self.account_id, self.mq_role_name),
            filter=Filter(
                key=FilterKey(
                    rules=[FilterRule(name='prefix', value='object')]
                )),
            rocket_mq=RocketMQConf(
                instance_id=self.mq_instance_id,
                topic='SDK',
                access_key_id=self.mq_access_key_id
            )
        )
        out = self.client2.put_bucket_notification(bucket_name,
                                                   rocket_mq_configurations=[rocket_mq_config])
        self.assertIsNotNone(out.request_id)
        get_out = self.client2.get_bucket_notification(bucket_name)
        self.assertEqual(get_out.rocket_mq_configurations[0].id, '2')
        self.assertEqual(get_out.rocket_mq_configurations[0].events, ['tos:ObjectCreated:Post'])
        self.assertEqual(get_out.rocket_mq_configurations[0].role,
                         'trn:iam::{}:role/{}'.format(self.account_id, self.mq_role_name))
        self.assertEqual(get_out.rocket_mq_configurations[0].filter.key.rules[0].name, 'prefix')
        self.assertEqual(get_out.rocket_mq_configurations[0].filter.key.rules[0].value, 'object')
        self.assertEqual(get_out.rocket_mq_configurations[0].rocket_mq.instance_id, self.mq_instance_id)
        self.assertEqual(get_out.rocket_mq_configurations[0].rocket_mq.topic, 'SDK')
        self.assertEqual(get_out.rocket_mq_configurations[0].rocket_mq.access_key_id, self.mq_access_key_id)

    def test_put_bucket_real_time_log(self):
        bucket_name = self.bucket_name + '-real-time-log'
        self.client2.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        config = RealTimeLogConfiguration(role='TOSLogArchiveTLSRole',
                                          configuration=AccessLogConfiguration(use_service_topic=True))
        out = self.client2.put_bucket_real_time_log(bucket_name, config)
        self.assertIsNotNone(out.request_id)
        get_out = self.client2.get_bucket_real_time_log(bucket_name)
        self.assertIsNotNone(get_out.request_id)
        self.assertEqual(get_out.configuration.role, 'TOSLogArchiveTLSRole')
        self.assertEqual(get_out.configuration.configuration.use_service_topic, True)
        self.assertIsNotNone(get_out.configuration.configuration.use_service_topic)
        self.assertIsNotNone(get_out.configuration.configuration.tls_project_id)
        delete_out = self.client2.delete_bucket_real_time_log(bucket_name)
        self.assertIsNotNone(delete_out.request_id)
        with self.assertRaises(TosServerError):
            self.client2.get_bucket_real_time_log(bucket_name)

    def retry_assert(self, func):
        for i in range(5):
            if func():
                return
            else:
                tim.sleep(i + 2)

        self.assertTrue(False)

    def test_delete_all(self):
        out = self.client2.list_buckets()
        task = TaskExecutor(15, clean_and_delete_bucket, None)
        for bucket in out.buckets:
            if bucket.name.startswith('sun'):
                if bucket.extranet_endpoint == self.endpoint2:
                    task.submit(self.client2, bucket.name)
                if bucket.extranet_endpoint == self.endpoint:
                    task.submit(self.client, bucket.name)
        task.run()


if __name__ == "__main__":
    unittest.main()
