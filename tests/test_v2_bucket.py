# -*- coding: utf-8 -*-
import datetime
import json
import os
import time
import time as tim
import unittest
import string
import random

import crcmod
from pytz import UTC

import tos
from tests.common import TosTestBase, clean_and_delete_bucket
from tos import TosClientV2
from tos.checkpoint import TaskExecutor
from tos.clientv2 import USER_AGENT
from tos.consts import BUCKET_TYPE_HNS, BUCKET_TYPE_FNS
from tos.credential import EnvCredentialsProvider
from tos.enum import ACLType, StorageClassType, RedirectType, StatusType, PermissionType, CannedType, GranteeType, \
    VersioningStatusType, ProtocolType, AzRedundancyType, StorageClassInheritDirectiveType, CertStatus, \
    InventoryFormatType, InventoryFrequencyType, InventoryIncludedObjType
from tos.exceptions import TosClientError, TosServerError
from tos.models2 import CORSRule, Rule, Condition, Redirect, PublicSource, SourceEndpoint, MirrorHeader, \
    BucketLifeCycleRule, BucketLifeCycleExpiration, BucketLifeCycleNoCurrentVersionExpiration, \
    Tag, BucketLifeCycleTransition, \
    BucketLifeCycleNonCurrentVersionTransition, BucketLifeCycleAbortInCompleteMultipartUpload, ReplicationRule, \
    Destination, RedirectAllRequestsTo, IndexDocument, ErrorDocument, RoutingRules, RoutingRule, \
    RoutingRuleCondition, RoutingRuleRedirect, CustomDomainRule, RealTimeLogConfiguration, AccessLogConfiguration, \
    CloudFunctionConfiguration, Filter, FilterKey, FilterRule, RocketMQConfiguration, RocketMQConf, Transform, \
    ReplaceKeyPrefix, FetchHeaderToMetaDataRule, BucketEncryptionRule, ApplyServerSideEncryptionByDefault, \
    BucketLifecycleFilter, NotificationRule, NotificationFilter, NotificationFilterKey, NotificationFilterRule, \
    NotificationDestination, DestinationVeFaaS, DestinationRocketMQ, KV, BucketInventoryConfiguration, \
    InventoryDestination, TOSBucketDestination, InventorySchedule, InventoryFilter, InventoryOptionalFields, \
    AccessControlTranslation, PrivateSource, CommonSourceEndpoint, EndpointCredentialProvider, CredentialProvider

tos.set_logger()


class TestBucket(TosTestBase):

    def test_ua(self):
        assert 'v' in tos.clientv2.USER_AGENT
        client = TosClientV2(self.ak, self.sk, self.endpoint, self.region, enable_crc=True, max_retry_count=2,
                             user_agent_product_name='tos', user_agent_soft_name='crr',
                             user_agent_soft_version='v3.0.0')
        print(client.user_agent)
        print(USER_AGENT + " --tos/crr/v3.0.0")
        assert client.user_agent == USER_AGENT + " --tos/crr/v3.0.0"

        assert 'v' in tos.clientv2.USER_AGENT
        client = TosClientV2(self.ak, self.sk, self.endpoint, self.region, enable_crc=True, max_retry_count=2,
                             user_agent_product_name='tos', user_agent_soft_name='crr',
                             user_agent_soft_version='v3.0.0', user_agent_customized_key_values={'aa':'bb', 'cc':'dd'})
        print(client.user_agent)
        print(USER_AGENT + " --tos/crr/v3.0.0 (aa/bb;cc/dd)")
        assert (client.user_agent == USER_AGENT + " --tos/crr/v3.0.0 (aa/bb;cc/dd)")

    def test_hns_bucket_expires(self):
        bucket_name = self.bucket_name + "hcl"
        self.bucket_delete.append(bucket_name)
        # bucket_name = "sun-eafrofzkzphcl"
        rsp = self.client.create_bucket(bucket_name, bucket_type="hns")
        print(rsp)
        assert rsp.status_code == 200
        rsp = self.client.head_bucket(bucket=bucket_name)
        assert rsp.status_code == 200
        assert rsp.bucket_type == BUCKET_TYPE_HNS

        append_key_0 = "hns/test/0.txt"
        rsp = self.client.append_object(bucket=bucket_name, key=append_key_0, offset=0, content="hello0",
                                        content_length=6,object_expires=3)
        assert rsp.status_code == 200
        offset = rsp.next_append_offset
        assert offset == 6
        head_out = self.client.head_object(bucket=bucket_name,key=append_key_0)
        assert head_out.status_code == 200
        assert head_out.expiration is not None

        append_key = "hns/test/2.txt"
        rsp = self.client.append_object(bucket=bucket_name, key=append_key, offset=0, content_length=0,object_expires=3)
        assert rsp.status_code == 200
        rsp = self.client.head_object(bucket=bucket_name, key=append_key)
        assert rsp.status_code == 200
        assert head_out.expiration is not None
        rsp = self.client.append_object(bucket=bucket_name, key=append_key, offset=0, content="hello1",
                                        content_length=6)
        offset = rsp.next_append_offset
        assert rsp.status_code == 200
        assert offset == 6
        rsp = self.client.head_object(bucket=bucket_name, key=append_key)
        assert rsp.status_code == 200

    def test_hns_bucket(self):
        bucket_name = self.bucket_name + "hcl"
        self.bucket_delete.append(bucket_name)
        # bucket_name = "sun-eafrofzkzphcl"
        rsp = self.client.create_bucket(bucket_name, bucket_type="hns")
        print(rsp)
        assert rsp.status_code == 200
        rsp = self.client.head_bucket(bucket=bucket_name)
        assert rsp.status_code == 200
        assert rsp.bucket_type == BUCKET_TYPE_HNS
        key = "hns/test/1.txt"
        rsp = self.client.put_object(bucket=bucket_name, key=key, content="hello")
        assert rsp.status_code == 200
        # rsp = self.client.head_object(bucket=bucket_name, key=key)

        rsp = self.client.get_file_status(bucket=bucket_name, key=key)
        assert rsp.status_code == 200

        append_key_0 = "hns/test/0.txt"
        rsp = self.client.append_object(bucket=bucket_name, key=append_key_0, offset=0, content="hello0",
                                        content_length=6)
        assert rsp.status_code == 200
        offset = rsp.next_append_offset
        assert offset == 6

        append_key = "hns/test/2.txt"
        try:
            rsp = self.client.append_object(bucket=bucket_name, key=append_key, offset=0, content_length=0, if_match='123')
        except TosServerError as e:
            assert e.status_code == 404
        assert rsp.status_code == 200
        rsp = self.client.append_object(bucket=bucket_name, key=append_key, offset=0, content_length=0)
        assert rsp.status_code == 200
        rsp = self.client.get_object(bucket=bucket_name, key=append_key)
        assert rsp.status_code == 200
        rsp = self.client.append_object(bucket=bucket_name, key=append_key, offset=0, content="hello1",
                                        content_length=6)
        offset = rsp.next_append_offset
        assert rsp.status_code == 200
        assert offset == 6
        rsp = self.client.append_object(bucket=bucket_name, key=append_key, offset=offset, content="hello2")
        offset = rsp.next_append_offset
        assert rsp.status_code == 200
        assert offset == 12
        rsp = self.client.get_object(bucket=bucket_name, key=append_key)
        data = rsp.read().decode('utf-8')
        assert data == 'hello1hello2'

        rsp = self.client.list_buckets(bucket_type=BUCKET_TYPE_HNS)
        assert rsp.status_code == 200
        print(rsp)
        hns_number = len(rsp.buckets)
        for bucket in rsp.buckets:
            assert bucket.bucket_type == BUCKET_TYPE_HNS

        rsp = self.client.list_buckets(bucket_type=BUCKET_TYPE_FNS)
        assert rsp.status_code == 200
        fns_number = len(rsp.buckets)
        for bucket in rsp.buckets:
            assert bucket.bucket_type == BUCKET_TYPE_FNS
        rsp = self.client.list_buckets()
        assert rsp.status_code == 200
        bucket_number = len(rsp.buckets)
        assert bucket_number == hns_number + fns_number

    def test_hns_bucket_is_directory(self):
        # hns 桶
        bucket_name = self.bucket_name + "hns"
        self.bucket_delete.append(bucket_name)
        rsp = self.client.create_bucket(bucket_name, bucket_type="hns")
        assert rsp.status_code == 200
        rsp = self.client.head_bucket(bucket=bucket_name)
        assert rsp.status_code == 200
        assert rsp.bucket_type == BUCKET_TYPE_HNS
        key = "hns/test/1.txt"

        rsp = self.client.put_object(bucket=bucket_name, key=key, content="hello")
        assert rsp.status_code == 200
        rsp = self.client.head_object(bucket=bucket_name, key=key)
        assert rsp.is_directory is False
        rsp = self.client.head_object(bucket=bucket_name, key="hns/")
        assert rsp.is_directory is True
        rsp = self.client.head_object(bucket=bucket_name, key="hns")
        assert rsp.is_directory is True
        rsp = self.client.get_object(bucket=bucket_name, key=key)
        assert rsp.is_directory is False
        rsp = self.client.get_object(bucket=bucket_name, key="hns/")
        assert rsp.is_directory is True
        rsp = self.client.get_object(bucket=bucket_name, key="hns")
        assert rsp.is_directory is True

        rsp = self.client.list_objects_type2(bucket=bucket_name, delimiter='/', prefix='hns/')
        rsp = self.client.list_objects(bucket=bucket_name, delimiter='/', prefix='hns/')

        rsp = self.client.list_buckets()
        # 普通桶
        bucket_name = self.bucket_name + "fns"
        self.bucket_delete.append(bucket_name)
        rsp = self.client.create_bucket(bucket_name)
        assert rsp.status_code == 200
        rsp = self.client.head_bucket(bucket=bucket_name)
        assert rsp.status_code == 200
        assert rsp.bucket_type == BUCKET_TYPE_FNS
        key = "fns/test/1.txt"
        rsp = self.client.put_object(bucket=bucket_name, key=key, content="hello")
        assert rsp.status_code == 200
        rsp = self.client.head_object(bucket=bucket_name, key=key)
        assert rsp.is_directory is False
        with self.assertRaises(TosServerError):
            rsp = self.client.head_object(bucket=bucket_name, key="hns")
        with self.assertRaises(TosServerError):
            rsp = self.client.head_object(bucket=bucket_name, key="hns/")
        rsp = self.client.get_object(bucket=bucket_name, key=key)
        assert rsp.is_directory is False
        with self.assertRaises(TosServerError):
            rsp = self.client.get_object(bucket=bucket_name, key="hns")
        with self.assertRaises(TosServerError):
            rsp = self.client.get_object(bucket=bucket_name, key="hns/")


    def test_get_file_status(self):
        bucket_name = self.bucket_name + "basic"
        self.bucket_delete.append(bucket_name)
        out = self.client.create_bucket(bucket_name)
        assert out.status_code == 200
        key = "hns/test/1.txt"
        content = "hello"
        rsp = self.client.put_object(bucket=bucket_name, key=key, content=content)
        assert rsp.status_code == 200
        rsp = self.client.get_file_status(bucket=bucket_name, key=key)
        assert rsp.status_code == 200
        assert rsp.key == key
        do_crc64 = crcmod.mkCrcFun(0x142F0E1EBA9EA3693, initCrc=0, xorOut=0xffffffffffffffff, rev=True)
        c1 = do_crc64(content.encode())
        assert rsp.crc64 == str(c1)

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

        bucket_name = self.bucket_name + "multi-az"
        self.client.create_bucket(bucket_name, az_redundancy=AzRedundancyType.Az_Redundancy_Multi_Az)
        self.client.delete_bucket(bucket_name)
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
            max_age_seconds=200,
            response_vary=True,
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
        self.assertEqual(out_get.cors_rules[1].response_vary, True)

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
        time.sleep(60)
        out = self.client.head_bucket(bucket=bucket_name)
        self.assertEqual(out.storage_class, StorageClassType.Storage_Class_Ia)

        self.client.put_bucket_storage_class(bucket_name, StorageClassType.Storage_Class_Standard)
        time.sleep(60)
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

    def test_bucket_private_mirror(self):
        bucket_name = self.bucket_name + 'private-mirror'
        self.client.create_bucket(bucket=bucket_name)
        self.bucket_delete.append(bucket_name)

        rules = []
        rules.append(Rule(
            id='1',
            condition=Condition(http_code=404, allow_host=["example.com"], http_method=["GET", "HEAD"]),
            redirect=Redirect(
                redirect_type=RedirectType.Mirror,
                fetch_source_on_redirect=True,
                private_source=PrivateSource(source_endpoint=CommonSourceEndpoint(
                    primary=[EndpointCredentialProvider(
                        endpoint="https://example.com",
                        bucket_name=bucket_name,
                        credential_provider=CredentialProvider("ServiceRoleBackSourceAccessTOS")
                    )],
                    follower=[EndpointCredentialProvider(
                        endpoint="https://example2.com",
                        bucket_name=bucket_name,
                        credential_provider=CredentialProvider("ServiceRoleBackSourceAccessTOS")
                    )]
                ),),
                pass_query=True,
                follow_redirect=True,
                mirror_header=MirrorHeader(pass_all=True, pass_headers=['aaa', 'bbb'], remove=['xxx', 'xxx'],
                                           set_header=[KV("key1", "value1"), KV("key2", "value2")]),
                transform=Transform(with_key_prefix='prefix', with_key_suffix='suffix',
                                    replace_key_prefix=ReplaceKeyPrefix(key_prefix='prefix1', replace_with='replace')),
                fetch_header_to_meta_data_rules=[FetchHeaderToMetaDataRule(source_header='a', meta_data_suffix='b')],
                fetch_source_on_redirect_with_query=True,
            )
        ))
        put_out = self.client.put_bucket_mirror_back(bucket=bucket_name, rules=rules)
        self.assertIsNotNone(put_out.request_id)
        get_out = self.client.get_bucket_mirror_back(bucket=bucket_name)
        self.assertIsNotNone(get_out.request_id)
        self.assertEqual(len(get_out.rules[0].redirect.private_source.source_endpoint.primary), 1)
        self.assertEqual(get_out.rules[0].redirect.private_source.source_endpoint.primary[0].bucket_name,bucket_name)
        self.assertEqual(get_out.rules[0].redirect.private_source.source_endpoint.primary[0].endpoint, 'https://example.com')
        self.assertEqual(get_out.rules[0].redirect.private_source.source_endpoint.primary[0].credential_provider.role,"ServiceRoleBackSourceAccessTOS")

        self.assertEqual(len(get_out.rules[0].redirect.private_source.source_endpoint.follower), 1)
        self.assertEqual(get_out.rules[0].redirect.private_source.source_endpoint.follower[0].bucket_name, bucket_name)
        self.assertEqual(get_out.rules[0].redirect.private_source.source_endpoint.follower[0].endpoint,
                         'https://example2.com')
        self.assertEqual(get_out.rules[0].redirect.private_source.source_endpoint.follower[0].credential_provider.role,
                         "ServiceRoleBackSourceAccessTOS")


    def test_bucket_mirror(self):
        bucket_name = self.bucket_name + 'mirror'
        self.client.create_bucket(bucket=bucket_name)
        self.bucket_delete.append(bucket_name)
        rules = []
        rules.append(Rule(
            id='1',
            condition=Condition(http_code=404,allow_host=["example.com"],http_method=["GET","HEAD"]),
            redirect=Redirect(
                redirect_type=RedirectType.Mirror,
                fetch_source_on_redirect=True,
                public_source=PublicSource(SourceEndpoint(primary=['http://test.com/obj/tostest/'])),
                pass_query=True,
                follow_redirect=True,
                mirror_header=MirrorHeader(pass_all=True, pass_headers=['aaa', 'bbb'], remove=['xxx', 'xxx'],set_header=[KV("key1", "value1"),KV("key2", "value2")]),
                transform=Transform(with_key_prefix='prefix', with_key_suffix='suffix',
                                    replace_key_prefix=ReplaceKeyPrefix(key_prefix='prefix1', replace_with='replace')),
                fetch_header_to_meta_data_rules=[FetchHeaderToMetaDataRule(source_header='a', meta_data_suffix='b')],
                fetch_source_on_redirect_with_query=True,
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
        self.assertEqual(2, len(get_out.rules[0].redirect.mirror_header.set_header))
        self.assertEqual("key1", get_out.rules[0].redirect.mirror_header.set_header[0].key)
        self.assertEqual("value1",get_out.rules[0].redirect.mirror_header.set_header[0].value)
        self.assertEqual("key2", get_out.rules[0].redirect.mirror_header.set_header[1].key)
        self.assertEqual("value2", get_out.rules[0].redirect.mirror_header.set_header[1].value)
        self.assertEqual('GET',get_out.rules[0].condition.http_method[0])
        self.assertEqual('HEAD', get_out.rules[0].condition.http_method[1])
        self.assertEqual(1, len(get_out.rules[0].condition.allow_host))
        self.assertEqual('example.com',get_out.rules[0].condition.allow_host[0])
        self.assertEqual(True, get_out.rules[0].redirect.fetch_source_on_redirect_with_query)
        self.assertEqual(get_out.rules[0].redirect.public_source.source_endpoint.primary,
                         ['http://test.com/obj/tostest/'])
        self.assertEqual(get_out.rules[0].redirect.public_source.fixed_endpoint, None)
        self.assertEqual(get_out.rules[0].redirect.transform.with_key_prefix, 'prefix')
        self.assertEqual(get_out.rules[0].redirect.transform.with_key_suffix, 'suffix')
        self.assertEqual(get_out.rules[0].redirect.transform.replace_key_prefix.key_prefix, 'prefix1')
        self.assertEqual(get_out.rules[0].redirect.transform.replace_key_prefix.replace_with, 'replace')
        self.assertEqual(get_out.rules[0].redirect.fetch_header_to_meta_data_rules[0].source_header, 'a')
        self.assertEqual(get_out.rules[0].redirect.fetch_header_to_meta_data_rules[0].meta_data_suffix, 'b')

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

        rules = []
        rules.append(Rule(
            id='1',
            condition=Condition(http_code=404, http_method=['GET', 'HEAD']),
            redirect=Redirect(
                redirect_type=RedirectType.Mirror,
                fetch_source_on_redirect=True,
                public_source=PublicSource(SourceEndpoint(primary=['http://test.com/obj/tostest/'])),
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
        self.assertEqual(get_out.rules[0].condition.http_method[0], 'GET')
        self.assertEqual(get_out.rules[0].condition.http_method[1], 'HEAD')
        self.assertEqual(get_out.rules[0].redirect.redirect_type, RedirectType.Mirror)
        self.assertEqual(get_out.rules[0].redirect.follow_redirect, True)
        self.assertEqual(get_out.rules[0].redirect.fetch_source_on_redirect, True)
        self.assertEqual(get_out.rules[0].redirect.mirror_header.pass_all, True)
        self.assertEqual(get_out.rules[0].redirect.mirror_header.pass_headers, ['aaa', 'bbb'])
        self.assertEqual(get_out.rules[0].redirect.mirror_header.remove, ['xxx', 'xxx'])
        self.assertEqual(get_out.rules[0].redirect.public_source.source_endpoint.primary,
                         ['http://test.com/obj/tostest/'])
        self.assertEqual(get_out.rules[0].redirect.public_source.fixed_endpoint, None)
        self.assertEqual(get_out.rules[0].redirect.transform.with_key_prefix, 'prefix')
        self.assertEqual(get_out.rules[0].redirect.transform.with_key_suffix, 'suffix')
        self.assertEqual(get_out.rules[0].redirect.transform.replace_key_prefix.key_prefix, 'prefix1')
        self.assertEqual(get_out.rules[0].redirect.transform.replace_key_prefix.replace_with, 'replace')
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
        self.bucket_delete.append(bucket_name)
        self.client.put_bucket_lifecycle(bucket=bucket_name, rules=rules, allow_same_action_overlap=True)
        out = self.client.get_bucket_lifecycle(bucket=bucket_name)
        self.assertEqual(len(out.rules[0].tags), 2)
        self.assertEqual(out.rules[0].tags[0].key, '1')
        self.assertEqual(out.rules[0].tags[0].value, '2')
        self.assertEqual(out.rules[0].tags[1].key, 'test')
        self.assertEqual(out.rules[0].tags[1].value, 'test')
        self.assertEqual(out.allow_same_action_overlap, True)
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
        self.assertEqual(out.allow_same_action_overlap, None)
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

    def test_lifecycle_filter(self):
        bucket_name = self.bucket_name + 'lifecycle'
        rules = []
        rules.append(BucketLifeCycleRule(
            id='1',
            prefix='test',
            status=StatusType.Status_Enable,
            # 指定 Bucket的过期属性
            expiration=BucketLifeCycleExpiration(
                date=datetime.datetime(2022, 9, 30)
            ),
            no_current_version_expiration=BucketLifeCycleNoCurrentVersionExpiration(
                non_current_date=datetime.datetime(2022, 11, 30)
            ),
            non_current_version_transitions=[BucketLifeCycleNonCurrentVersionTransition(
                storage_class=StorageClassType.Storage_Class_Ia,
                non_current_date=datetime.datetime(2022, 10, 30)
            )],
            filter=BucketLifecycleFilter(
                object_size_greater_than=1,
                object_size_less_than=1000,
                greater_than_include_equal=StatusType.Status_Enable,
                less_than_include_equal=StatusType.Status_Disable,
            )
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
        self.assertEqual(rule1.expiration.date, datetime.datetime(2022, 9, 30, tzinfo=UTC))
        self.assertEqual(rule1.no_current_version_expiration.non_current_date,
                         datetime.datetime(2022, 11, 30, tzinfo=UTC))
        self.assertEqual(rule1.non_current_version_transitions[0].non_current_date,
                         datetime.datetime(2022, 10, 30, tzinfo=UTC))
        self.assertEqual(rule1.non_current_version_transitions[0].non_current_date,
                         datetime.datetime(2022, 10, 30, tzinfo=UTC))
        self.assertEqual(rule1.non_current_version_transitions[0].storage_class, StorageClassType.Storage_Class_Ia)
        self.assertEqual(rule1.filter.object_size_greater_than, 1)
        self.assertEqual(rule1.filter.object_size_less_than, 1000)
        self.assertEqual(rule1.filter.greater_than_include_equal, StatusType.Status_Enable)
        self.assertEqual(rule1.filter.less_than_include_equal, StatusType.Status_Disable)

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

        try:
            self.client.put_bucket_acl(bucket_name+':8080', acl=ACLType.ACL_Public_Read)
        except TosClientError as e:
            self.assertIsNotNone(e)


        self.client.delete_bucket(bucket=bucket_name)

    def test_put_bucket_replication(self):
        bucket_name_src = self.bucket_name + 'replication'
        bucket_name_crr = self.bucket_name + '-crr'
        bucket_name_crr_2 = self.bucket_name + '-crr2'
        bucket_name_crr_3 = self.bucket_name + '-crr3'
        self.client.create_bucket(bucket_name_src)
        self.client2.create_bucket(bucket_name_crr)
        self.client2.create_bucket(bucket_name_crr_2)
        self.client2.create_bucket(bucket_name_crr_3)
        self.bucket_delete.append(bucket_name_src)
        self.bucket_delete.append(bucket_name_crr)
        self.bucket_delete.append(bucket_name_crr_2)
        self.bucket_delete.append(bucket_name_crr_3)
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

        rules.append(ReplicationRule(id='3',
                                     status=StatusType.Status_Enable,
                                     prefix_set=['prefix5'],
                                     destination=Destination(bucket=bucket_name_crr_3, location=self.region2,
                                                             storage_class=StorageClassType.Storage_Class_Ia,
                                                             storage_class_inherit_directive=StorageClassInheritDirectiveType.Storage_Class_ID_Source_Object),
                                     historical_object_replication=StatusType.Status_Disable,tags=[Tag("key1","value1"),Tag("key2","value2")],
                                     access_control_translation=AccessControlTranslation("BucketOwnerEntrusted")))

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

        out = self.client.get_bucket_replication(bucket_name_src, '3')
        self.assertEqual(out.rules[0].id, '3')
        self.assertEqual(out.rules[0].prefix_set, ['prefix5'])
        self.assertEqual(out.rules[0].destination.bucket, bucket_name_crr_3)
        self.assertEqual(out.rules[0].destination.location, self.region2)
        self.assertEqual(out.rules[0].destination.storage_class, StorageClassType.Storage_Class_Ia)
        self.assertEqual(out.rules[0].destination.storage_class_inherit_directive,
                         StorageClassInheritDirectiveType.Storage_Class_ID_Source_Object)
        self.assertEqual(out.rules[0].historical_object_replication, StatusType.Status_Disable)
        self.assertIsNotNone(out.rules[0].progress)
        self.assertEqual(out.rules[0].progress.historical_object, 0.0)
        self.assertEqual(out.rules[0].access_control_translation.owner['Owner'], 'BucketOwnerEntrusted')
        self.assertEqual(len(out.rules[0].tags), 2)
        self.assertEqual(out.rules[0].tags[0].key, 'key1')
        self.assertEqual(out.rules[0].tags[1].key, 'key2')

        out = self.client.get_bucket_replication(bucket_name_src)
        self.assertEqual(len(out.rules), 3)

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

    def test_bucket_tagging(self):
        bucket_name = self.bucket_name  # + '-bucket-tagging'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        tag_set = [Tag(
            key='1',
            value='2'
        ), Tag(
            key='3',
            value='4'
        )]
        self.client.put_bucket_tagging(bucket_name, tag_set)
        out = self.client.get_bucket_tagging(bucket_name)
        self.assertIsNotNone(out.request_id)
        self.assertEqual(len(out.tag_set), 2)
        self.assertEqual(out.tag_set[0].key, tag_set[0].key)
        self.assertEqual(out.tag_set[0].value, tag_set[0].value)
        self.assertEqual(out.tag_set[1].key, tag_set[1].key)
        self.assertEqual(out.tag_set[1].value, tag_set[1].value)
        delete_out = self.client.delete_bucket_tagging(bucket_name)
        self.assertIsNotNone(delete_out.request_id)
        with self.assertRaises(TosServerError):
            self.client.get_bucket_tagging(bucket_name)

    def test_bucket_project_name(self):
        bucket_name = self.bucket_name + "project-name"
        self.bucket_delete.append(bucket_name)

        project_name = 'default'
        self.client.create_bucket(bucket=bucket_name, project_name=project_name)
        head_out = self.client.head_bucket(bucket_name)
        self.assertEqual(head_out.project_name, project_name)
        list_out = self.client.list_buckets(project_name=project_name)
        self.assertTrue(len(list_out.buckets) > 1)
        self.assertTrue(bucket_name in (b.name for b in list_out.buckets))
        for bucket in list_out.buckets:
            self.assertEqual(bucket.project_name, project_name)

    def test_bucket_encryption(self):
        bucket_name = self.bucket_name + "-encryption"
        endpoint = "https://{}".format(_get_clean_endpoint(self.endpoint))
        https_client = TosClientV2(self.ak, self.sk, endpoint, self.region, enable_crc=True, max_retry_count=2)
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        https_client.put_bucket_encryption(bucket_name, BucketEncryptionRule(
            apply_server_side_encryption_by_default=ApplyServerSideEncryptionByDefault(
                sse_algorithm="kms",
                kms_master_key_id="123"
            )
        ))
        get_out = self.client.get_bucket_encryption(bucket_name)
        self.assertEqual(get_out.rule.apply_server_side_encryption_by_default.sse_algorithm, "kms")
        self.assertEqual(get_out.rule.apply_server_side_encryption_by_default.kms_master_key_id, "123")
        self.client.delete_bucket_encryption(bucket_name)
        with self.assertRaises(TosServerError):
            self.client.get_bucket_encryption(bucket_name)
    # UT所用实例不可用
    # def test_bucket_notification_type2(self):
    #     bucket_name = self.bucket_name + "-notification-type2"
    #     self.client.create_bucket(bucket_name)
    #     self.bucket_delete.append(bucket_name)
    #
    #     rules = [
    #         NotificationRule(
    #             rule_id="test1",
    #             events=["tos:ObjectCreated:Post", "tos:ObjectCreated:Origin"],
    #             filter=NotificationFilter(
    #                 tos_key=NotificationFilterKey(
    #                     filter_rules=[
    #                         NotificationFilterRule(name="prefix", value="test-")
    #                     ]
    #                 )
    #             ),
    #             destination=NotificationDestination(
    #                 ve_faas=[DestinationVeFaaS(function_id=self.cloud_function)],
    #                 rocket_mq=[
    #                     DestinationRocketMQ(
    #                         role="trn:iam::{}:role/{}".format(self.account_id, self.mq_role_name),
    #                         instance_id=self.mq_instance_id,
    #                         topic="SDK",
    #                         access_key_id=self.mq_access_key_id
    #                     )
    #                 ]
    #             )
    #         )
    #     ]
    #     self.client.put_bucket_notification_type2(bucket_name, rules)
    #     out = self.client.get_bucket_notification_type2(bucket_name)
    #
    #     self.assertTrue(out.version != '')
    #     self.assertEqual(len(out.rules), 1)
    #     self.assertEqual(out.rules[0].rule_id, rules[0].rule_id)
    #     self.assertEqual(out.rules[0].events, rules[0].events)
    #     self.assertEqual(out.rules[0].filter.tos_key.filter_rules[0].name, rules[0].filter.tos_key.filter_rules[0].name)
    #     self.assertEqual(out.rules[0].filter.tos_key.filter_rules[0].value,
    #                      rules[0].filter.tos_key.filter_rules[0].value)
    #     self.assertEqual(out.rules[0].destination.ve_faas[0].function_id, rules[0].destination.ve_faas[0].function_id)
    #     self.assertEqual(out.rules[0].destination.rocket_mq[0].role, rules[0].destination.rocket_mq[0].role)
    #     self.assertEqual(out.rules[0].destination.rocket_mq[0].topic, rules[0].destination.rocket_mq[0].topic)
    #     self.assertEqual(out.rules[0].destination.rocket_mq[0].access_key_id,
    #                      rules[0].destination.rocket_mq[0].access_key_id)
    #     self.assertEqual(out.rules[0].destination.rocket_mq[0].instance_id,
    #                      rules[0].destination.rocket_mq[0].instance_id)

    def test_bucket_inventory(self):
        bucket_name = self.bucket_name + '-inventory'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        inventory_id = "py-sdk-test"
        bucket_inventory_configuration = BucketInventoryConfiguration(
            inventory_id=inventory_id,
            is_enabled=True,
            destination=InventoryDestination(tos_bucket_destination=TOSBucketDestination(
                format=InventoryFormatType.InventoryFormatCsv,
                account_id=self.account_id,
                role="TosArchiveTOSInventory",
                bucket=bucket_name)),
            inventory_filter=InventoryFilter(prefix="prefix1"),
            schedule=InventorySchedule(frequency=InventoryFrequencyType.InventoryFrequencyTypeDaily),
            included_object_versions=InventoryIncludedObjType.InventoryIncludedObjTypeCurrent,

        )
        resp = self.client.put_bucket_inventory(bucket_name,bucket_inventory_configuration)
        self.assertEqual(resp.status_code,200)

        inventory_id2 = "py-sdk-test2"
        bucket_inventory_configuration = BucketInventoryConfiguration(
            inventory_id=inventory_id2,
            is_enabled=False,
            destination=InventoryDestination(tos_bucket_destination=TOSBucketDestination(
                format=InventoryFormatType.InventoryFormatCsv,
                account_id=self.account_id,
                role="TosArchiveTOSInventory",
                bucket=bucket_name)),
            schedule=InventorySchedule(frequency=InventoryFrequencyType.InventoryFrequencyTypeWeekly),
            included_object_versions=InventoryIncludedObjType.InventoryIncludedObjTypeAll,
            inventory_filter=InventoryFilter(prefix="prefix2"),
            optional_fields=InventoryOptionalFields(["Size","CRC64"])
        )
        resp = self.client.put_bucket_inventory(bucket_name, bucket_inventory_configuration)
        self.assertEqual(resp.status_code, 200)


        resp = self.client.get_bucket_inventory(bucket_name,inventory_id=inventory_id)
        self.assertEqual(resp.bucket_inventory_configuration.inventory_id, inventory_id)
        self.assertEqual(resp.bucket_inventory_configuration.is_enabled, True)

        resp = self.client.get_bucket_inventory(bucket_name, inventory_id=inventory_id2)
        self.assertEqual(resp.bucket_inventory_configuration.inventory_id, inventory_id2)
        self.assertEqual(resp.bucket_inventory_configuration.is_enabled, False)
        self.assertEqual(resp.bucket_inventory_configuration.destination.tos_bucket_destination.format, InventoryFormatType.InventoryFormatCsv)
        self.assertEqual(resp.bucket_inventory_configuration.destination.tos_bucket_destination.account_id, self.account_id)
        self.assertEqual(resp.bucket_inventory_configuration.destination.tos_bucket_destination.role, "TosArchiveTOSInventory")
        self.assertEqual(resp.bucket_inventory_configuration.destination.tos_bucket_destination.bucket, bucket_name)
        self.assertEqual(resp.bucket_inventory_configuration.schedule.frequency, InventoryFrequencyType.InventoryFrequencyTypeWeekly)
        self.assertEqual(resp.bucket_inventory_configuration.included_object_versions, InventoryIncludedObjType.InventoryIncludedObjTypeAll)
        self.assertEqual(resp.bucket_inventory_configuration.inventory_filter.prefix, "prefix2")
        self.assertEqual(resp.bucket_inventory_configuration.optional_fields.fields, ["Size","CRC64"])

        resp = self.client.list_bucket_inventory(bucket_name)
        self.assertEqual(len(resp.configurations), 2)
        bucket_inventory_configuration = resp.configurations[1]
        self.assertEqual(bucket_inventory_configuration.inventory_id, inventory_id2)
        self.assertEqual(bucket_inventory_configuration.is_enabled, False)
        self.assertEqual(bucket_inventory_configuration.destination.tos_bucket_destination.format,
                         InventoryFormatType.InventoryFormatCsv)
        self.assertEqual(bucket_inventory_configuration.destination.tos_bucket_destination.account_id,
                         self.account_id)
        self.assertEqual(bucket_inventory_configuration.destination.tos_bucket_destination.role,
                         "TosArchiveTOSInventory")
        self.assertEqual(bucket_inventory_configuration.destination.tos_bucket_destination.bucket, bucket_name)
        self.assertEqual(bucket_inventory_configuration.schedule.frequency,
                         InventoryFrequencyType.InventoryFrequencyTypeWeekly)
        self.assertEqual(bucket_inventory_configuration.included_object_versions,
                         InventoryIncludedObjType.InventoryIncludedObjTypeAll)
        self.assertEqual(bucket_inventory_configuration.inventory_filter.prefix, "prefix2")
        self.assertEqual(bucket_inventory_configuration.optional_fields.fields, ["Size", "CRC64"])

        self.client.delete_bucket_inventory(bucket_name,inventory_id=inventory_id)
        self.client.delete_bucket_inventory(bucket_name, inventory_id=inventory_id2)

        try:
            self.client.get_bucket_inventory(bucket_name, inventory_id=inventory_id)
        except TosServerError as e:
            self.assertEqual(e.status_code,404)

        try:
            self.client.get_bucket_inventory(bucket_name, inventory_id=inventory_id2)
        except TosServerError as e:
            self.assertEqual(e.status_code, 404)

    def test_list_bucket_inventory(self):
        bucket_name = self.bucket_name + '-inventory'
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)
        for i in range(102):
            inventory_id = "py-sdk-test"+str(i)
            bucket_inventory_configuration = BucketInventoryConfiguration(
                inventory_id=inventory_id,
                is_enabled=True,
                destination=InventoryDestination(tos_bucket_destination=TOSBucketDestination(
                    format=InventoryFormatType.InventoryFormatCsv,
                    account_id=self.account_id,
                    role="TosArchiveTOSInventory",
                    bucket=bucket_name)),
                inventory_filter=InventoryFilter(prefix="prefix"+''.join(random.choice(string.ascii_lowercase) for i in range(5))),
                schedule=InventorySchedule(frequency=InventoryFrequencyType.InventoryFrequencyTypeDaily),
                included_object_versions=InventoryIncludedObjType.InventoryIncludedObjTypeCurrent,

            )
            resp = self.client.put_bucket_inventory(bucket_name, bucket_inventory_configuration)
            self.assertEqual(resp.status_code, 200)

        resp = self.client.list_bucket_inventory(bucket_name)
        self.assertEqual(len(resp.configurations), 100)

        resp = self.client.list_bucket_inventory(bucket_name,continuation_token=resp.next_continuation_token)
        self.assertEqual(len(resp.configurations), 1)



    def test_bucket_notification_type2(self):
        bucket_name = self.bucket_name + "-notification-type2"
        self.client.create_bucket(bucket_name)
        self.bucket_delete.append(bucket_name)

        rules = [
            NotificationRule(
                rule_id="test1",
                events=["tos:ObjectCreated:Post", "tos:ObjectCreated:Origin"],
                filter=NotificationFilter(
                    tos_key=NotificationFilterKey(
                        filter_rules=[
                            NotificationFilterRule(name="prefix", value="test-")
                        ]
                    )
                ),
                destination=NotificationDestination(
                    ve_faas=[DestinationVeFaaS(function_id=self.cloud_function)],
                    rocket_mq=[
                        DestinationRocketMQ(
                            role="trn:iam::{}:role/{}".format(self.account_id, self.mq_role_name),
                            instance_id=self.mq_instance_id,
                            topic="SDK",
                            access_key_id=self.mq_access_key_id
                        )
                    ]
                )
            )
        ]
        self.client.put_bucket_notification_type2(bucket_name, rules)
        out = self.client.get_bucket_notification_type2(bucket_name)

        self.assertTrue(out.version != '')
        self.assertEqual(len(out.rules), 1)
        self.assertEqual(out.rules[0].rule_id, rules[0].rule_id)
        self.assertEqual(out.rules[0].events, rules[0].events)
        self.assertEqual(out.rules[0].filter.tos_key.filter_rules[0].name, rules[0].filter.tos_key.filter_rules[0].name)
        self.assertEqual(out.rules[0].filter.tos_key.filter_rules[0].value,
                         rules[0].filter.tos_key.filter_rules[0].value)
        self.assertEqual(out.rules[0].destination.ve_faas[0].function_id, rules[0].destination.ve_faas[0].function_id)
        self.assertEqual(out.rules[0].destination.rocket_mq[0].role, rules[0].destination.rocket_mq[0].role)
        self.assertEqual(out.rules[0].destination.rocket_mq[0].topic, rules[0].destination.rocket_mq[0].topic)
        self.assertEqual(out.rules[0].destination.rocket_mq[0].access_key_id,
                         rules[0].destination.rocket_mq[0].access_key_id)
        self.assertEqual(out.rules[0].destination.rocket_mq[0].instance_id,
                         rules[0].destination.rocket_mq[0].instance_id)

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


def _get_clean_endpoint(endpoint):
    if endpoint.startswith('http://'):
        return endpoint[7:]
    elif endpoint.startswith('https://'):
        return endpoint[8:]
    return endpoint


if __name__ == "__main__":
    unittest.main()
