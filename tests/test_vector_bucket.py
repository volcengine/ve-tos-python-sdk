import time
import json
import unittest
from tests.vector_client import TosVectorClientBase
from tos.exceptions import TosClientError, TosServerError
from tos.enum import  DataType, DistanceMetricType
from tos.models2 import Vector, VectorData

class TestVectorBucket(TosVectorClientBase):
    def test_create_bucket(self):
        bucket_name = self.get_bucket_name()
        self.bucket_delete.append(bucket_name)
        res = self.vector_client.create_vector_bucket(bucket_name)
        self.assertEqual(res.status_code, 200)
        res2 = self.vector_client.get_vector_bucket(bucket_name, self.account_id)
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.vector_bucket.vector_bucket_name, bucket_name)
    
    def test_validate_account_id(self):
        with self.assertRaises(TosClientError):
            self.vector_client.get_vector_bucket(self.bucket_name, account_id='')
        
        with self.assertRaises(TosClientError):
            self.vector_client.delete_vector_bucket(self.bucket_name, account_id='abc')

        with self.assertRaises(TosClientError):
            self.vector_client.delete_vector_bucket(self.bucket_name, account_id='12a')

    def test_get_vector_bucket_success(self):
        """测试成功获取向量存储桶信息"""
        bucket_name = self.get_bucket_name()
        
        # 创建测试用的向量存储桶
        create_res = self.vector_client.create_vector_bucket(bucket_name)
        print(create_res.status_code)
        self.assertEqual(create_res.status_code, 200)
        
        # 获取向量存储桶信息
        result = self.vector_client.get_vector_bucket(bucket_name, self.account_id)
        
        # 验证返回结果
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result.vector_bucket)
        self.assertEqual(result.vector_bucket.vector_bucket_name, bucket_name)
        self.assertIsNotNone(result.vector_bucket.creation_time)
        self.assertIsNotNone(result.vector_bucket.vector_bucket_trn)
        print(result.vector_bucket.vector_bucket_trn)
        
        # 删除向量存储桶
        delete_res = self.vector_client.delete_vector_bucket(bucket_name, self.account_id)
        self.assertEqual(delete_res.status_code, 200)
        
        # 验证删除后获取会抛出异常
        with self.assertRaises(TosServerError) as context:
            self.vector_client.get_vector_bucket(bucket_name, self.account_id)
        
        self.assertEqual(context.exception.status_code, 404)
        self.assertEqual(context.exception.code, 'VectorBucketNotFound')
    def test_create_index_basic(self):
        test_vector_bucket_name = self.get_bucket_name()
        self.vector_client.create_vector_bucket(test_vector_bucket_name)
        self.bucket_delete.append(test_vector_bucket_name)
        """测试使用基础参数成功创建向量索引"""
        test_index_name = 'test-index-basic-' + str(int(time.time() * 1000))
        
        # 创建向量索引
        result = self.vector_client.create_index(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            index_name=test_index_name,
            data_type=DataType.DataTypeFloat32,
            dimension=128,
            distance_metric=DistanceMetricType.DistanceMetricEuclidean
        )
        
        # 验证返回结果
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result.request_id)
        self.assertIsNotNone(result.header)
        
        # 获取索引验证
        get_index_result = self.vector_client.get_index(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            index_name=test_index_name
        )
        self.assertEqual(get_index_result.status_code, 200)
        self.assertEqual(get_index_result.index.index_name, test_index_name)
        self.assertEqual(get_index_result.index.data_type, DataType.DataTypeFloat32)
        self.assertEqual(get_index_result.index.dimension, 128)
        self.assertEqual(get_index_result.index.distance_metric, DistanceMetricType.DistanceMetricEuclidean)
        
        # 删除索引
        delete_result = self.vector_client.delete_index(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            index_name=test_index_name
        )
        self.assertEqual(delete_result.status_code, 200)
        
        # 验证删除后获取会抛出异常
        with self.assertRaises(TosServerError) as context:
            self.vector_client.get_index(
                vector_bucket_name=test_vector_bucket_name,
                account_id=self.account_id,
                index_name=test_index_name
            )
        
        self.assertEqual(context.exception.status_code, 404)
        self.assertEqual(context.exception.code, 'VectorIndexNotFound')
    
    def test_create_index_with_metadata(self):
        """测试使用元数据配置成功创建向量索引"""
        test_index_name = 'test-index-metadata-' + str(int(time.time() * 1000))
        test_vector_bucket_name = self.get_bucket_name()
        self.vector_client.create_vector_bucket(test_vector_bucket_name)
        self.bucket_delete.append(test_vector_bucket_name)
        
        # 创建带元数据配置的向量索引
        result = self.vector_client.create_index(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            index_name=test_index_name,
            data_type=DataType.DataTypeFloat32,
            dimension=256,
            distance_metric=DistanceMetricType.DistanceMetricCosine,
            metadata_configuration={
                'nonFilterableMetadataKeys': ['timestamp', 'source', 'category']
            }
        )
        
        # 验证返回结果
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)
        
        # 获取索引验证
        get_index_result = self.vector_client.get_index(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            index_name=test_index_name
        )
        self.assertEqual(get_index_result.status_code, 200)
        self.assertEqual(get_index_result.index.index_name, test_index_name)
        self.assertEqual(get_index_result.index.data_type, DataType.DataTypeFloat32)
        self.assertEqual(get_index_result.index.dimension, 256)
        self.assertIsNotNone(get_index_result.index.metadata_configuration)
        self.assertEqual(
            get_index_result.index.metadata_configuration.non_filterable_metadata_keys,
            ['timestamp', 'source', 'category']
        )

    def test_list_vector_buckets_basic(self):
        """P0: 基本功能测试 - 列举向量存储桶"""
        vector_bucket_name = f"test-list-bucket-{int(time.time() * 1000)}"
        
        # 先创建一个测试存储桶
        create_result = self.vector_client.create_vector_bucket(vector_bucket_name)
        self.assertEqual(create_result.status_code, 200)
        self.bucket_delete.append(vector_bucket_name)

        # 测试列举功能
        result = self.vector_client.list_vector_buckets()
        
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result.vector_buckets)
        self.assertIsInstance(result.vector_buckets, list)
        
        # 验证返回的存储桶列表中包含刚创建的存储桶
        found_bucket = None
        for bucket in result.vector_buckets:
            if bucket.vector_bucket_name == vector_bucket_name:
                found_bucket = bucket
                break
        
        self.assertIsNotNone(found_bucket)
        self.assertEqual(found_bucket.vector_bucket_name, vector_bucket_name)
        self.assertIsNotNone(found_bucket.vector_bucket_trn)
        self.assertIsNotNone(found_bucket.creation_time)

    def test_list_vector_buckets_pagination(self):
        """P0: 分页功能测试"""
        import time
        # 创建多个测试存储桶
        bucket_names = []
        for i in range(3):
            bucket_name = f"page-bucket-{int(time.time() * 1000)}-{i}"
            bucket_names.append(bucket_name)
            
            create_result = self.vector_client.create_vector_bucket(bucket_name)
            self.assertEqual(create_result.status_code, 200)
            self.bucket_delete.append(bucket_name)

        # 第一页，限制返回数量
        page1 = self.vector_client.list_vector_buckets(max_results=2)
        
        self.assertEqual(page1.status_code, 200)
        self.assertIsNotNone(page1.vector_buckets)
        self.assertLessEqual(len(page1.vector_buckets), 2)

        # 如果有下一页，测试nextToken
        if page1.next_token:
            page2 = self.vector_client.list_vector_buckets(max_results=2, next_token=page1.next_token)
            
            self.assertEqual(page2.status_code, 200)
            self.assertIsNotNone(page2.vector_buckets)

    def test_list_vector_buckets_prefix_filter(self):
        """P0: 前缀过滤功能测试"""
        import time
        prefix = f"test-prefix-{int(time.time() * 1000)}"
        bucket_name1 = f"{prefix}-1"
        bucket_name2 = f"{prefix}-2"
        other_bucket_name = f"other-{int(time.time() * 1000)}"

        # 创建测试存储桶
        self.vector_client.create_vector_bucket(bucket_name1)
        self.vector_client.create_vector_bucket(bucket_name2)
        self.vector_client.create_vector_bucket(other_bucket_name)
        self.bucket_delete.extend([bucket_name1, bucket_name2, other_bucket_name])

        # 使用前缀过滤
        result = self.vector_client.list_vector_buckets(prefix=prefix)

        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result.vector_buckets)
        
        # 验证只返回了匹配前缀的存储桶
        filtered_buckets = result.vector_buckets or []
        self.assertGreaterEqual(len(filtered_buckets), 2)
        
        for bucket in filtered_buckets:
            self.assertTrue(bucket.vector_bucket_name.startswith(prefix))

        # 验证包含预期的存储桶
        found_bucket1 = None
        found_bucket2 = None
        for bucket in filtered_buckets:
            if bucket.vector_bucket_name == bucket_name1:
                found_bucket1 = bucket
            elif bucket.vector_bucket_name == bucket_name2:
                found_bucket2 = bucket
        
        self.assertIsNotNone(found_bucket1)
        self.assertIsNotNone(found_bucket2)

    def test_list_vector_buckets_empty_result(self):
        """P2: 空结果测试"""
        import time
        result = self.vector_client.list_vector_buckets(prefix=f"non-existing-prefix-{int(time.time() * 1000)}")

        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(result.vector_buckets or []), 0)
        self.assertIsNone(result.next_token)

    def test_list_indexes_basic(self):
        """P0: 基本功能测试 - 列举向量索引"""
        import time
        test_vector_bucket_name = self.get_bucket_name()
        
        # 创建测试用的向量存储桶
        create_res = self.vector_client.create_vector_bucket(test_vector_bucket_name)
        self.assertEqual(create_res.status_code, 200)
        self.bucket_delete.append(test_vector_bucket_name)

        # 创建几个测试索引用于列表测试
        index_names = [
            'test-index-1',
            'test-index-2',
            'prefix-index-1',
            'prefix-index-2',
        ]
        for index_name in index_names:
            create_result = self.vector_client.create_index(
                vector_bucket_name=test_vector_bucket_name,
                account_id=self.account_id,
                index_name=index_name,
                data_type=DataType.DataTypeFloat32,
                dimension=128,
                distance_metric=DistanceMetricType.DistanceMetricEuclidean
            )
            self.assertEqual(create_result.status_code, 200)

        # 测试列举功能
        result = self.vector_client.list_indexes(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result.indexes)
        self.assertIsInstance(result.indexes, list)
        self.assertIsNotNone(result.request_id)
        self.assertIsNotNone(result.header)

        # 验证返回的索引数据结构
        if len(result.indexes) > 0:
            index = result.indexes[0]
            self.assertIsNotNone(index.creation_time)
            self.assertIsNotNone(index.index_name)
            self.assertIsNotNone(index.index_trn)
            self.assertIsNotNone(index.vector_bucket_name)
            self.assertIsInstance(index.creation_time, int)
            self.assertIsInstance(index.index_name, str)
            self.assertIsInstance(index.index_trn, str)
            self.assertIsInstance(index.vector_bucket_name, str)

    def test_list_indexes_max_results(self):
        """P0: maxResults参数限制测试"""
        import time
        test_vector_bucket_name = self.get_bucket_name()
        
        # 创建测试用的向量存储桶
        create_res = self.vector_client.create_vector_bucket(test_vector_bucket_name)
        self.assertEqual(create_res.status_code, 200)
        self.bucket_delete.append(test_vector_bucket_name)

        # 创建几个测试索引用于列表测试
        index_names = [
            'test-index-1',
            'test-index-2',
            'prefix-index-1',
            'prefix-index-2',
        ]
        for index_name in index_names:
            create_result = self.vector_client.create_index(
                vector_bucket_name=test_vector_bucket_name,
                account_id=self.account_id,
                index_name=index_name,
                data_type=DataType.DataTypeFloat32,
                dimension=128,
                distance_metric=DistanceMetricType.DistanceMetricEuclidean
            )
            self.assertEqual(create_result.status_code, 200)

        # 测试maxResults参数
        result = self.vector_client.list_indexes(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            max_results=2
        )

        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result.indexes)
        self.assertLessEqual(len(result.indexes), 2)

    def test_list_indexes_prefix_filter(self):
        """P0: prefix参数过滤测试"""
        import time
        test_vector_bucket_name = self.get_bucket_name()
        
        # 创建测试用的向量存储桶
        create_res = self.vector_client.create_vector_bucket(test_vector_bucket_name)
        self.assertEqual(create_res.status_code, 200)
        self.bucket_delete.append(test_vector_bucket_name)

        # 创建几个测试索引用于列表测试
        index_names = [
            'test-index-1',
            'test-index-2',
            'prefix-index-1',
            'prefix-index-2',
        ]
        for index_name in index_names:
            create_result = self.vector_client.create_index(
                vector_bucket_name=test_vector_bucket_name,
                account_id=self.account_id,
                index_name=index_name,
                data_type=DataType.DataTypeFloat32,
                dimension=128,
                distance_metric=DistanceMetricType.DistanceMetricEuclidean
            )
            self.assertEqual(create_result.status_code, 200)

        # 测试prefix参数过滤
        result = self.vector_client.list_indexes(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            prefix='prefix-'
        )

        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result.indexes)

        # 验证所有返回的索引名称都以指定前缀开头
        for index in result.indexes:
            self.assertTrue(index.index_name.startswith('prefix-'))

    def test_list_indexes_pagination(self):
        """P0: 分页功能测试"""
        import time
        test_vector_bucket_name = self.get_bucket_name()
        
        # 创建测试用的向量存储桶
        create_res = self.vector_client.create_vector_bucket(test_vector_bucket_name)
        self.assertEqual(create_res.status_code, 200)
        self.bucket_delete.append(test_vector_bucket_name)

        # 创建几个测试索引用于列表测试
        index_names = [
            'test-index-1',
            'test-index-2',
            'prefix-index-1',
            'prefix-index-2',
        ]
        for index_name in index_names:
            create_result = self.vector_client.create_index(
                vector_bucket_name=test_vector_bucket_name,
                account_id=self.account_id,
                index_name=index_name,
                data_type=DataType.DataTypeFloat32,
                dimension=128,
                distance_metric=DistanceMetricType.DistanceMetricEuclidean
            )
            self.assertEqual(create_result.status_code, 200)

        # 先列举一次获取nextToken
        first_page = self.vector_client.list_indexes(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            max_results=2
        )

        self.assertEqual(first_page.status_code, 200)
        self.assertIsNotNone(first_page.indexes)
        self.assertEqual(len(first_page.indexes), 2)

        # 如果有nextToken，继续列举下一页
        if first_page.next_token:
            second_page = self.vector_client.list_indexes(
                vector_bucket_name=test_vector_bucket_name,
                account_id=self.account_id,
                max_results=2,
                next_token=first_page.next_token
            )

            self.assertEqual(second_page.status_code, 200)
            self.assertIsNotNone(second_page.indexes)
            self.assertLessEqual(len(second_page.indexes), 2)
            
            # 验证第一页和第二页数据不重复
            first_page_names = [index.index_name for index in first_page.indexes]
            second_page_names = [index.index_name for index in second_page.indexes]
            overlap = [name for name in first_page_names if name in second_page_names]
            self.assertEqual(len(overlap), 0)

    def test_put_vector_bucket_policy_basic(self):
        """P0: 基本功能测试 - 设置向量存储桶策略"""
        print("test_put_vector_bucket_policy_basic")
        test_vector_bucket_name = self.get_bucket_name()
        
        # 创建测试向量存储桶
        create_res = self.vector_client.create_vector_bucket(test_vector_bucket_name)
        self.assertEqual(create_res.status_code, 200)
        self.bucket_delete.append(test_vector_bucket_name)

        simple_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": [self.account_id],
                    "Action": "tosvectors:GetVectorBucket",
                    "Resource": f"trn:tosvectors:cn-guilin-boe:{self.account_id}:bucket/{test_vector_bucket_name}"
                }
            ]
        })

        # 设置策略
        result = self.vector_client.put_vector_bucket_policy(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            policy=simple_policy
        )

        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result)

        # 验证策略已设置
        get_result = self.vector_client.get_vector_bucket_policy(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id
        )

        self.assertEqual(get_result.status_code, 200)
        self.assertIsNotNone(get_result.policy)
        policy_dict = json.loads(get_result.policy)

        self.assertIsNotNone(policy_dict['Statement'])
        self.assertEqual(len(policy_dict['Statement']), 1)
        
        statement = policy_dict['Statement'][0]
        self.assertEqual(statement['Effect'], "Allow")
        self.assertIn(self.account_id, statement['Principal'])
        self.assertEqual(
            statement['Resource'],
            f"trn:tosvectors:cn-guilin-boe:{self.account_id}:bucket/{test_vector_bucket_name}"
        )

        # 删除策略
        delete_result = self.vector_client.delete_vector_bucket_policy(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id
        )
        self.assertEqual(delete_result.status_code, 200)

        # 验证删除后获取会抛出异常
        with self.assertRaises(TosServerError) as context:
            self.vector_client.get_vector_bucket_policy(
                vector_bucket_name=test_vector_bucket_name,
                account_id=self.account_id
            )
        
        self.assertEqual(context.exception.status_code, 404)

    def test_put_vector_bucket_policy_invalid_json(self):
        """P0: 无效JSON策略格式测试"""
        import time
        test_vector_bucket_name = self.get_bucket_name()
        
        # 创建测试向量存储桶
        create_res = self.vector_client.create_vector_bucket(test_vector_bucket_name)
        self.assertEqual(create_res.status_code, 200)
        self.bucket_delete.append(test_vector_bucket_name)

        invalid_json_policy = 'invalid json string {'

        # 测试无效JSON策略应该抛出异常
        with self.assertRaises(TosServerError) as context:
            self.vector_client.put_vector_bucket_policy(
                vector_bucket_name=test_vector_bucket_name,
                account_id=self.account_id,
                policy=invalid_json_policy
            )
        
        self.assertEqual(context.exception.status_code, 400)

    def test_get_vectors_basic(self):
        """测试基本获取向量功能"""
        import time
        test_vector_bucket_name = self.get_bucket_name()
        test_index_name = 'test-index-' + str(int(time.time() * 1000))
        
        # 创建测试用的向量存储桶和索引
        self.vector_client.create_vector_bucket(test_vector_bucket_name)
        self.bucket_delete.append(test_vector_bucket_name)
        
        # 创建测试索引
        self.vector_client.create_index(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            index_name=test_index_name,
            data_type=DataType.DataTypeFloat32,
            dimension=128,
            distance_metric=DistanceMetricType.DistanceMetricEuclidean
        )
        
        # 准备测试向量数据
        vectors = [
            Vector(
                key='vector-meta-1-' + str(int(time.time() * 1000)),
                data=VectorData(float32=[float(x) for x in range(128)]),
                metadata={
                    'category': 'electronics',
                    'timestamp': str(int(time.time() * 1000)),
                    'source': 'user-upload'
                }
            ),
            Vector(
                key='vector-meta-2-' + str(int(time.time() * 1000)),
                data=VectorData(float32=[float(x + 0.5) for x in range(128)]),
                metadata={
                    'category': 'clothing',
                    'timestamp': str(int(time.time() * 1000)),
                    'source': 'batch-import'
                }
            )
        ]
        
        # 写入向量数据
        result = self.vector_client.put_vectors(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            index_name=test_index_name,
            vectors=vectors
        )
        
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result)
        print("向量写入成功")
        
        # 等待向量索引完成
        time.sleep(60)
        
        # 获取向量数据（不包含数据和元数据）
        get_result = self.vector_client.get_vectors(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            index_name=test_index_name,
            keys=[v.key for v in vectors]
        )
        
        self.assertEqual(get_result.status_code, 200)
        self.assertIsNotNone(get_result)
        self.assertIsNotNone(get_result.vectors)
        
        # 获取向量数据（包含数据和元数据）
        get_result_with_data_and_metadata = self.vector_client.get_vectors(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            index_name=test_index_name,
            keys=[v.key for v in vectors],
            return_data=True,
            return_metadata=True
        )
        
        self.assertEqual(get_result_with_data_and_metadata.status_code, 200)
        self.assertIsNotNone(get_result_with_data_and_metadata)
        self.assertIsNotNone(get_result_with_data_and_metadata.vectors)
        self.assertEqual(len(get_result_with_data_and_metadata.vectors), 2)
        self.assertEqual(get_result_with_data_and_metadata.vectors[0].key, vectors[0].key)
        self.assertEqual(len(get_result_with_data_and_metadata.vectors[0].data.float32), 128)
        self.assertEqual(get_result_with_data_and_metadata.vectors[0].metadata, vectors[0].metadata)
        
        # 删除向量数据
        delete_result = self.vector_client.delete_vectors(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            index_name=test_index_name,
            keys=[v.key for v in vectors]
        )
        
        self.assertEqual(delete_result.status_code, 200)
        self.assertIsNotNone(delete_result)
        
        # 等待删除操作完成
        time.sleep(60)
        
        # 验证向量已被删除
        res2 = self.vector_client.get_vectors(
            vector_bucket_name=test_vector_bucket_name,
            account_id=self.account_id,
            index_name=test_index_name,
            keys=[v.key for v in vectors]
        )
        self.assertEqual(res2.status_code, 200)
        self.assertIsNotNone(res2)
        self.assertEqual(len(res2.vectors), 0)
        
if __name__ == "__main__":
    unittest.main()
