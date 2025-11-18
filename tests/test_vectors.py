import os
import random
import time
import json
import unittest
from tests.common import random_string
from tests.vector_client import TosVectorClientBase
from tos.exceptions import TosClientError, TosServerError
from tos.enum import  DataType, DistanceMetricType
from tos.models2 import Vector, VectorData
from tos.vector_client import VectorClient

class TestVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ak = os.getenv('AK')
        cls.sk = os.getenv('SK')
        cls.vector_endpoint = os.getenv('VectorEndpoint')
        cls.region = os.getenv('Region')
        cls.account_id = os.getenv('AccountId')
        cls.bucket_name = "py-sdk-" + random_string(10)
        cls.vector_client = VectorClient(cls.ak, cls.sk, cls.vector_endpoint, cls.region)
        cls.vector_client.create_vector_bucket(cls.bucket_name)
        cls.test_index_name = 'test-query-vectors-index'
        cls.vector_client.create_index(
            vector_bucket_name=cls.bucket_name,
            account_id=cls.account_id,
            index_name=cls.test_index_name,
            dimension=128,
            data_type=DataType.DataTypeFloat32,
            distance_metric=DistanceMetricType.DistanceMetricCosine
        )
        print(f"测试用的向量存储桶名称: {cls.bucket_name}")
        print(f"测试用的索引名称: {cls.test_index_name}")
        time.sleep(5)
        test_vectors = []
        for i in range(10):
            vector = Vector(
                key=f'test-vector-{i}',
                data=VectorData(float32=[float(random.random()) for _ in range(128)]),
                metadata={
                    'category': 'A' if i % 2 == 0 else 'B',
                    'timestamp': str(int(time.time() * 1000) - i * 1000),
                    'index': i
                }
            )
            test_vectors.append(vector)
        
        # 上传测试向量
        cls.vector_client.put_vectors(
            vector_bucket_name=cls.bucket_name,
            account_id=cls.account_id,
            index_name=cls.test_index_name,
            vectors=test_vectors
        )
        
        # 等待向量上传完成
        time.sleep(60)
        
    @classmethod
    def tearDownClass(cls):
        response = cls.vector_client.list_indexes(cls.bucket_name, cls.account_id, 100)
        for index in response.indexes:
            cls.vector_client.delete_index(cls.bucket_name, cls.account_id, index.index_name)
        cls.vector_client.delete_vector_bucket(cls.bucket_name, cls.account_id)
    
    def test_query_vectors_basic(self):
        # 测试基本参数查询
        query_vector = VectorData(float32=[float(random.random()) for _ in range(128)])
        
        result = self.vector_client.query_vectors(
            vector_bucket_name=self.bucket_name,
            account_id=self.account_id,
            index_name=self.test_index_name,
            query_vector=query_vector,
            top_k=5,
            return_distance=True,
            return_metadata=True
        )
        
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.vectors)
        self.assertLessEqual(len(result.vectors), 5)
        
        # 验证返回的向量结构
        if len(result.vectors) > 0:
            vector = result.vectors[0]
            self.assertIsNotNone(vector.key)
            self.assertIsNotNone(vector.data)
            self.assertIsNotNone(vector.distance)
            self.assertIsNotNone(vector.metadata)
            self.assertIsInstance(vector.key, str)
            self.assertIsInstance(vector.distance, float)

    def test_query_vectors_with_filter(self):
        """测试带过滤条件的向量查询"""
        # 测试带过滤条件的查询
        query_vector = VectorData(float32=[float(random.random()) for _ in range(128)])
        
        result = self.vector_client.query_vectors(
            vector_bucket_name=self.bucket_name,
            account_id=self.account_id,
            index_name=self.test_index_name,
            query_vector=query_vector,
            top_k=10,
            return_distance=True,
            return_metadata=True,
            filter={'category': 'A'}
        )
        
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.vectors)
        
        # 验证过滤后的结果
        for vector in result.vectors:
            self.assertEqual(vector.metadata['category'], 'A')

    def test_query_vectors_without_distance(self):
        """测试不返回距离的向量查询"""
        query_vector = VectorData(float32=[float(random.random()) for _ in range(128)])
        
        result = self.vector_client.query_vectors(
            vector_bucket_name=self.bucket_name,
            account_id=self.account_id,
            index_name=self.test_index_name,
            query_vector=query_vector,
            top_k=3,
            return_distance=False,
            return_metadata=True,
            filter={}
        )
        
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.vectors)
        
        # 验证返回的向量结构
        vector = result.vectors[0]
        self.assertIsNotNone(vector.key)
        self.assertIsNotNone(vector.data)
        self.assertIsNotNone(vector.metadata)
        # distance字段应该为None
        self.assertIsNone(vector.distance)

    def test_query_vectors_without_metadata(self):
        """测试不返回元数据的向量查询"""
        # 测试不返回元数据的查询
        query_vector = VectorData(float32=[float(random.random()) for _ in range(128)])
        
        result = self.vector_client.query_vectors(
            vector_bucket_name=self.bucket_name,
            account_id=self.account_id,
            index_name=self.test_index_name,
            query_vector=query_vector,
            top_k=3,
            return_distance=True,
            return_metadata=False,
            filter={}
        )
        
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.vectors)
        
        # 验证返回的向量结构
        vector = result.vectors[0]
        self.assertIsNotNone(vector.key)
        self.assertIsNotNone(vector.data)
        self.assertIsNotNone(vector.distance)
        # metadata字段应该为None
        self.assertIsNone(vector.metadata)

    def test_query_vectors_different_topk(self):
        """测试不同topK值的向量查询"""    
        # 测试不同的topK值
        top_k_values = [1, 3, 5, 10]
        query_vector = VectorData(float32=[float(random.random()) for _ in range(128)])
        
        for top_k in top_k_values:
            result = self.vector_client.query_vectors(
                vector_bucket_name=self.bucket_name,
                account_id=self.account_id,
                index_name=self.test_index_name,
                query_vector=query_vector,
                top_k=top_k,
                return_distance=True,
                return_metadata=True,
                filter={}
            )
            
            self.assertEqual(result.status_code, 200)
            self.assertIsNotNone(result)
            self.assertIsNotNone(result.vectors)
            self.assertLessEqual(len(result.vectors), top_k)

    def test_query_vectors_empty_results(self):
        """测试空查询结果的向量查询"""
        # 测试空查询结果
        query_vector = VectorData(float32=[float(random.random()) for _ in range(128)])
        
        result = self.vector_client.query_vectors(
            vector_bucket_name=self.bucket_name,
            account_id=self.account_id,
            index_name=self.test_index_name,
            query_vector=query_vector,
            top_k=5,
            return_distance=True,
            return_metadata=True,
            filter={'category': 'NonExistentCategory'}
        )
        
        self.assertEqual(result.status_code, 200)
        self.assertIsNotNone(result)
        # 空结果时vectors应该为空列表
        self.assertEqual(len(result.vectors), 0)

    def test_list_vectors_pagination(self):
        """测试向量分页功能"""
        page_size = 5

        # 第一页
        page1 = self.vector_client.list_vectors(
            vector_bucket_name=self.bucket_name,
            account_id=self.account_id,
            index_name=self.test_index_name,
            max_results=page_size,
            return_data=True,
            return_metadata=True
        )

        self.assertEqual(page1.status_code, 200)
        self.assertIsNotNone(page1.vectors)
        self.assertEqual(len(page1.vectors), page_size)
        self.assertIsNotNone(page1.next_token)

        # 第二页
        page2 = self.vector_client.list_vectors(
            vector_bucket_name=self.bucket_name,
            account_id=self.account_id,
            index_name=self.test_index_name,
            max_results=page_size,
            next_token=page1.next_token,
            return_data=True,
            return_metadata=True
        )

        self.assertEqual(page2.status_code, 200)
        self.assertIsNotNone(page2.vectors)
        self.assertEqual(len(page2.vectors), page_size)
        self.assertIsNotNone(page2.next_token)

        # 验证没有重复向量
        page1_keys = [v.key for v in page1.vectors]
        page2_keys = [v.key for v in page2.vectors]
        duplicates = set(page1_keys) & set(page2_keys)
        self.assertEqual(len(duplicates), 0)

        # 第三页（最后一页）
        page3 = self.vector_client.list_vectors(
            vector_bucket_name=self.bucket_name,
            account_id=self.account_id,
            index_name=self.test_index_name,
            max_results=page_size,
            next_token=page2.next_token,
            return_data=True,
            return_metadata=True
        )

        self.assertEqual(page3.status_code, 200)
        self.assertIsNotNone(page3.vectors)
        self.assertEqual(len(page3.vectors), 0)

    def test_list_vectors_without_optional_parameters(self):
        """测试不带可选参数的向量列表查询"""
        list_res = self.vector_client.list_vectors(
            vector_bucket_name=self.bucket_name,
            account_id=self.account_id,
            index_name=self.test_index_name
        )

        self.assertEqual(list_res.status_code, 200)
        self.assertIsNotNone(list_res.vectors)
        self.assertGreaterEqual(len(list_res.vectors), 10)

    def test_list_vectors_with_return_data_false(self):
        """测试return_data为false的向量列表查询"""
        list_res = self.vector_client.list_vectors(
            vector_bucket_name=self.bucket_name,
            account_id=self.account_id,
            index_name=self.test_index_name,
            return_data=False
        )

        self.assertEqual(list_res.status_code, 200)
        self.assertIsNotNone(list_res.vectors)
        self.assertGreaterEqual(len(list_res.vectors), 10)

        # 当return_data为false时，验证向量的data字段应该为None
        test_vector = list_res.vectors[0]
        self.assertIsNone(test_vector.data)
        self.assertIsNone(test_vector.metadata)
           

    def test_list_vectors_with_return_metadata_false(self):
        """测试return_metadata为false的向量列表查询"""
        list_res = self.vector_client.list_vectors(
            vector_bucket_name=self.bucket_name,
            account_id=self.account_id,
            index_name=self.test_index_name,
            return_metadata=False
        )

        self.assertEqual(list_res.status_code, 200)
        self.assertIsNotNone(list_res.vectors)
        self.assertGreaterEqual(len(list_res.vectors), 10)

        # 当return_metadata为false时，验证向量的metadata字段应该为None
        test_vector = list_res.vectors[0]
        self.assertIsNone(test_vector.data)
        self.assertIsNone(test_vector.metadata)

    def test_list_vectors_with_both_return_data_and_metadata_true(self):
        """测试return_data和return_metadata都为true的向量列表查询"""
        list_res = self.vector_client.list_vectors(
            vector_bucket_name=self.bucket_name,
            account_id=self.account_id,
            index_name=self.test_index_name,
            return_data=True,
            return_metadata=True
        )

        self.assertEqual(list_res.status_code, 200)
        self.assertIsNotNone(list_res.vectors)
        self.assertGreaterEqual(len(list_res.vectors), 10)

        # 验证数据和元数据都存在
        test_vector = list_res.vectors[0]
        self.assertEqual(test_vector.key, "test-vector-0")
        self.assertIsNotNone(test_vector.data)
        self.assertIsNotNone(test_vector.data.float32)
        self.assertEqual(len(test_vector.data.float32), 128)
        self.assertIsNotNone(test_vector.metadata)
        self.assertEqual(test_vector.metadata['category'], 'A')
        
        
if __name__ == "__main__":
    unittest.main()
