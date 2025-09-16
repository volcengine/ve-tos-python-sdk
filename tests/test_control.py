# # -*- coding: utf-8 -*-
# from tests.common import TosTestBase
#
# from tos.enum import (QueryOrderType, AggregationOperationType, SemanticQueryType,
#                       QueryOperationType)
#
# from tos.models2 import  AggregationRequest, QueryRequest
#
#
# class TestObject(TosTestBase):
#
#     def test_simple_query(self):
#         # base simple query
#         resp = self.client.simple_query(account_id=self.account_id,
#                                         dataset_name="windlike-2")
#         self.assertEqual(resp.status_code, 200)
#         self.assertEqual(100, len(resp.files))
#
#         # with sort,order,max_result
#         resp = self.client.simple_query(account_id=self.account_id,
#                                  dataset_name="windlike-2",
#                                  sort="FileModifiedTime",
#                                  order=QueryOrderType.ASC,
#                                         max_results=10)
#         self.assertEqual(resp.status_code, 200)
#         self.assertEqual(10, len(resp.files))
#         file_name = resp.files[0].file_name
#         # with next token
#         resp = self.client.simple_query(account_id=self.account_id,
#                                         dataset_name="windlike-2",
#                                         sort="FileModifiedTime",
#                                         order=QueryOrderType.ASC,
#                                         max_results=10,next_token=resp.next_token)
#         self.assertEqual(10, len(resp.files))
#         self.assertNotEquals(file_name , resp.files[0].file_name)
#         # with fields
#         resp = self.client.simple_query(account_id=self.account_id,
#                                         dataset_name="windlike-2",
#                                         sort="FileModifiedTime",
#                                         order=QueryOrderType.ASC,
#                                         max_results=10,with_fields=["TOSBucketName","FileName","ETag","TOSStorageClass",
#                                                                     "Size","ContentType","TOSCRC64","ServerSideEncryption",
#                                                                     "ServerSideEncryptionCustomerAlgorithm","TOSTaggingCount",
#                                                                     "TOSTagging","TOSUserMeta","TOSVersionId","TOSObjectType",
#                                                                     "TOSReplicationStatus","TOSIsDeleteMarker","AccountId"],
#                                         query=QueryRequest(
#                                             operation=QueryOperationType.AND,
#                                             sub_queries=[QueryRequest(operation=QueryOperationType.PREFIX,
#                                                                       field="FileName", value="test-py-sdk")])
#                                         )
#         self.assertEqual(1, len(resp.files))
#         self.assertEqual(True,resp.files[0].etag is not None)
#         # with query
#         resp = self.client.simple_query(account_id=self.account_id,
#                                         dataset_name="windlike-2",
#                                         sort="FileModifiedTime",
#                                         order=QueryOrderType.ASC,
#                                         max_results=10,  with_fields=["FileName"],
#                                         query=QueryRequest(
#                                             operation=QueryOperationType.AND,
#                                             sub_queries=[QueryRequest(operation=QueryOperationType.PREFIX,
#                                                                       field="FileName", value="1a5")])
#                                         )
#         self.assertEqual(0, len(resp.files))
#
#
#         # with aggregations
#
#         resp = self.client.simple_query(account_id=self.account_id,
#                                         dataset_name="windlike-2",
#                                         aggregations=[AggregationRequest("Size",AggregationOperationType.MAX),
#                                                       AggregationRequest("TOSStorageClass", AggregationOperationType.GROUP),
#                                                       AggregationRequest("ContentType", AggregationOperationType.GROUP)
#                                                       ])
#
#         self.assertEqual(resp.status_code, 200)
#
#     def test_semantic_query(self):
#         # 文字检索
#         resp = self.client.semantic_query(account_id=self.account_id,
#                                         dataset_name="img-test-only-incr",
#                                         semantic_query_type=SemanticQueryType.SemanticQueryTypeText,
#                                         max_results=10,
#                                         semantic_query_input="猫",
#                                         query=QueryRequest(
#                                             operation=QueryOperationType.AND,
#                                             sub_queries=[QueryRequest(operation=QueryOperationType.PREFIX,
#                                                                       field="FileName",value="1a5")]),
#                                         with_fields=["FileName"],
#                                           )
#
#         self.assertEqual(resp.status_code, 200)