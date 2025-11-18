import os
import unittest
from tests.common import random_string
from tos.vector_client import VectorClient

class TosVectorClientBase(unittest.TestCase):
  def __init__(self, *args, **kwargs):
    super(TosVectorClientBase, self).__init__(*args, **kwargs)
    self.ak = os.getenv('AK')
    self.sk = os.getenv('SK')
    self.vector_endpoint = os.getenv('VectorEndpoint')
    self.region = os.getenv('Region')
    self.account_id = os.getenv('AccountId')
    self.bucket_name = "py-sdk-" + random_string(10)
    self.bucket_delete = []
  def setUp(self):
    self.vector_client = VectorClient(self.ak, self.sk, self.vector_endpoint, self.region)
  
  def tearDown(self):
    for bucket in self.bucket_delete:
        response = self.vector_client.list_indexes(bucket, self.account_id, 100)
        for index in response.indexes:
            self.vector_client.delete_index(bucket, self.account_id, index.index_name)
        self.vector_client.delete_vector_bucket(bucket, self.account_id)
  
  def get_bucket_name(self):
    return "py-sdk-" + random_string(10)