import tos

# 以下代码展示了Bucket相关操作，诸如创建、删除、列举Bucket等。

ak = 'your access key'
sk = 'your secret key'
endpoint = "your endpoint"
region = 'your region'
bucket_name = 'your bucket name'
object_key = 'your object key'

# 创建TosClient2对象，对桶和对象的操作都通过TosClient2对象对象进行操作
client = tos.TosClientV2(ak, sk, endpoint, region)

# 创建带权限与存储类型的bucket
client.create_bucket(bucket_name, storage_class=tos.StorageClassType.Storage_Class_Standard,
                     az_redundancy=tos.AzRedundancyType.Az_Redundancy_Single_Az)
# 查询bucket元数据
bucket_info = client.head_bucket(bucket_name)
print(bucket_info.region)
print(bucket_info.storage_class)

# 列举bucket
list_buckets = client.list_buckets()
print(list_buckets.owner)
print(list_buckets.buckets)

# 删除桶
client.delete_bucket(bucket_name)

