import tos

ak = 'your access key'
sk = 'your secret key'
endpoint = 'your endpoint'
region = 'your region'
bucket_name = 'your bucket name'
object_key = 'your object key'

# 配置上传对象平均为 5MB/s 最大为 20MB/s
limiter = tos.RateLimiter(5 * 1024 * 1024, 20 * 1024 * 104)

# 创建TosClient2对象，对桶和对象的操作都通过TosClient2对象对象进行操作
client = tos.TosClientV2(ak, sk, endpoint, region)

# 创建bucket
client.create_bucket(bucket_name)

# 向bucket 中添加object
# rate_limiter 为可选参数， 用于实现客户端上传限速功能
client.put_object(bucket_name, object_key, content='a' * 1024 * 1024, rate_limiter=limiter)
