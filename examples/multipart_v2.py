import tos

ak = 'your access key'
sk = 'your secret key'
endpoint = 'your endpoint'
region = 'your region'
bucket_name = 'your bucket name'
object_key = 'your object key'

content = 'something to upload'

# 创建TosClient2对象，对桶和对象的操作都通过TosClient2对象对象进行操作
client = tos.TosClientV2(ak, sk, endpoint, region)

# 初始化上传任务
parts = []
mult_result = client.create_multipart_upload(bucket_name, object_key)
upload_id = mult_result.upload_id

# 上传分片(除了最后一个分片外, 每个分片必须大于5MB)
result = client.upload_part(bucket_name, object_key, upload_id, 1, content=content)
parts.append(tos.models2.UploadedPart(result.part_number, result.etag))


# 完成分片上传任务
client.complete_multipart_upload(bucket_name, object_key, upload_id, parts)

# 确定对象上传成功
client.head_object(bucket_name, object_key)

# 删除已上传对象
client.delete_object(bucket_name, object_key)
