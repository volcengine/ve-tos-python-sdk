import os

import tos

# 以下的代码展示了基本的对象上传、下载、列举、删除用法

ak = 'your access key'
sk = 'your secret key'
endpoint = 'your endpoint'
region = 'your region'
bucket_name = 'your bucket name'
object_key = 'your object key'

# 创建TosClient2对象，对桶和对象的操作都通过TosClient2对象对象进行操作
client = tos.TosClientV2(ak, sk, endpoint, region)

# 创建bucket
client.create_bucket(bucket_name)

# 向bucket 中添加object
client.put_object(bucket_name, object_key, content='测试一下')

# 获取object的元信息
head_object = client.head_object(bucket_name, object_key)
print(head_object.etag)
print(head_object.last_modified)
print(head_object.content_length)
print(head_object.object_type)
print(head_object.hash_crc64_ecma)

# 下载到本地文件
client.get_object_to_file(bucket_name, object_key, '本地文件名.txt')

# 将下载的本地文件上传到Tos并设置新的object为 'xxx.txt'
client.put_object_from_file(bucket_name, 'xx.txt', '本地文件名.txt')

# 列举bucket中object
list_objects = client.list_objects(bucket_name)
print(list_objects.contents)

# 删除名为 '本地文件名.txt' 的 object
client.delete_object(bucket_name, 'xx.txt')

# 获取不存在的文件会抛出 tos.exceptions.TosServerError
try:
    client.get_object(bucket_name, 'xx.txt')
except tos.TosServerError as e:
    print('对象已经被删除, request_id={0}'.format(e.request_id))
else:
    assert False

# 清除本地文件
os.remove('本地文件名.txt')
os.remove('xx.txt')


