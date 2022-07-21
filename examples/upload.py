import os
import random
import string

import tos
from tos import to_bytes

ak = 'your access key'
sk = 'your secret key'
endpoint = 'your endpoint'
region = 'your region'
bucket_name = 'your bucket name'
object_key = 'your object key'

# 创建 TosClient2 对象，对桶和对象的操作都通过 TosClient2 对象对象进行操作
client = tos.TosClientV2(ak, sk, endpoint, region)


def random_string(n):
    return ''.join(random.choice(string.ascii_lowercase) for i in range(n))


# 生成一个本地文件用于测试。文件内容是 bytes 类型。
filename = random_string(32) + '.txt'
content = to_bytes(random_string(1024 * 1024 * 21))

with open(filename, 'wb') as fileobj:
    fileobj.write(content)

# 断点续传: 内部使用分片上传接口, 因此最小 part_size 为 5M, 默认设置 20M
client.upload_file(bucket_name, object_key, filename, task_num=3, part_size=1024 * 1024 * 5)

# 验证一下
with open(filename, 'rb') as f:
    assert client.get_object(bucket_name, object_key).read() == fileobj.read()

os.remove(filename)
