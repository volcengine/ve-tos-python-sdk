# -*- coding: utf-8 -*-
import logging

import tos

# 以下代码展示了 Python SDK 日志开启功能

log_file_path = 'your fog file path'

tos.set_logger(file_path=log_file_path, name='tos', level=logging.INFO)

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