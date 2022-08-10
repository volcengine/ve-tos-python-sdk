import os
import random
import string
import threading
import time

import tos
from tos import to_bytes
from tos.checkpoint import CancelHook

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


class MyCancel(CancelHook):
    def cancel(self, is_abort: bool):
        time.sleep(1)
        super(MyCancel, self).cancel(is_abort)


# 用户可通过继承CancelHook类 实现取消断点续传上传任务，is_abort 为True时删除上下文信息并 abort 分片上传任务，
# 为 False 时只是中断当前执行
cancel = MyCancel()
# CancelHook
t1 = threading.Thread(target=cancel.cancel, args=(True,))
t1.start()

# 生成一个本地文件用于测试。文件内容是 bytes 类型。
filename = random_string(32) + '.txt'
content = to_bytes(random_string(1024 * 1024 * 21))

with open(filename, 'wb') as fileobj:
    fileobj.write(content)

# 断点续传: 内部使用分片上传接口, 因此最小 part_size 为 5M, 默认设置 20M
# 通过 cancel_hook 实现用户取消断点续传上传任务
client.upload_file(bucket_name, object_key, filename, task_num=3, part_size=1024 * 1024 * 5, cancel_hook=cancel)

# 验证一下
with open(filename, 'rb') as f:
    assert client.get_object(bucket_name, object_key).read() == fileobj.read()

os.remove(filename)
