import threading
import time

import tos
from tos.checkpoint import CancelHook

ak = 'your access key'
sk = 'your secret key'
endpoint = 'your endpoint'
region = 'your region'
bucket_name = 'your bucket name'
object_key = 'your object key'
file_path = 'your file path'


class MyCancel(CancelHook):
    def cancel(self, is_abort: bool):
        time.sleep(1)
        super(MyCancel, self).cancel(is_abort)


# 用户可通过继承CancelHook类 实现取消断点续传下载任务，is_abort 为True时删除上下文信息并 abort 分段下载任务，
# 为 false 时只是中断当前执行
cancel = MyCancel()
# CancelHook
t1 = threading.Thread(target=cancel.cancel, args=(True,))
t1.start()


# 创建 TosClient2 对象，对桶和对象的操作都通过 TosClient2 对象对象进行操作
client = tos.TosClientV2(ak, sk, endpoint, region)

# 创建分段大小为 20MB 并发线程数为 3 的断点续传下载
client.download_file(bucket=bucket_name, key=object_key, file_path=file_path, part_size=1024 * 1024 * 20, task_num=3,
                     cancel_hook=cancel)
