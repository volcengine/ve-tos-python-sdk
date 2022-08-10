import tos
from tos import DataTransferType

ak = 'your access key'
sk = 'your secret key'
endpoint = 'your endpoint'
region = 'your region'
bucket_name = 'your bucket name'
object_key = 'your object key'


def prercentage(consumed_bytes, total_bytes, rw_once_bytes,
                type: DataTransferType):
    if total_bytes:
        rate = int(100 * float(consumed_bytes) / float(total_bytes))
        print("rate:{}, consumed_bytes:{},total_bytes{}, rw_once_bytes:{}, type:{}".format(rate, consumed_bytes,
                                                                                           total_bytes,
                                                                                           rw_once_bytes, type))

# 创建TosClient2对象，对桶和对象的操作都通过TosClient2对象对象进行操作
client = tos.TosClientV2(ak, sk, endpoint, region)

# 创建bucket
client.create_bucket(bucket_name)

# 向bucket 中添加object
# data_transfer_listener 为可选参数， 用于实现上传下载事件回调（进度条）功能
client.put_object(bucket_name, object_key, content='a' * 1024 * 1024, data_transfer_listener=prercentage)
