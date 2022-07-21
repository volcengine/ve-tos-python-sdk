import tos

ak = "your ak"
sk = "your sk"
endpoint = "endpoint"
region = 'region'
bucket_name = "bucket"
object_key = "key"

# 以下代码展示了object操作的高级用法，包括：中文、设置用户自定义元数据、拷贝文件、追加上传等.

# 创建TosClient2对象，对桶和对象的操作都通过TosClient2对象对象进行操作
client = tos.TosClientV2(ak, sk, endpoint, region)

client.put_object(bucket_name, "中文对象名.txt", "中文内容")


# 上传数据时携带自定义元数据
result = client.put_object(bucket_name, object_key, meta={"姓名": "张三", "age": 20})

# python sdk 中所有接口返回的结果都继承 ResponseInfo类，返回异常为TosServerError时，可通过request_id 和id2进行定位
print('http-status={0}, request_id={1}, id2={2}'.format(result.status_code, result.request_id, result.id2))

# 修改自定义元数据, 包括用户自定义元数据/网页缓存行为相关元数据/内容编码与格式相关元数据
client.set_object_meta(bucket_name, object_key, meta={'姓名': '李四'})

# 查询自定义元数据
result = client.head_object(bucket_name, object_key)
assert result.meta['姓名'] == '李四'

# 查询对象大小/存储类型/修改时间等元数据
print(result.content_length)
print(result.storage_class)
print(result.last_modified)

# 拷贝对象.示例中将 object_name 拷贝为 new_object_name
client.copy_object(bucket_name, object_key, bucket_name, "new_object_name")

# 创建类型为可追加文件,首次偏移 offset 设置为0
result = client.append_object(bucket_name, object_key, 0, 'test append object first time')

# 追加一行数据, 偏移量从上次相应中获取，或者通过head_object接口 返回content-length获取
client.append_object(bucket_name, object_key, result.next_append_offset, 'test append object second time')

