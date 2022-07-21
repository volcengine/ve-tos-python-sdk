# 火山引擎 TOS Python SDK
## 简介
TOS Python SDK为Python开发者提供了访问火山引擎对象存储服务TOS（Tinder Object Storage）的系列接口。本文档将给出TOS桶和对象的基本操作代码，供开发者参考.

## 安装
### 最低依赖
- Python3

SDK提供了针对桶、对象操作的示例代码，方便使用者参考使用。

| **示例代码**         | **示例说明**                                    |
| -------------------- |---------------------------------------------|
| bucket_v2.py      | 创建桶，列举用户桶，获取桶信息和删桶等                         |
| object_v2.py       | 创建桶，上传对象，下载对象，查看对象信息，列举对象，删除对象等             |
| object_v2_extra.py   | 包括设置和获取用户自定义元数据、拷贝对象、追加上传对象等                |
| multipart_v2.py   | 多段上传对象，包括初始化、上传、合并多段，取消分片上传，列举分片任务和已经上传的分片等 |
| upload.py   | 断点续传上传                                      |

# 快速入门

本章节介绍，如何通过TOS Python SDK来完成常见的操作，如创建桶，上传、下载和删除对象等。

## 初始化TOS客户端

初始化TosClient实例之后，才可以向TOS服务发送HTTP/HTTPS请求。

TOS Python客户端初始化，提供了一系列接口用来与TOS服务进行交互，用来管理桶和对象等TOS上的资源。初始化客户端时，需要带上accesskey，secretkey，endpoint和region。初始化代码如下：

```python
import tos

ak = "your access key"
sk = "your secret key"
endpoint = "your endpoint"
region = "your region"
bucket_name = "your bucket name"
object_key = "your object key"
client = tos.TosClientV2(ak, sk, endpoint, region)  
```

## 创建桶

桶是TOS的全局唯一的命名空间，相当于数据的容器，用来储存对象数据。如下代码展示如何创建一个新桶：

```python
# 创建桶
resp = client.create_bucket(bucket_name)
assert resp.status_code == 200                                
```

## 上传对象

新建桶成功后，可以往桶中上传对象，如下展示如何上传一个对象到已创建的桶中：

```python
# 调用 put_object 将对象上传到桶中                     
resp = client.put_object(bucket_name, key_name, content="123")
assert resp.status_code == 200       
```
## 下载对象

如下展示如何从桶中下载一个已经存在的对象：

```python
# 调用 get_object 接口从桶中获取对象
resp = client.get_object(bucket_name, key_name)
assert resp.status_code == 200
```

## 删除对象

如下展示如何从桶中删除一个已经存在的对象：

```python
# 调用 put_object 将对象上传到桶中                     
resp = client.put_object(bucket_name, key_name, content="123")
assert resp.status_code == 200   
# 调用 delete_object 从桶中删除对象
resp = client.delete_object(bucket_name, key_name)
assert resp.status_code == 204
```

## License
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.html)