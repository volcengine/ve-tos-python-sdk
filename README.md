# Volcengine TOS SDK for Python
The TOS Python SDK enables Python developers to easily work with TOS(Tinder Object Storage) service in the volcengine.
This document will show developers some basic examples about TOS bucket and object operation.


## Install
### Requirements
- Python3

The SDK provides user-friendly examples about bucket and object operation.

| **Code**             | **Introduction**                                              |
|----------------------|---------------------------------------------------------------|
| bucket_v2.py         | create/list/head/delete a bucket                              |
| object_v2.py         | put/get/head/list/delete an object                            |
| object_v2_extra.py   | set_meta/get_meta/copy_object/append_object                   |
| multipart_v2.py      | upload part object, including init/upload/complete/abort/list |
| upload.py            | upload object with checkpoint                                 |
| download.py          | download object with checkpoint                               |
| limiter.py           | upload object/download object with rate limiter               |
| progress_callback.py | upload object/download object with progress callback          |
| log.py               | using log                                                     |


# Quick Start

This section introduces how to create a bucket, upload/download/delete an object in TOS service through our SDK.

## Create a TOS Client

You can interact with TOS service after initiating a TOSClient instance.
The accesskey and secretkey of your account, endpoint and region are required as params.

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

## Create a bucket

The bucket is a kind of unique namespace in TOS, which is a container to store data.
This example shows you how to create a bucket.

```python
import tos

ak = "your access key"
sk = "your secret key"
endpoint = "your endpoint"
region = "your region"
bucket_name = "your bucket name"
client = tos.TosClientV2(ak, sk, endpoint, region)
client.create_bucket(bucket_name)                            
```

## Put Object

You can put your file as an object into your own bucket.

```python
# call put_object to upload you data to the TOS                     
client.put_object(bucket_name, object_key, content="123")
assert resp.status == 200       
```
## Get Object
You can download objects in the TOS bucket through our SDK.

```python
# call get_object to download your data from your bucket
client.get_object(bucket_name, object_key)
```

## Delete Object

Your can delete your objects in the bucket：

```python
# call put_object to upload you data to the TOS  
resp = client.put_object(bucket_name, key_name, content="123")
assert resp.status_code == 200   
# call delete_object to delete an object in your bucket
resp = client.delete_object(bucket_name, key_name)
assert resp.status_code == 204
```

## License
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.html)