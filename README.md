# Volcengine TOS SDK for Python
The TOS Python SDK enables Python developers to easily work with TOS(Tinder Object Storage) service in the volcengine.
This document will show developers some basic examples about TOS bucket and object operation.


## Install
### Requirements
- Python3

The SDK provides user-friendly examples about bucket and object operation.

| **Code**         | **Introduction**                                                 |
| -------------------- | ------------------------------------------------------------ |
| bucket_basic.py      | create/list/head/delete a bucket                       |
| object_basic.py      | put/get/head/list/delete an object |
| multipart_basic.py   | upload part object, including init/upload/complete/abort/list |


# Quick Start

This section introduces how to create a bucket, upload/download/delete an object in TOS service through our SDK.

## Create a TOS Client

You can interact with TOS service after initiating a TOSClient instance.
The accesskey and secretkey of your account, endpoint and region are required as params.

```python
ak = "Your Access Key"
sk = "Your Secret Key"
endpoint = "your endpoint"
region = "your bucket's region"
# create a TosClient
client = tos.TosClient(tos.Auth(ak, sk, region), endpoint)
```

## Create a bucket

The bucket is a kind of unique namespace in TOS, which is a container to store data.
This example shows you how to create a bucket.

```python
# Create a bucket
resp = client.create_bucket(Bucket=bucket_name)
assert resp.status == 200                                
```

## Put Object

You can put your file as an object into your own bucket.

```python
# call put_object to upload you data to the TOS                     
resp = client.put_object(Bucket=bucket_name, Key=key_name, Body="123")
assert resp.status == 200       
```
## Get Object
You can download objects in the TOS bucket through our SDK.

```python
# call get_object to download your data from your bucket
resp = client.get_object(Bucket=bucket_name, Key=key_name)
assert resp.status == 200
```

## Delete Object

Your can delete your objects in the bucket：

```python
# call put_object to upload you data to the TOS  
resp = client.put_object(Bucket=bucket_name, Key=key_name, Body="123")
assert resp.status == 200   
# call delete_object to delete an object in your bucket
resp = client.delete_object(Bucket=bucket_name, Key=key_name)
assert resp.status == 204
```

