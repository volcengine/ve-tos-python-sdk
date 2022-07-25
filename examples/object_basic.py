import tos

ak = 'your access key'
sk = 'your secret key'
endpoint = 'your endpoint'
region = 'your region'
bucket_name = 'your bucket name'
key_name = 'your object key'

client = tos.TosClient(tos.Auth(ak, sk, region), endpoint)
try:
    resp = client.create_bucket(Bucket=bucket_name)
    assert resp.status == 200

    resp = client.put_object(Bucket=bucket_name, Key=key_name, Body="123")
    assert resp.status == 200
    etag = resp.etag

    resp = client.head_object(Bucket=bucket_name, Key=key_name)
    assert resp.status == 200
    assert resp.etag == etag

    resp = client.get_object(Bucket=bucket_name, Key=key_name)
    assert resp.status == 200
    assert resp.read() == b'123'

    resp = client.list_objects(Bucket=bucket_name)
    assert resp.status == 200
    assert len(resp.object_list) == 1
    assert resp.object_list[0].key == key_name
    assert resp.object_list[0].etag == etag

    resp = client.delete_object(Bucket=bucket_name, Key=key_name)
    assert resp.status == 204
except Exception as e:
    print(e)
    assert False
finally:
    client.delete_object(Bucket=bucket_name, Key=key_name)
    resp = client.delete_bucket(Bucket=bucket_name)
    assert resp.status == 204
