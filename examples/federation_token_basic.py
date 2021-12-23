import time

import tos
from tos.credential import FederationCredentials, FederationToken

ak = "your ak"
sk = "your sk"
sts_token = "your token"
endpoint = "endpoint"
region = 'region'
bucket_name = "bucket"
key_name = "key"

def get_federation_credential():
    global count
    count += 1
    return FederationToken(ak, sk, sts_token, int(time.time()) + 5, 1)


def get_federation_credential2():
    global count
    count += 1
    return FederationToken(ak, sk, sts_token, int(time.time()) + 10)


federationCredential = FederationCredentials(get_federation_credential)
client = tos.TosClient(tos.FederationAuth(federationCredential, region), endpoint)
try:
    count = 0
    resp = client.create_bucket(Bucket=bucket_name, ACL="public-read")
    assert resp.status == 200
    assert count == 1

    resp = client.list_buckets()
    assert resp.status == 200
    assert count == 1

    time.sleep(6)

    resp = client.head_bucket(Bucket=bucket_name)
    assert resp.status == 200
    assert count == 2

    count = 0
    federationCredential = FederationCredentials(get_federation_credential2)
    client = tos.TosClient(tos.FederationAuth(federationCredential, region), endpoint)
    resp = client.put_object(Bucket=bucket_name, Key=key_name, Body="123")
    assert resp.status == 200
    assert count == 1

    time.sleep(2)
    resp = client.get_object(Bucket=bucket_name, Key=key_name)
    assert resp.status == 200
    assert resp.read() == b'123'
    assert count == 2

    time.sleep(2)
    resp = client.delete_object(Bucket=bucket_name, Key=key_name)
    assert resp.status == 204
    assert count == 3
except Exception as e:
    print("error: {}".format(e))
finally:
    resp = client.delete_bucket(Bucket=bucket_name)
    assert resp.status == 204
