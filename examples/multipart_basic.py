import tos

ak = "your ak"
sk = "your sk"
endpoint = "endpoint"
region = 'region'
bucket_name = "bucket"
key_name = "key"

client = tos.TosClient(tos.Auth(ak, sk, region), endpoint)
try:
    resp = client.create_bucket(Bucket=bucket_name)
    assert resp.status == 200

    resp = client.create_multipart_upload(Bucket=bucket_name, Key=key_name)
    assert resp.status == 200
    upload_id = resp.upload_id

    resp = client.list_multipart_uploads(Bucket=bucket_name)
    for upload in resp.upload_list:
        resp = client.abort_multipart_upload(Bucket=bucket_name, Key=upload.key, UploadId=upload.upload_id)
        assert resp.status == 204

    resp = client.create_multipart_upload(Bucket=bucket_name, Key=key_name)
    assert resp.status == 200
    upload_id = resp.upload_id

    data1 = '12345' * 1024 * 1024
    resp = client.upload_part(Bucket=bucket_name, Key=key_name, PartNumber=1, UploadId=upload_id, Body=data1)
    assert resp.status == 200
    etag1 = resp.etag

    data2 = '23456' * 1024 * 1024
    resp = client.upload_part(Bucket=bucket_name, Key=key_name, PartNumber=2, UploadId=upload_id, Body=data2)
    assert resp.status == 200
    etag2 = resp.etag

    resp = client.list_parts(Bucket=bucket_name, Key=key_name, UploadId=upload_id)
    assert resp.status == 200
    assert len(resp.part_list) == 2
    assert resp.part_list[0].part_number == 1
    assert resp.part_list[0].etag == etag1
    assert resp.part_list[1].part_number == 2
    assert resp.part_list[1].etag == etag2

    multipartUpload = {
        'Parts': [
            {
                'ETag': etag1,
                'PartNumber': 1
            },
            {
                'ETag': etag2,
                'PartNumber': 2
            }
        ]
    }
    resp = client.complete_multipart_upload(Bucket=bucket_name, Key=key_name, UploadId=upload_id,
                                            MultipartUpload=multipartUpload)
    assert resp.status == 200
    etag = resp.etag

    resp = client.head_object(Bucket=bucket_name, Key=key_name)
    assert resp.etag == etag
except Exception as e:
    print(e)
    assert False
finally:
    client.delete_object(Bucket=bucket_name, Key=key_name)
    resp = client.delete_bucket(Bucket=bucket_name)
    assert resp.status == 204
