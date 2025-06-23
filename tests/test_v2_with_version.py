import time

import tos
from tests.common import TosTestBase, random_bytes
from tos import VersioningStatusType
from tos.models2 import Tag, ObjectTobeDeleted


class TestWithVersion(TosTestBase):
    def test_get_version(self):
        bucket_name = self.bucket_name + '-with-version'
        dist_bucket = self.bucket_name + 'dist'
        self.bucket_delete.append(bucket_name)
        self.bucket_delete.append(dist_bucket)
        key = self.random_key('.js')
        self.client.create_bucket(bucket_name)
        self.client.create_bucket(dist_bucket)
        self.version_client.put_bucket_versioning(bucket_name, True)
        self.version_client.put_bucket_versioning(dist_bucket, True)
        time.sleep(60)
        out_v1 = self.client.put_object(bucket_name, key, content=b'123')
        self.assertIsNotNone(out_v1.version_id)
        self.assertObjectContent(bucket_name, key, content=b'123')

        out_v2 = self.client.put_object(bucket_name, key, content=b'456')
        self.assertIsNotNone(out_v2.version_id)
        self.assertObjectContent(bucket_name, key, content=b'456')

        tag_set = []
        tag_set.append(Tag(
            key='1',
            value='2'
        ))
        put_out = self.client.put_object_tagging(bucket=bucket_name, key=key, tag_set=tag_set,
                                                 version_id=out_v1.version_id)
        out = self.client.get_object_tagging(bucket_name, key, version_id=out_v1.version_id)
        self.assertEqual(out.version_id, out_v1.version_id)
        self.assertIsNotNone(out.tag_set[0].key, '1')
        self.assertIsNotNone(out.tag_set[0].value, '2')

        tag_set = []
        tag_set.append(Tag(
            key='2',
            value='3'
        ))
        put_out = self.client.put_object_tagging(bucket=bucket_name, key=key, tag_set=tag_set,
                                                 version_id=out_v2.version_id)
        out = self.client.get_object_tagging(bucket_name, key, version_id=out_v2.version_id)
        self.assertEqual(out.version_id, out_v2.version_id)
        self.assertIsNotNone(out.tag_set[0].key, '2')
        self.assertIsNotNone(out.tag_set[0].value, '3')

        self.assertEqual(self.client.get_object(bucket_name, key, version_id=out_v1.version_id).read(), b'123')
        self.assertEqual(self.client.get_object(bucket_name, key, version_id=out_v2.version_id).read(), b'456')

        out = self.client.copy_object(dist_bucket, key, bucket_name, key, src_version_id=out_v1.version_id)
        self.assertEqual(out.copy_source_version_id, out_v1.version_id)

        task = self.client.create_multipart_upload(bucket_name, 'testcopyversion')
        part = []
        out = self.client.upload_part_copy(bucket_name, task.key, task.upload_id, 1, bucket_name, key,
                                           src_version_id=out_v1.version_id)
        part.append(tos.models2.UploadedPart(1, out.etag))
        self.client.complete_multipart_upload(bucket_name, task.key, task.upload_id, part)
        copy_out = self.client.get_object(task.bucket, task.key)
        self.assertEqual(copy_out.read(), b'123')

        task = self.client.create_multipart_upload(bucket_name, 'testcopyversion2')
        part = []
        out = self.client.upload_part_copy(bucket_name, task.key, task.upload_id, 1, bucket_name, key,
                                           src_version_id=out_v2.version_id)
        part.append(tos.models2.UploadedPart(1, out.etag))
        self.client.complete_multipart_upload(bucket_name, task.key, task.upload_id, part)
        copy_out = self.client.get_object(task.bucket, task.key)
        self.assertEqual(copy_out.read(), b'456')

    def test_list_with_version(self):
        bucket_name = self.bucket_name + '-with-version-2'
        self.bucket_delete.append(bucket_name)
        key = self.random_key('.js')
        content = random_bytes(100)
        self.client.create_bucket(bucket_name)
        self.version_client.put_bucket_versioning(bucket_name, True)
        time.sleep(30)
        raw = "!@#$%^&*()_+-=[]{}|;':\",./<>?中文测试编码%20%%%^&abcd /\\"
        meta = {'name': ' %张/三%', 'age': '12', 'special': raw, raw: raw}
        self.client.put_object(bucket_name, 'test.txt', content=content,
                               storage_class=tos.StorageClassType.Storage_Class_Ia, meta=meta)
        self.client.put_object(bucket_name, 'test.txt', content=content,
                               storage_class=tos.StorageClassType.Storage_Class_Ia, meta=meta)
        out = self.client.list_object_versions(bucket_name, fetch_meta=True)
        for version in out.versions:
            self.assertIsNotNone(version.version_id)
            self.assertIsNotNone(version.etag)
            self.assertIsNotNone(version.owner)
            self.assertIsNotNone(version.is_latest)
            self.assertEqual(version.key, 'test.txt')
            self.assertEqual(version.storage_class, tos.StorageClassType.Storage_Class_Ia)
            self.assertTrue(version.meta['name'], meta['name'])
            self.assertTrue(version.meta['age'], meta['age'])
            self.assertTrue(version.meta['special'], meta['special'])
            self.assertTrue(version.meta[raw], meta[raw])

        self.client.put_object(bucket_name, 'test2.txt', content='123')
        out_1 = self.client.list_object_versions(bucket_name, max_keys=1)
        self.assertEqual(out_1.max_keys, 1)
        self.assertIsNotNone(out_1.next_version_id_marker)
        self.assertIsNotNone(out_1.next_key_marker)
        out_2 = self.client.list_object_versions(bucket_name, key_marker=out_1.next_key_marker,
                                                 version_id_marker=out_1.next_version_id_marker)

        self.client.put_object(bucket_name, 'func/')
        self.client.put_object(bucket_name, 'func2/')
        self.client.put_object(bucket_name, 'func3/')
        out = self.client.list_object_versions(bucket_name, delimiter='/')
        self.assertTrue(len(out.common_prefixes), 3)
        self.assertFalse(out_2.is_truncated)

    def test_download_copy_version(self):
        bucket_name = self.bucket_name + '-with-download-copy-version'
        dist_bucket = self.bucket_name + 'dist'
        file_name = self.random_filename()
        self.bucket_delete.append(bucket_name)
        self.bucket_delete.append(dist_bucket)
        content1 = random_bytes(1024)
        content2 = random_bytes(1024)
        key = self.random_key('.js')
        self.client.create_bucket(bucket_name)
        self.client.create_bucket(dist_bucket)
        self.version_client.put_bucket_versioning(bucket_name, True)
        self.version_client.put_bucket_versioning(dist_bucket, True)
        time.sleep(60)
        rsp = self.version_client.get_bucket_version(bucket_name)
        self.assertEqual(rsp.status, VersioningStatusType.Versioning_Status_Enabled)
        rsp = self.version_client.get_bucket_version(dist_bucket)
        self.assertEqual(rsp.status, VersioningStatusType.Versioning_Status_Enabled)
        out = self.client.put_object(bucket_name, key, content=content1)
        self.client.put_object(bucket_name, key, content=content2)
        self.client.download_file(bucket_name, key, file_name, version_id=out.version_id)
        self.assertFileContent(file_name, content1)

        self.client.resumable_copy_object(dist_bucket, key, bucket_name, key, src_version_id=out.version_id)
        self.assertObjectContent(dist_bucket, key, content1)

    def test_delete_version(self):
        bucket_name = self.bucket_name + '-with-download-copy-version'
        self.bucket_delete.append(bucket_name)
        self.client.create_bucket(bucket_name)
        self.version_client.put_bucket_versioning(bucket_name, True)
        time.sleep(10)
        delete = []
        v1 = self.client.put_object(bucket_name, '1')
        delete.append(ObjectTobeDeleted('1', v1.version_id))
        v2 = self.client.put_object(bucket_name, '1')
        delete.append(ObjectTobeDeleted('1', v2.version_id))
        out = self.client.delete_multi_objects(bucket_name, delete)
        self.assertTrue(len(out.deleted) == 2)

        v1 = self.client.put_object(bucket_name, '1')
        delete.append(ObjectTobeDeleted('1', v1.version_id))
        v2 = self.client.put_object(bucket_name, '1')
        delete.append(ObjectTobeDeleted('1', v2.version_id))
        out = self.client.delete_multi_objects(bucket_name, delete, quiet=True)
        self.assertTrue(len(out.deleted) == 0)
