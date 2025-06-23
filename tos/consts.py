# -*- coding: utf-8 -*-

#: 连接超时时间
CONNECT_TIMEOUT = 60

GMT_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
DATE_FORMAT = '%Y%m%dT%H%M%SZ'
LAST_MODIFY_TIME_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD'
ECS_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S%z'

CHUNK_SIZE = 64 * 1024
PAYLOAD_BUFFER = 1024 * 1024
EMPTY_SHA256_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

DEFAULT_MIMETYPE = 'binary/octet-stream'
SLEEP_BASE_TIME = 0.1

WHITE_LIST_FUNCTION = ['create_bucket', 'delete_bucket', 'create_multipart_upload', 'complete_multipart_upload',
                       'abort_multipart_upload', 'set_object_meta', 'put_object_acl', 'delete_object', 'put_object',
                       'upload_part', 'put_bucket_cors', 'delete_bucket_cors', 'put_bucket_storage_class',
                       'put_bucket_lifecycle', 'delete_bucket_lifecycle', 'put_bucket_policy', 'delete_bucket_policy',
                       'put_bucket_mirror_back', 'delete_bucket_mirror_back', 'put_object_tagging',
                       'delete_object_tagging', 'put_bucket_acl', 'put_fetch_task', 'put_bucket_replication',
                       'put_bucket_versioning', 'put_bucket_website', 'delete_bucket_website',
                       'put_bucket_notification', 'put_bucket_custom_domain', 'delete_bucket_custom_domain',
                       'put_bucket_real_time_log', 'delete_bucket_real_time_log', 'restore_object', 'rename_object',
                       'put_bucket_rename', 'delete_bucket_rename', 'put_bucket_tagging', 'delete_bucket_tagging']

CALLBACK_FUNCTION = ['put_object', 'complete_multipart_upload']
CLIENT_ENCRYPTION_ALGORITHM = ['AES256']
SERVER_ENCRYPTION_ALGORITHM = ['AES256']

MAX_PART_NUMBER = 10000

MIN_PART_SIZE = 5242880
MAX_PART_SIZE = 5368709120

MIN_TRAFFIC_LIMIT = 819200
MAX_TRAFFIC_LIMIT = 838860800

SIGNATURE_QUERY_LOWER = "x-tos-signature"
V4_PREFIX = "x-tos"
BUCKET_TYPE_FNS = "fns"
BUCKET_TYPE_HNS = "hns"
