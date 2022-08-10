# -*- coding: utf-8 -*-

#: 连接超时时间
CONNECT_TIMEOUT = 60

GMT_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
DATE_FORMAT = '%Y%m%dT%H%M%SZ'
LAST_MODIFY_TIME_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD'

CHUNK_SIZE = 8 * 1024
PAYLOAD_BUFFER = 1024 * 1024
EMPTY_SHA256_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

DEFAULT_MIMETYPE = 'binary/octet-stream'
SLEEP_BASE_TIME = 0.1

WHITE_LIST_FUNCTION = ['create_bucket', 'delete_bucket', 'create_multipart_upload', 'complete_multipart_upload',
                       'abort_multipart_upload', 'set_object_meta', 'put_object_acl', 'delete_object', 'put_object',
                       'upload_part']
PUT_OBJECT_WHITE_FUNC = ['put_object_from_file']

UPLOAD_PART_WHITE_FUNC = ['upload_part_from_file', '_upload_part']

CLIENT_ENCRYPTION_ALGORITHM = ['AES256']
SERVER_ENCRYPTION_ALGORITHM = ['AES256']

MAX_PART_NUMBER = 10000

MIN_PART_SIZE = 5242880
MAX_PART_SIZE = 5368709120
