import six
import datetime
import pytz
import os.path
from .consts import LAST_MODIFY_TIME_DATE_FORMAT, GMT_DATE_FORMAT, DEFAULT_MIMETYPE
from .mine_type import TYPES_MAP


def get_value(kv, key, handler=lambda x: x):
    if key in kv:
        return handler(kv[key])
    else:
        return None


def get_etag(kv):
    return get_value(kv, "ETag", lambda x: x.strip('"'))


def to_bytes(data):
    if six.PY2:
        if isinstance(data, unicode):
            return data.encode('utf-8')
    if six.PY3:
        if isinstance(data, str):
            return data.encode(encoding='utf-8')
    return data


def to_str(data):
    if six.PY2:
        if isinstance(data, unicode):
            return data.encode('utf-8')
    if six.PY3:
        if isinstance(data, bytes):
            return data.decode('utf-8')
    return data


def normalize_url_path(path):
    if not path:
        return '/'
    return remove_dot_segments(path)


def remove_dot_segments(url):
    if not url:
        return ''
    input_url = url.split('/')
    output_list = []
    for x in input_url:
        if x and x != '.':
            if x == '..':
                if output_list:
                    output_list.pop()
            else:
                output_list.append(x)

    if url[0] == '/':
        first = '/'
    else:
        first = ''
    if url[-1] == '/' and output_list:
        last = '/'
    else:
        last = ''
    return first + '/'.join(output_list) + last


def parse_modify_time_to_utc_datetime(value):
    return datetime.datetime.strptime(value, LAST_MODIFY_TIME_DATE_FORMAT).replace(tzinfo=pytz.utc)


def parse_gmt_time_to_utc_datetime(value):
    return datetime.datetime.strptime(value, GMT_DATE_FORMAT).replace(tzinfo=pytz.utc)

def get_content_type(key):
    """根据文件名后缀，获取文件类型"""
    ext = os.path.splitext(key)[1].lower()
    return TYPES_MAP[ext] if ext in TYPES_MAP else DEFAULT_MIMETYPE
