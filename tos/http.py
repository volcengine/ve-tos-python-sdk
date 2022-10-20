import json
from requests.structures import CaseInsensitiveDict

from . import exceptions
from .consts import CHUNK_SIZE
from .exceptions import TosClientError
from .utils import get_value, to_bytes


class Request(object):
    def __init__(self, method, url, path, host, data=None, params=None, headers=None):
        self.method = method
        self.url = url
        self.path = path
        self.data = to_bytes(data)
        self.params = params or {}
        self.headers = headers or {}

        self.headers['Host'] = host


class Response(object):
    def __init__(self, resp):
        self.resp = resp
        self.status = resp.status_code
        self.headers = CaseInsensitiveDict(resp.headers)
        self.content_length = get_value(self.headers, "content-length", lambda x: int(x))
        self.request_id = self.headers.get('x-tos-request-id', '')
        self._all_read = False
        self.offset = 0

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        content = self.read(CHUNK_SIZE)
        if content:
            return content
        else:
            raise StopIteration

    def read(self, amt=None):
        if self._all_read:
            return b''

        if amt is None:
            content_list = []
            for chunk in self.resp.iter_content(CHUNK_SIZE):
                content_list.append(chunk)
            content = b''.join(content_list)

            self._all_read = True
            if self.content_length and len(content) != self.content_length:
                raise exceptions.TosClientError('IO Content not equal content-length')
            return content
        else:
            try:
                read = next(self.resp.iter_content(amt))
                self.offset += len(read)
                return read
            except StopIteration:
                if self.content_length and self.offset != self.content_length:
                    raise exceptions.TosClientError('IO Content not equal content-length')
                self._all_read = True
                return b''

    def json_read(self):
        try:
            body = self.read()
            return json.loads(body.decode('utf-8'))
        except Exception as e:
            raise TosClientError('unable to do serialization', e)
