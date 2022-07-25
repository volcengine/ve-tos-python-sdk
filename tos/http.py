from requests.structures import CaseInsensitiveDict

from .consts import CHUNK_SIZE
from .utils import to_bytes


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
        self.request_id = self.headers.get('x-tos-request-id', '')
        self._all_read = False

    def __iter__(self):
        return self.resp.iter_content(CHUNK_SIZE)

    def read(self, amt=None):
        if self._all_read:
            return b''

        if amt is None:
            content_list = []
            for chunk in self.resp.iter_content(CHUNK_SIZE):
                content_list.append(chunk)
            content = b''.join(content_list)

            self._all_read = True
            return content
        else:
            try:
                return next(self.resp.iter_content(amt))
            except StopIteration:
                self._all_read = True
                return b''
