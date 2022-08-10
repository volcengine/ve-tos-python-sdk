import json

from .models2 import ResponseInfo
from .utils import get_value, to_str

_TOS_ERROR_TO_EXCEPTION = {}


class TosError(Exception):
    def __init__(self, msg: str):
        self.message = msg

    def __str__(self):
        error = {"message": self.message}
        return str(error)


def make_exception(resp):
    body = resp.read()
    details = _parse_error_body(body)
    return TosError(details.get('Message', ''))


def _parse_error_body(body):
    try:
        return json.loads(body)
    except Exception:
        return {'message': to_str(body)}


class TosClientError(TosError):
    def __init__(self, msg: str, cause: Exception = None):
        super(TosClientError, self).__init__(msg)
        self.cause = cause

    def __str__(self):
        error = {'message': self.message,
                 'case': str(self.cause)}
        return str(error)


class TosServerError(TosError, ResponseInfo):
    def __init__(self, resp, msg: str, code: str, host_id: str, resource: str):
        self.message = msg
        self.request_id = resp.request_id
        self.id2 = get_value(resp.headers, "x-tos-id-2")
        self.status_code = resp.status
        self.header = resp.headers
        self.code = code
        self.host_id = host_id
        self.resource = resource

    def __str__(self):
        error = {'message': self.message,
                 'request_id': self.request_id,
                 'id2': self.id2,
                 'status_code': self.status_code,
                 'header': self.header,
                 'code': self.code,
                 'host_id': self.host_id,
                 'resource': self.resource}
        return str(error)


def make_server_error(resp):
    body = resp.read()
    details = _parse_error_body(body)
    code = details.get('Code', '')
    host_id = details.get('HostId', '')
    resource = details.get('Resource', '')
    message = details.get('Message', '')
    return TosServerError(resp, message, code, host_id, resource)


class CancelError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        info = {'message': self.message}
        return str(info)


class CancelWithAbortError(CancelError):
    def __init__(self, message):
        super(CancelWithAbortError, self).__init__(message)


class CancelNotWithAbortError(CancelError):
    def __init__(self, message):
        super(CancelNotWithAbortError, self).__init__(message)