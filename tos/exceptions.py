import json

_TOS_ERROR_TO_EXCEPTION = {}

from .thread_ctx import produce_body


def get_value(kv, key, handler=lambda x: x):
    if key in kv:
        return handler(kv[key])
    else:
        return None


class TosError(Exception):
    def __init__(self, status=None, headers=None, body=None, details=None):
        self.status = status
        self.body = body
        self.details = details
        self.headers = headers
        if headers:
            self.request_id = headers.get('x-tos-request-id', '')
            self.etag = headers.get("ETag")
        if details:
            self.code = self.details.get('Code', '')
            self.message = self.details.get('Message', '')
        self.request_url = ''


def make_exception(resp):
    status = resp.status
    headers = resp.headers
    body = resp.read()
    details = _parse_body_json(body)
    return TosError(status, headers, body, details)


def _parse_error_body(resp):
    body = resp.read()
    produce_body(len(body))
    return _parse_body_json(body)


def _parse_body_json(body):
    try:
        return json.loads(body.decode('utf-8'))
    except Exception:
        return {'Message': body.decode('utf-8')}


class TosClientError(TosError):
    def __init__(self, msg: str, cause: Exception = None):
        super().__init__()
        self.message = msg
        self.cause = cause

    def __str__(self):
        error = {'message': self.message,
                 'case': str(self.cause)}
        if self.request_url:
            error['request_url'] = self.request_url
        return str(error)


class TosServerError(TosError):
    def __init__(self, resp, msg: str, code: str, host_id: str, resource: str, ec: str = ''):
        super().__init__()
        self.message = msg
        self.request_id = resp.request_id
        self.id2 = get_value(resp.headers, 'x-tos-id-2')
        self.status_code = resp.status
        self.header = resp.headers
        self.code = code
        self.host_id = host_id
        self.resource = resource
        self.ec = ec
        self.key = ''

    def __str__(self):
        error = {'message': self.message,
                 'request_id': self.request_id,
                 'id2': self.id2,
                 'status_code': self.status_code,
                 'header': self.header,
                 'code': self.code,
                 'host_id': self.host_id,
                 'resource': self.resource}
        if self.ec:
            error['ec'] = self.ec
        if self.request_url:
            error['request_url'] = self.request_url
        return str(error)


def make_server_error(resp,key=''):
    details = _parse_error_body(resp)
    e = make_server_error_with_exception(resp, details)
    e.key = key
    return e


def make_server_error_with_exception(resp, body):
    code = body.get('Code', '')
    host_id = body.get('HostId', '')
    resource = body.get('Resource', '')
    message = body.get('Message', '')
    ec = body.get('EC', '')
    return TosServerError(resp, message, code, host_id, resource, ec)


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


class TaskCompleteMultipartError(Exception):
    def __init__(self, cause):
        self.cause = cause
        self.message = 'failed to do complete multipart task '

    def __str__(self):
        error = {'message': self.message,
                 'case': str(self.cause)}
        return str(error)


class RenameFileError(Exception):
    def __init__(self, cause):
        self.cause = cause
        self.message = 'failed to do rename file task'

    def __str__(self):
        error = {'message': self.message,
                 'case': str(self.cause)}
        return str(error)


class NoneTokenException(Exception):
    def __init__(self, message):
        super(NoneTokenException, self).__init__(self)
        self.message = message

    def __str__(self):
        return {'message': self.message}
