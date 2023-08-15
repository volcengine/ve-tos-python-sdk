import json

_TOS_ERROR_TO_EXCEPTION = {}


def get_value(kv, key, handler=lambda x: x):
    if key in kv:
        return handler(kv[key])
    else:
        return None


class TosError(Exception):
    def __init__(self, status, headers, body, details):
        self.status = status
        self.request_id = headers.get('x-tos-request-id', '')
        self.body = body
        self.details = details
        self.code = self.details.get('Code', '')
        self.message = self.details.get('Message', '')
        self.headers = headers
        self.etag = headers.get("ETag")


def make_exception(resp):
    status = resp.status
    headers = resp.headers
    body = resp.read()
    details = _parse_body_json(body)
    return TosError(status, headers, body, details)


def _parse_error_body(resp):
    body = resp.read()
    return _parse_body_json(body)


def _parse_body_json(body):
    try:
        return json.loads(body.decode('utf-8'))
    except Exception:
        return {'Message': body.decode('utf-8')}


class TosClientError(TosError):
    def __init__(self, msg: str, cause: Exception = None):
        self.message = msg
        self.cause = cause

    def __str__(self):
        error = {'message': self.message,
                 'case': str(self.cause)}
        return str(error)


class TosServerError(TosError):
    def __init__(self, resp, msg: str, code: str, host_id: str, resource: str):
        self.message = msg
        self.request_id = resp.request_id
        self.id2 = get_value(resp.headers, 'x-tos-id-2')
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
    details = _parse_error_body(resp)
    code = details.get('Code', '')
    host_id = details.get('HostId', '')
    resource = details.get('Resource', '')
    message = details.get('Message', '')
    return TosServerError(resp, message, code, host_id, resource)


def make_server_error_with_exception(resp, body):
    code = body.get('Code', '')
    host_id = body.get('HostId', '')
    resource = body.get('Resource', '')
    message = body.get('Message', '')
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
