import json

from .utils import get_etag, to_str

_TOS_ERROR_TO_EXCEPTION = {}


class TosError(Exception):
    def __init__(self, status, headers, body, details):
        self.status = status
        self.request_id = headers.get("x-tos-request-id", '')
        self.body = body
        self.details = details
        self.code = self.details.get('Code', '')
        self.message = self.details.get('Message', '')
        self.headers = headers
        self.etag = get_etag(headers)


def make_exception(resp):
    status = resp.status
    headers = resp.headers
    body = resp.read()
    details = _parse_error_body(body)
    return TosError(status, headers, body, details)


def _parse_error_body(body):
    try:
        return json.loads(body)
    except Exception:
        return {'message': to_str(body)}
