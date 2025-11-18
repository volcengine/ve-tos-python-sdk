# -*- coding: utf-8 -*-
import base64
import datetime
import hmac
import json
import logging
from hashlib import sha256
from urllib.parse import quote

import pytz

from .consts import DATE_FORMAT, UNSIGNED_PAYLOAD, LAST_MODIFY_TIME_DATE_FORMAT, SIGNATURE_QUERY_LOWER, V4_PREFIX
from .credential import FederationCredentials, StaticCredentialsProvider
from .exceptions import TosClientError
from .log import get_logger
from .models2 import PreSignedPostSignatureOutPut, ContentLengthRange, GenericInput
from .utils import to_bytes, _param_to_quoted_query


def _canonical_query_string_params(params):
    results = []
    for param in sorted(params):
        if param.lower() == SIGNATURE_QUERY_LOWER:
            continue
        value = str(params[param])
        results.append('%s=%s' % (quote(param, safe='-_.~'),
                                  quote(value, safe='-_.~')))
    cqs = '&'.join(results)
    return cqs


def _need_signed_headers(key, is_signing_query):
    return (key == "content-type" and not is_signing_query) or key.startswith(V4_PREFIX) or key == 'host'


def _get_signed_headers(headers, is_signing_query=False):
    signed_headers = {}
    for k, v in headers.items():
        k = k.lower()
        if _need_signed_headers(k, is_signing_query):
            signed_headers[k] = v
    return sorted(signed_headers.items(), key=lambda d: d[0].lower())


def _get_signed_header_key(signed_headers):
    return ';'.join([v[0] for v in signed_headers])


def _canonical_headers(headers):
    s = ''
    for val in headers:
        if isinstance(val[1], list):
            tlist = sorted(val[1])
            for v in tlist:
                s += val[0].lower() + ':' + v + '\n'
        else:
            s += val[0].lower() + ':' + str(val[1]) + '\n'
    return s


def _canonical_request(req, signed_headers):
    cr = [req.method.upper(), quote(req.path, safe='/~'), _canonical_query_string_params(req.params),
          _canonical_headers(signed_headers), _get_signed_header_key(signed_headers)]
    if req.headers.get('x-tos-content-sha256'):
        cr.append(req.headers['x-tos-content-sha256'])
    else:
        cr.append(UNSIGNED_PAYLOAD)
    return '\n'.join(cr)


def _x_tos_policy_canonical_request(params):
    cr = [_canonical_query_string_params(params), UNSIGNED_PAYLOAD]
    return '\n'.join(cr)


def _sign(key, msg, hex=False):
    if hex:
        sig = hmac.new(key, msg.encode('utf-8'), sha256).hexdigest()
    else:
        sig = hmac.new(key, msg.encode('utf-8'), sha256).digest()
    return sig


def _check_policy_key(key):
    if not key:
        raise TosClientError('invalid preSingedCondition key')


def _get_post_policy(date: str, expire: int, algorithm, credential, bucket, object_key,
                     conditions: [], content_length_range: ContentLengthRange = None, sts: str = None) -> dict:
    time = datetime.datetime.strptime(date, DATE_FORMAT).replace(tzinfo=pytz.utc) + datetime.timedelta(seconds=expire)
    post_policy = {
        "expiration": time.strftime(LAST_MODIFY_TIME_DATE_FORMAT)
    }

    cond = [{"x-tos-algorithm": algorithm}, {"x-tos-credential": credential}, {"x-tos-date": date}]
    if bucket:
        cond.append({"bucket": bucket})
    if object_key:
        cond.append({"key": object_key})
    if sts:
        cond.append({'x-tos-security-token': sts})

    for c in conditions:
        _check_policy_key(c.key)
        if c.operator:
            cond.append([c.operator, "${}".format(c.key), c.value])
            continue
        cond.append({c.key: c.value})

    if content_length_range:
        cond.append(["content-length-range", content_length_range.start, content_length_range.end])

    post_policy["conditions"] = cond
    return post_policy


def _get_policy(conditions: []):
    policy = {}
    cond = []
    for c in conditions:
        _check_policy_key(c.key)
        if c.operator:
            cond.append([c.operator, "${}".format(c.key), c.value])
            continue
        cond.append({c.key: c.value})
    policy['conditions'] = cond
    return policy


class AuthBase():
    def __init__(self, credentials_provider, region,service='tos'):
        self.credentials_provider = credentials_provider
        self.region = region.strip()
        self.credential = None
        self.service = service

    def sign_request(self, req):
        self.credential = self.credentials_provider.get_credentials()
        if self.credential.get_security_token():
            req.headers["x-tos-security-token"] = self.credential.get_security_token()

        date = get_date(req.generic_input)
        req.headers['Date'] = date
        req.headers['x-tos-date'] = date

        if req.generic_input and req.generic_input.request_host:
            req.headers['host'] = req.generic_input.request_host
        signed_headers = _get_signed_headers(req.headers)
        signature = self._make_signature(req=req, date=date, signed_headers=signed_headers)
        req.headers['Authorization'] = self._inject_signature_to_request(signature, date, signed_headers)

    def sign_url(self, req, expires):
        if expires is None:
            expires = 60 * 60
        date = datetime.datetime.utcnow().strftime(DATE_FORMAT)
        self.credential = self.credentials_provider.get_credentials()

        req.params['X-Tos-Algorithm'] = 'TOS4-HMAC-SHA256'
        req.params['X-Tos-Credential'] = self._credential(date)
        req.params['X-Tos-Date'] = date
        req.params['X-Tos-Expires'] = expires
        if self.credential.get_security_token():
            req.params["X-Tos-Security-Token"] = self.credential.get_security_token()
        signed_headers = _get_signed_headers(req.headers, True)
        req.params['X-Tos-SignedHeaders'] = _get_signed_header_key(signed_headers)
        req.params['X-Tos-Signature'] = self._make_signature(req=req, date=date, signed_headers=signed_headers)

        return req.url + '?' + '&'.join(_param_to_quoted_query(k, v) for k, v in req.params.items())

    def post_sign(self, bucket: str, key: str, expires: int, conditions: [],
                  content_length_range: ContentLengthRange) -> PreSignedPostSignatureOutPut:
        date = datetime.datetime.utcnow().strftime(DATE_FORMAT)
        self.credential = self.credentials_provider.get_credentials()

        sign = PreSignedPostSignatureOutPut()
        sign.algorithm = "TOS4-HMAC-SHA256"
        sign.date = date
        sign.credential = self._credential(date)
        sign.origin_policy = _get_post_policy(date, expires, sign.algorithm, sign.credential, bucket, key,
                                              conditions, content_length_range,
                                              self.credential.get_security_token())
        sign.origin_policy = json.dumps(sign.origin_policy)
        sign.policy = base64.b64encode(sign.origin_policy.encode('utf-8')).decode('utf-8')
        sign.signature = self._make_signature(date=date, string_to_sign=sign.policy)

        return sign

    def x_tos_post_sign(self, expires: int, conditions: []):
        if expires is None:
            expires = 60 * 60
        date = datetime.datetime.utcnow().strftime(DATE_FORMAT)
        self.credential = self.credentials_provider.get_credentials()
        params = {}
        params['X-Tos-Algorithm'] = 'TOS4-HMAC-SHA256'
        params['X-Tos-Credential'] = self._credential(date)
        params['X-Tos-Date'] = date
        params['X-Tos-Expires'] = expires
        if self.credential.get_security_token():
            params["X-Tos-Security-Token"] = self.credential.get_security_token()
        params['X-Tos-Policy'] = base64.b64encode(json.dumps(_get_policy(conditions)).encode('utf-8')).decode('utf-8')
        params['X-Tos-Signature'] = self._make_x_tos_policy_signature(date=date, params=params)

        return '&'.join(_param_to_quoted_query(k, v) for k, v in params.items())

    def _make_signature(self, date, req=None, string_to_sign=None, signed_headers=None):
        if not string_to_sign:
            canonical_request = _canonical_request(req, signed_headers)
            get_logger().debug("pre-request: canonical_request:\n%s", canonical_request)
            string_to_sign = self._string_to_sign(canonical_request, date)
        get_logger().debug("pre-request: string_to_sign:\n%s", string_to_sign)
        signature = self._signature(string_to_sign, date)
        get_logger().debug("pre-request: signature:\n%s", signature)
        return signature

    def _make_x_tos_policy_signature(self, date, params):
        canonical_request = _x_tos_policy_canonical_request(params)
        get_logger().debug("pre-request: canonical_request:\n%s", canonical_request)
        string_to_sign = self._string_to_sign(canonical_request, date)
        get_logger().debug("pre-request: string_to_sign:\n%s", string_to_sign)
        signature = self._signature(string_to_sign, date)
        get_logger().debug("pre-request: signature:\n%s", signature)
        return signature

    def _inject_signature_to_request(self, signature, date, signed_headers):
        results = ['TOS4-HMAC-SHA256 Credential=%s' % self._credential(date),
                   'SignedHeaders=%s' % _get_signed_header_key(signed_headers), 'Signature=%s' % signature]
        return ', '.join(results)

    def _string_to_sign(self, canonical_request, date):
        sts = ['TOS4-HMAC-SHA256', date, self._credential_scope(date),
               sha256(canonical_request.encode('utf-8')).hexdigest()]
        return '\n'.join(sts)

    def _credential(self, date):
        return "{0}/{1}/{2}/{3}/request".format(self.credential.get_ak(), date[0:8], self.region,self.service)

    def _credential_scope(self, date):
        return "{0}/{1}/{2}/request".format(date[0:8], self.region,self.service)

    def _signature(self, string_to_sign, date):
        k_date = _sign(to_bytes(self.credential.get_sk()), date[0:8])
        k_region = _sign(k_date, self.region)
        k_service = _sign(k_region, self.service)
        k_signing = _sign(k_service, 'request')
        return _sign(k_signing, string_to_sign, hex=True)


class Auth(AuthBase):
    def __init__(self, access_key_id, access_key_secret, region, sts=None,service='tos'):
        super(Auth, self).__init__(StaticCredentialsProvider(access_key_id, access_key_secret, sts), region,service)


class CredentialProviderAuth(AuthBase):
    def __init__(self, credential_provider, region,service='tos'):
        super(CredentialProviderAuth, self).__init__(credential_provider, region,service)


class FederationAuth(AuthBase):
    def __init__(self, credentials_provider: FederationCredentials, region: str,service='tos'):
        super(FederationAuth, self).__init__(credentials_provider, region,service)


class AnonymousAuth(object):
    def __init__(self, access_key_id, access_key_secret, region, sts=None):
        self.region = region.strip()

    def sign_request(self, req):
        pass

    def sign_url(self, req, expires):
        return req.url + '?' + '&'.join(_param_to_quoted_query(k, v) for k, v in req.params.items())

    def post_sign(self, bucket: str, key: str, expires: int, conditions: [],
                  content_length_range: ContentLengthRange) -> PreSignedPostSignatureOutPut:
        date = datetime.datetime.utcnow().strftime(DATE_FORMAT)
        sign = PreSignedPostSignatureOutPut()
        sign.origin_policy = _get_post_policy(date, expires, sign.algorithm, sign.credential, bucket, key,
                                              conditions, content_length_range)
        sign.origin_policy = json.dumps(sign.origin_policy)
        sign.policy = base64.b64encode(sign.origin_policy.encode('utf-8')).decode('utf-8')

        return sign

    def x_tos_post_sign(self, expires: int, conditions: []):
        params = {'X-Tos-Policy': base64.b64encode(json.dumps(_get_policy(conditions)).encode('utf-8')).decode('utf-8')}
        return '&'.join(_param_to_quoted_query(k, v) for k, v in params.items())


def get_date(generic_input: GenericInput = None):
    if generic_input:
        if generic_input.request_date:
            return generic_input.request_date.strftime(DATE_FORMAT)
    return datetime.datetime.utcnow().strftime(DATE_FORMAT)
