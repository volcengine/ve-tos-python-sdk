# -*- coding: utf-8 -*-
import datetime
import hmac
import logging
from hashlib import sha256
from urllib.parse import quote

from .consts import DATE_FORMAT, UNSIGNED_PAYLOAD
from .credential import FederationCredentials, StaticCredentials
from .utils import to_bytes

logger = logging.getLogger(__name__)


def _canonical_query_string_params(params):
    results = []
    for param in sorted(params):
        value = str(params[param])
        results.append('%s=%s' % (quote(param, safe='-_.~'),
                                  quote(value, safe='-_.~')))
    cqs = '&'.join(results)
    return cqs


def _signed_headers(headers):
    hl = sorted(headers.items(), key=lambda d: d[0].lower())
    vl = []
    for v in hl:
        vl.append(v[0].lower())
    return ';'.join(vl)


def _canonical_headers(headers):
    hl = sorted(headers.items(), key=lambda d: d[0].lower())
    s = ''
    for val in hl:
        if isinstance(val[1], list):
            tlist = sorted(val[1])
            for v in tlist:
                s += val[0] + ':' + v + '\n'
        else:
            s += val[0].lower() + ':' + str(val[1]) + '\n'
    return s


def _canonical_request(req):
    cr = [req.method.upper(), quote(req.path, safe='/~'), _canonical_query_string_params(req.params),
          _canonical_headers(req.headers), _signed_headers(req.headers)]
    if req.headers.get('x-tos-content-sha256'):
        cr.append(req.headers['x-tos-content-sha256'])
    else:
        cr.append(UNSIGNED_PAYLOAD)
    return '\n'.join(cr)


def _param_to_quoted_query(k, v):
    if v:
        return quote(str(k), '') + '=' + quote(str(v), '')
    else:
        return quote(k, '/~')


def _sign(key, msg, hex=False):
    if hex:
        sig = hmac.new(key, msg.encode('utf-8'), sha256).hexdigest()
    else:
        sig = hmac.new(key, msg.encode('utf-8'), sha256).digest()
    return sig


class AuthBase():
    def __init__(self, credentials_provider, region):
        self.credentials_provider = credentials_provider
        self.region = region.strip()
        self.credential = None

    def sign_request(self, req):
        self.credential = self.credentials_provider.get_credentials()
        if self.credential.get_security_token():
            req.headers["x-tos-security-token"] = self.credential.get_security_token()

        date = datetime.datetime.utcnow().strftime(DATE_FORMAT)
        req.headers['Date'] = date
        req.headers['x-tos-date'] = date

        signature = self._make_signature(req, date)
        req.headers['Authorization'] = self._inject_signature_to_request(req, signature, date)

    def sign_url(self, req, expires):
        if expires is None:
            expires = 60 * 60
        date = datetime.datetime.utcnow().strftime(DATE_FORMAT)
        self.credential = self.credentials_provider.get_credentials()

        req.params['X-Tos-Algorithm'] = 'TOS4-HMAC-SHA256'
        req.params['X-Tos-Credential'] = self._credential(date)
        req.params['X-Tos-Date'] = date
        req.params['X-Tos-Expires'] = expires
        req.params['X-Tos-SignedHeaders'] = _signed_headers(req.headers)

        if self.credential.get_security_token():
            req.params["X-Tos-Security-Token"] = self.credential.get_security_token()
        req.params['X-Tos-Signature'] = self._make_signature(req, date)

        return req.url + '?' + '&'.join(_param_to_quoted_query(k, v) for k, v in req.params.items())

    def _make_signature(self, req, date):
        canonical_request = _canonical_request(req)
        logger.debug("pre-request: canonical_request:\n%s", canonical_request)
        string_to_sign = self._string_to_sign(canonical_request, date)
        logger.debug("pre-request: string_to_sign:\n%s", string_to_sign)
        signature = self._signature(string_to_sign, date)
        logger.debug("pre-request: signature:\n%s", signature)
        return signature

    def _inject_signature_to_request(self, req, signature, date):
        results = ['TOS4-HMAC-SHA256 Credential=%s' % self._credential(date),
                   'SignedHeaders=%s' % _signed_headers(req.headers), 'Signature=%s' % signature]
        return ', '.join(results)

    def _string_to_sign(self, canonical_request, date):
        sts = ['TOS4-HMAC-SHA256', date, self._credential_scope(date),
               sha256(canonical_request.encode('utf-8')).hexdigest()]
        return '\n'.join(sts)

    def _credential(self, date):
        return "{0}/{1}/{2}/tos/request".format(self.credential.get_access_key_id(), date[0:8], self.region)

    def _credential_scope(self, date):
        return "{0}/{1}/tos/request".format(date[0:8], self.region)

    def _signature(self, string_to_sign, date):
        k_date = _sign(to_bytes(self.credential.get_access_key_secret()), date[0:8])
        k_region = _sign(k_date, self.region)
        k_service = _sign(k_region, 'tos')
        k_signing = _sign(k_service, 'request')
        return _sign(k_signing, string_to_sign, hex=True)

    def copy(self):
        if not isinstance(self.credentials_provider, StaticCredentials):
            return None
        provider = self.credentials_provider.credentials
        return provider.access_key_id, provider.access_key_secret, provider.security_token, self.region


class Auth(AuthBase):
    def __init__(self, access_key_id, access_key_secret, region, sts=None):
        super(Auth, self).__init__(StaticCredentials(access_key_id, access_key_secret, sts), region)


class FederationAuth(AuthBase):
    def __init__(self, credentials_provider: FederationCredentials, region: str):
        super(FederationAuth, self).__init__(credentials_provider, region)
