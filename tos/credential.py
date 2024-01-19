import logging
import os
import threading
import time
from datetime import datetime, timedelta

import requests
from deprecated import deprecated
from tos.consts import ECS_DATE_FORMAT

from tos.exceptions import TosClientError

logger = logging.getLogger(__name__)

DEFAULT_FETCH_TIME = 5 * 60


class Credentials():
    def __init__(self, access_key_id, access_key_secret, security_token=None):
        self.access_key_id = access_key_id.strip()
        self.access_key_secret = access_key_secret.strip()
        self.security_token = security_token

    def get_ak(self):
        return self.access_key_id

    def get_sk(self):
        return self.access_key_secret

    def get_security_token(self):
        return self.security_token

    @deprecated(version='2.6.6', reason="please use get_ak")
    def get_access_key_id(self):
        return self.get_ak()

    @deprecated(version='2.6.6', reason="please use get_sk")
    def get_access_key_secret(self):
        return self.get_sk()


class CredentialsProvider():
    def get_credentials(self):
        return


class StaticCredentials(CredentialsProvider):
    """
    This class is deprecated and should not be used anymore.
    """
    @deprecated(version='2.6.6', reason="please use StaticCredentialsProvider")
    def __init__(self, access_key_id, access_key_secret, security_token=None):
        self.credentials = Credentials(access_key_id, access_key_secret, security_token)

    @deprecated(version='2.6.6', reason="please use StaticCredentialsProvider")
    def get_credentials(self):
        return self.credentials


class FederationToken():
    def __init__(self, access_key_id, access_key_secret, security_token, expiration, pre_fetch_sec=DEFAULT_FETCH_TIME):
        self.credential = Credentials(access_key_id, access_key_secret, security_token)
        self.expiration = expiration
        self.pre_fetch_sec = pre_fetch_sec

    def get_credentials(self):
        return self.credential

    def will_soon_expire(self):
        now = int(time.time())
        return now + self.pre_fetch_sec - self.expiration > 0

    def expire(self):
        return int(time.time()) > self.expiration


class FederationCredentials(CredentialsProvider):
    def __init__(self, get_credentials_func):
        self.get_credentials_func = get_credentials_func
        self.federationToken = None
        self.refreshing = 0
        self.__lock = threading.Lock()

    def get_credentials(self):
        # 不存在或者已经过期直接获取token
        if self.federationToken is None or self.federationToken.expire():
            return self._try_get_credential()
        # 快要过期且没有其他正在获取token的任务时，尝试去获取token
        if self.federationToken.will_soon_expire() and self.refreshing == 0:
            return self._try_get_credential()
        return self.federationToken.get_credentials()

    def _try_get_credential(self):
        with self.__lock:
            try:
                self.refreshing = 1
                # 再判断一次，因为可能已经被更新过了
                if self.federationToken is None or self.federationToken.will_soon_expire():
                    self.federationToken = self.get_credentials_func()
            except Exception as e:
                logger.error("get_credentials error: {0}".format(e))
                if self.federationToken is None:
                    raise
            finally:
                self.refreshing = 0
        return self.federationToken.get_credentials()


class StaticCredentialsProvider(CredentialsProvider):
    def __init__(self, access_key_id, access_key_secret, security_token=None):
        self.credentials = Credentials(access_key_id, access_key_secret, security_token)

    def get_credentials(self):
        return self.credentials


class EnvCredentialsProvider(CredentialsProvider):
    def __init__(self):
        access_key = os.environ.get('TOS_ACCESS_KEY')
        secret_key = os.environ.get('TOS_SECRET_KEY')
        security_token = os.environ.get('TOS_SECURITY_TOKEN')

        if access_key is None or secret_key is None:
            raise TosClientError('ak or sk is empty')

        self.credentials = Credentials(access_key, secret_key, security_token)

    def get_credentials(self):
        return self.credentials


class EcsCredentialsProvider(CredentialsProvider):
    ecs_url = 'http://100.96.0.96/volcstack/latest/iam/security_credentials/{}'

    def __init__(self, role_name):
        if role_name == '':
            raise TosClientError('ecs role name is empty')
        self._lock = threading.Lock()
        self.expires = None
        self.credentials = None
        self._ecs_url = EcsCredentialsProvider.ecs_url.format(role_name)

    def get_credentials(self):
        res = self._try_get_credentials()
        if res is not None:
            return res
        with self._lock:
            try:
                res = self._try_get_credentials()
                if res is not None:
                    return res

                res = requests.get(self._ecs_url, timeout=30)
                res_body = res.json()
                self.credentials = Credentials(res_body.get('AccessKeyId'), res_body.get('SecretAccessKey'),
                                               res_body.get('SessionToken'))
                self.expires = datetime.strptime(res_body.get('ExpiredTime'), ECS_DATE_FORMAT)
                return self.credentials
            except Exception as e:
                if self.expires is not None and datetime.now().timestamp() < self.expires.timestamp():
                    return self.credentials
                raise TosClientError('get ecs token failed', e)

    def _try_get_credentials(self):
        if self.expires is None or self.credentials is None:
            return None
        if datetime.now().timestamp() > (self.expires - timedelta(minutes=10)).timestamp():
            return None
        return self.credentials
