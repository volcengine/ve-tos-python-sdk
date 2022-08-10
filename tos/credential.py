import logging
import threading
import time

logger = logging.getLogger(__name__)

DEFAULT_FETCH_TIME = 5 * 60


class Credentials():
    def __init__(self, access_key_id, access_key_secret, security_token=None):
        self.access_key_id = access_key_id.strip()
        self.access_key_secret = access_key_secret.strip()
        self.security_token = security_token

    def get_access_key_id(self):
        return self.access_key_id

    def get_access_key_secret(self):
        return self.access_key_secret

    def get_security_token(self):
        return self.security_token


class CredentialsProvider():
    def get_credentials(self):
        return

    def copy(self):
        return


class StaticCredentials(CredentialsProvider):
    def __init__(self, access_key_id, access_key_secret, security_token=None):
        self.credentials = Credentials(access_key_id, access_key_secret, security_token)

    def get_credentials(self):
        return self.credentials

    def copy(self):
        return Credentials(self.credentials.access_key_id, self.credentials.access_key_secret,
                           self.credentials.security_token)


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
