from . import exceptions, models2, log
from .auth import Auth, FederationAuth
from .client import TosClient
from .clientv2 import TosClientV2
from .enum import *
from .utils import RateLimiter, to_bytes, DnsCacheService
from .credential import StaticCredentialsProvider, EcsCredentialsProvider, EnvCredentialsProvider
from .vector_client import VectorClient


def set_logger(file_path='TosClient.log', name="tos", level=log.INFO, format_string=None, log_handler=None):
    log.set_logger(file_path, name, level, format_string, log_handler)
