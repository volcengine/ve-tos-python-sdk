import logging

from . import exceptions, models2
from .auth import Auth, FederationAuth
from .client import TosClient
from .clientv2 import TosClientV2
from .enum import *
from .utils import RateLimiter, to_bytes

logger = logging.getLogger('tos')


# def set_logger(file_path='TosClient.log', name="tos", level=logging.INFO, format_string=None):
#     global logger
#     if not format_string:
#         format_string = "%(asctime)s %(name)s [%(levelname)s] %(thread)d : %(message)s"
#     logger = logging.getLogger(name)
#     logger.setLevel(level)
#     fh = logging.FileHandler(file_path)
#     fh.setLevel(level)
#     formatter = logging.Formatter(format_string)
#     fh.setFormatter(formatter)
#     logger.addHandler(fh)
