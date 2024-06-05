import logging

OFF = 60
CRITICAL = 50
FATAL = CRITICAL
ERROR = 40
WARNING = 30
WARN = WARNING
INFO = 20
DEBUG = 10
NOTSET = 0

logger = logging.getLogger('tos')


def set_logger(file_path='TosClient.log', name="tos", level=INFO, format_string=None, log_handler=None):
    global logger
    if not format_string:
        format_string = "%(asctime)s %(name)s [%(levelname)s] %(thread)d : %(message)s"
    logger = logging.getLogger(name)
    logger.setLevel(level)
    fh = log_handler
    if fh is None:
        fh = logging.FileHandler(file_path)
    fh.setLevel(level)
    formatter = logging.Formatter(format_string)
    fh.setFormatter(formatter)
    logger.addHandler(fh)


def get_logger():
    return logger
