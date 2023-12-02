import threading

_thread_ctx = threading.local()


def consume_body():
    current = 0
    if hasattr(_thread_ctx, 'body'):
        current = int(_thread_ctx.body)
        del _thread_ctx.body
    return current


def produce_body(val):
    current = int(val)
    if hasattr(_thread_ctx, 'body'):
        current += int(_thread_ctx.body)
    _thread_ctx.body = current
