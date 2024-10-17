import threading
import time


class SafeMapFIFO:
    def __init__(self, max_length: int = 100, default_expiration_sec: int = 60):
        self.map = {}
        self.lock = threading.Lock()
        self.max_length = max_length
        self.default_expiration_sec = default_expiration_sec

    def _clean_expired_keys(self):
        current_time = time.time()
        with self.lock:
            keys_to_delete = [key for key, value in self.map.items() if
                              current_time - value['insert_time'] > value['expiration']]
            for key in keys_to_delete:
                del self.map[key]

    def put(self, key, value, expiration_time=None):
        with self.lock:
            if len(self.map) >= self.max_length:
                # 达到最大长度，删除最早插入的元素
                oldest_key = min(self.map.keys(), key=lambda k: self.map[k]['insert_time'])
                del self.map[oldest_key]
            now = time.time()
            expiration = expiration_time if expiration_time else self.default_expiration_sec
            self.map[key] = {'value': value, 'insert_time': now, 'expiration': expiration}

    def get(self, key):
        with self.lock:
            if key in self.map:
                item = self.map[key]
                if time.time() - item['insert_time'] <= item['expiration']:
                    return item['value']
                else:
                    del self.map[key]  # 过期删除
            return None

    def delete(self, key):
        with self.lock:
            if key in self.map:
                del self.map[key]

    def has_key(self, key):
        with self.lock:
            return key in self.map

    def items(self):
        with self.lock:
            current_time = time.time()
            return [(k, v['value']) for k, v in self.map.items() if current_time - v['insert_time'] <= v['expiration']]
