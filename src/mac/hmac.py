from ..hash import ALGORITHMS

IPAD = 0x36
OPAD = 0x5C


# побайтовый XOR ключа с повторённым байтом
def _xor_with(key: bytes, pad_byte: int) -> bytes:
    return bytes(b ^ pad_byte for b in key)


# сравнение
def constant_time_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


class HMAC:

    def __init__(self, key: bytes, hash_function: str = "sha256"):
        self.hash_function = ALGORITHMS[hash_function]
        self.block_size = self.hash_function.block_size
        self.key = self._process_key(key)
        self._inner = self.hash_function(_xor_with(self.key, IPAD))

    # ключ: длинный хешируется, короткий дополняется нулями
    def _process_key(self, key: bytes) -> bytes:
        if len(key) > self.block_size:
            key = self.hash_function(key).digest()
        return key + b"\x00" * (self.block_size - len(key))


    def update(self, data: bytes) -> None:
        self._inner.update(data)

    # итоговый MAC в байтах
    def digest(self) -> bytes:
        inner_hash = self._inner.digest()
        outer = self.hash_function(_xor_with(self.key, OPAD))
        outer.update(inner_hash)
        return outer.digest()

    # итоговый MAC как hex-строка в нижнем регистре
    def hexdigest(self) -> str:
        return self.digest().hex()

    def compute(self, message: bytes) -> str:
        self.update(message)
        return self.hexdigest()
