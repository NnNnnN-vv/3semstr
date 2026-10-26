from Crypto.Cipher import AES

from ..modes.ecb import BLOCK_SIZE, _check_key

RB = 0x87  # константа для 128-битного блока из SP 800-38B


def _double(block: bytes) -> bytes:
    value = int.from_bytes(block, "big") << 1
    if value >> 128:
        value = (value & ((1 << 128) - 1)) ^ RB
    return value.to_bytes(BLOCK_SIZE, "big")


# XOR двух блоков одинаковой длины
def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# подключи K1 и K2 из ключа AES
def generate_subkeys(aes) -> tuple:
    l_block = aes.encrypt(b"\x00" * BLOCK_SIZE)
    k1 = _double(l_block)
    k2 = _double(k1)
    return k1, k2


class CMAC:
    def __init__(self, key: bytes):
        _check_key(key)
        self._aes = AES.new(key, AES.MODE_ECB)
        self.k1, self.k2 = generate_subkeys(self._aes)
        self._state = b"\x00" * BLOCK_SIZE
        self._buffer = b""


    def update(self, data: bytes) -> None:
        data = self._buffer + data
        end = (len(data) - 1) // BLOCK_SIZE * BLOCK_SIZE if data else 0
        for i in range(0, end, BLOCK_SIZE):
            self._state = self._aes.encrypt(_xor(self._state, data[i:i + BLOCK_SIZE]))
        self._buffer = data[end:]

    # итоговый MAC
    def digest(self) -> bytes:
        if len(self._buffer) == BLOCK_SIZE:
            last = _xor(self._buffer, self.k1)
        else:
            padded = self._buffer + b"\x80" + b"\x00" * (BLOCK_SIZE - len(self._buffer) - 1)
            last = _xor(padded, self.k2)
        return self._aes.encrypt(_xor(self._state, last))

    # итоговый MAC как hex-строка в нижнем регистре
    def hexdigest(self) -> str:
        return self.digest().hex()

    # MAC сообщения
    def compute(self, message: bytes) -> str:
        self.update(message)
        return self.hexdigest()
