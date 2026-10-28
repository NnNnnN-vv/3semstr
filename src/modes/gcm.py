from Crypto.Cipher import AES

from ..aead import AuthenticationError
from ..csprng import generate_random_bytes
from ..mac import constant_time_equal
from .ecb import BLOCK_SIZE, _check_key

NONCE_SIZE = 12
TAG_SIZE = 16
R = 0xE1 << 120  # x^128 + x^7 + x^2 + x + 1 в битовом порядке GCM
MASK128 = (1 << 128) - 1


# умножение в GF(2^128) по биту, как в SP 800-38D
def gf_mult(x: int, y: int) -> int:
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ R if v & 1 else v >> 1
    return z


# таблицы для умножения на H
# table[i][b] = (байт b на позиции i) * H
def _make_table(h: int) -> list:
    powers = []
    v = h
    for _ in range(128):
        powers.append(v)
        v = (v >> 1) ^ R if v & 1 else v >> 1
    table = []
    for i in range(16):
        row = [0] * 256
        for b in range(1, 256):
            low = b & -b
            row[b] = row[b ^ low] ^ powers[8 * i + 7 - low.bit_length() + 1]
        table.append(row)
    return table


class _GHash:
    # GHASH с нулевым начальным значением и буфером неполного блока
    def __init__(self, table: list):
        self.table = table
        self.y = 0
        self.buffer = b""

    # умножение x на H по таблицам: 16 поисков вместо 128 шагов
    def _mult(self, x: int) -> int:
        z = 0
        for i, row in enumerate(self.table):
            z ^= row[(x >> (120 - 8 * i)) & 0xFF]
        return z

    # Y = (Y ^ блок) * H для каждого полного блока
    def update(self, data: bytes) -> None:
        data = self.buffer + data
        end = len(data) - len(data) % BLOCK_SIZE
        for i in range(0, end, BLOCK_SIZE):
            self.y = self._mult(self.y ^ int.from_bytes(data[i:i + BLOCK_SIZE], "big"))
        self.buffer = data[end:]

    # дополнение нулями до границы блока
    def flush(self) -> None:
        if self.buffer:
            self.update(b"\x00" * (BLOCK_SIZE - len(self.buffer)))


class GCM:
    # ключ AES-128, nonce (по умолчанию случайный, 12 байт), таблицы для H = AES(0)
    def __init__(self, key: bytes, nonce: bytes = None):
        _check_key(key)
        self.aes = AES.new(key, AES.MODE_ECB)
        self.nonce = nonce if nonce is not None else generate_random_bytes(NONCE_SIZE)
        if not self.nonce:
            raise ValueError("nonce must not be empty")
        self.table = _make_table(int.from_bytes(self.aes.encrypt(bytes(BLOCK_SIZE)), "big"))

    # начальный счётчик J0: nonce || 0...01 для 12 байт, иначе GHASH(nonce)
    def _j0(self) -> int:
        if len(self.nonce) == NONCE_SIZE:
            return int.from_bytes(self.nonce + b"\x00\x00\x00\x01", "big")
        g = _GHash(self.table)
        g.update(self.nonce)
        g.flush()
        g.update(bytes(8) + (len(self.nonce) * 8).to_bytes(8, "big"))
        return g.y

    # CTR с 32-битным счётчиком в младших байтах, начиная с J0 + 1
    def _ctr(self, j0: int, data: bytes) -> bytes:
        result = bytearray()
        high = j0 & ~0xFFFFFFFF & MASK128
        counter = j0 & 0xFFFFFFFF
        for i in range(0, len(data), BLOCK_SIZE):
            counter = (counter + 1) & 0xFFFFFFFF
            block = self.aes.encrypt((high | counter).to_bytes(BLOCK_SIZE, "big"))
            result += bytes(a ^ b for a, b in zip(data[i:i + BLOCK_SIZE], block))
        return bytes(result)

    # тег: GHASH(AAD, C, длины) ^ AES(J0); aad - байты или куски байтов
    def _tag(self, j0: int, aad, ciphertext: bytes) -> bytes:
        g = _GHash(self.table)
        aad_len = 0
        for chunk in ([aad] if isinstance(aad, (bytes, bytearray)) else aad):
            g.update(bytes(chunk))
            aad_len += len(chunk)
        g.flush()
        g.update(ciphertext)
        g.flush()
        g.update((aad_len * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big"))
        s = int.from_bytes(self.aes.encrypt(j0.to_bytes(BLOCK_SIZE, "big")), "big")
        return (g.y ^ s).to_bytes(BLOCK_SIZE, "big")

    # шифрование: шифротекст и тег
    def seal(self, plaintext: bytes, aad=b"") -> tuple:
        j0 = self._j0()
        ciphertext = self._ctr(j0, plaintext)
        return ciphertext, self._tag(j0, aad, ciphertext)

    # тег проверяется до расшифрования, при несовпадении открытый текст не считается
    def open(self, ciphertext: bytes, tag: bytes, aad=b"") -> bytes:
        j0 = self._j0()
        if not constant_time_equal(self._tag(j0, aad, ciphertext), tag):
            raise AuthenticationError("Authentication failed: AAD mismatch or ciphertext tampered")
        return self._ctr(j0, ciphertext)

    # nonce || C || tag
    def encrypt(self, plaintext: bytes, aad=b"") -> bytes:
        ciphertext, tag = self.seal(plaintext, aad)
        return self.nonce + ciphertext + tag

    # расшифрование nonce || C || tag
    def decrypt(self, data: bytes, aad=b"") -> bytes:
        n = len(self.nonce)
        if len(data) < n + TAG_SIZE:
            raise AuthenticationError("Authentication failed: data is too short")
        self.nonce = data[:n]
        return self.open(data[n:-TAG_SIZE], data[-TAG_SIZE:], aad)
