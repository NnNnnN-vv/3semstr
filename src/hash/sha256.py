import struct

BLOCK_SIZE = 64   # размер блока в байтах
DIGEST_SIZE = 32   # размер хеша в байтах
MASK = 0xFFFFFFFF  # все вычисления по модулю 2^32

# начальное состояние
H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]


K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


# сдвиг 32-битного слова вправо на n бит
def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK


class SHA256:
    block_size = BLOCK_SIZE
    digest_size = DIGEST_SIZE

    def __init__(self, data: bytes = b""):
        self.h = list(H0)
        self.k = K
        self.buffer = b""
        self.length = 0
        if data:
            self.update(data)

    # дополнение для сообщения длиной message_len байт: 0x80, нули и длина в битах
    @staticmethod
    def padding(message_len: int) -> bytes:
        zeros = (BLOCK_SIZE - (message_len + 1 + 8) % BLOCK_SIZE) % BLOCK_SIZE
        return b"\x80" + b"\x00" * zeros + (message_len * 8).to_bytes(8, "big")

    # функция сжатия
    def process_block(self, block: bytes) -> None:
        # 16 слов из блока, остальные 48 вычисляются из предыдущих
        w = list(struct.unpack(">16I", block))
        for t in range(16, 64):
            x, y = w[t - 15], w[t - 2]
            s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
            s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10)
            w.append((w[t - 16] + s0 + w[t - 7] + s1) & MASK)

        a, b, c, d, e, f, g, h = self.h
        for kt, wt in zip(self.k, w):
            # Σ1, Ch (выбор: где бит e = 1, берётся бит f, иначе бит g)
            big_s1 = ((e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7)) & MASK
            ch = (e & f) ^ (~e & g)
            t1 = h + big_s1 + ch + kt + wt
            # Σ0, Maj (большинство: бит, который есть хотя бы в двух из a, b, c)
            big_s0 = ((a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10)) & MASK
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = big_s0 + maj
            # слова сдвигаются на одну позицию, в a и e приходят новые значения
            h, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK, c, b, a, (t1 + t2) & MASK

        # результат раундов прибавляется к старому состоянию
        self.h = [(x + y) & MASK for x, y in zip(self.h, (a, b, c, d, e, f, g, h))]

    # добавление очередной части сообщения
    def update(self, data: bytes) -> None:
        self.length += len(data)
        data = self.buffer + data
        # обрабатываются только целые блоки, остаток ждёт следующего вызова
        full = len(data) - len(data) % BLOCK_SIZE
        for i in range(0, full, BLOCK_SIZE):
            self.process_block(data[i:i + BLOCK_SIZE])
        self.buffer = data[full:]

    # итоговый хеш
    def digest(self) -> bytes:
        copy = SHA256()
        copy.h, copy.buffer, copy.length = list(self.h), self.buffer, self.length
        tail = copy.buffer + self.padding(copy.length)
        for i in range(0, len(tail), BLOCK_SIZE):
            copy.process_block(tail[i:i + BLOCK_SIZE])
        return b"".join(x.to_bytes(4, "big") for x in copy.h)

    # итоговый хеш как hex-строка в нижнем регистре
    def hexdigest(self) -> str:
        return self.digest().hex()

    # хеш данных целиком одним вызовом, как в примере из задания
    def hash(self, data: bytes) -> str:
        self.update(data)
        return self.hexdigest()
