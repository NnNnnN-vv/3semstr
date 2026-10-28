
RATE = 136        # байт сообщения на один блок (1600 - 2 * 256 бит)
DIGEST_SIZE = 32  # размер хеша в байтах
MASK64 = (1 << 64) - 1

# константы шага iota для 24 раундов
ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# сдвиги шага rho для слова с координатами (x, y), индекс x + 5 * y
ROTATIONS = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
]


# циклический сдвиг 64-битного слова влево на n бит
def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x


# перестановка Keccak-f[1600]: 24 раунда theta, rho, pi, chi, iota над 25 словами
def keccak_f(a: list) -> list:
    for rc in ROUND_CONSTANTS:
        # theta: к каждому слову добавляется чётность двух соседних столбцов
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        # rho и pi: каждое слово сдвигается и переезжает на новое место (x, y) -> (y, 2x + 3y)
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(a[x + 5 * y], ROTATIONS[x + 5 * y])
        # chi: каждое слово смешивается с двумя соседями в строке
        a = [b[i] ^ (~b[(i + 1) % 5 + i // 5 * 5] & b[(i + 2) % 5 + i // 5 * 5]) for i in range(25)]
        # iota: XOR константы раунда, чтобы раунды отличались друг от друга
        a[0] ^= rc
    return a


class SHA3_256:
    block_size = RATE
    digest_size = DIGEST_SIZE


    def __init__(self, data: bytes = b""):
        self.state = [0] * 25
        self.buffer = b""
        if data:
            self.update(data)

    # XOR в первые 17, затем перестановка
    def process_block(self, block: bytes) -> None:
        # слова в Keccak младшим байтом вперёд
        for i in range(RATE // 8):
            self.state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        self.state = keccak_f(self.state)


    @staticmethod
    def padding(tail_len: int) -> bytes:
        n = RATE - tail_len % RATE
        if n == 1:
            # 0x06 и 0x80 в 0x86
            return b"\x86"
        return b"\x06" + b"\x00" * (n - 2) + b"\x80"

    # добавление части сообщения
    def update(self, data: bytes) -> None:
        data = self.buffer + data
        full = len(data) - len(data) % RATE
        for i in range(0, full, RATE):
            self.process_block(data[i:i + RATE])
        self.buffer = data[full:]

    # итоговый хеш
    def digest(self) -> bytes:
        copy = SHA3_256()
        copy.state = list(self.state)
        copy.process_block(self.buffer + self.padding(len(self.buffer)))
        return b"".join(lane.to_bytes(8, "little") for lane in copy.state[:DIGEST_SIZE // 8])

    # итоговый хеш как hex-строка в нижнем регистре
    def hexdigest(self) -> str:
        return self.digest().hex()

    # хеш данных целиком одним вызовом
    def hash(self, data: bytes) -> str:
        self.update(data)
        return self.hexdigest()
