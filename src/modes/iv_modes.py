from Crypto.Cipher import AES

# общий генератор случайных байт проекта
from ..csprng import generate_random_bytes
from .ecb import BLOCK_SIZE, _check_key, pad, unpad

IV_SIZE = BLOCK_SIZE  # IV всегда равен размеру блока AES: 16 байт


def generate_iv() -> bytes:
    return generate_random_bytes(IV_SIZE)


# XOR двух строк байтов
def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# разбиение данных на блоки
def _blocks(data: bytes):
    for i in range(0, len(data), BLOCK_SIZE):
        yield data[i:i + BLOCK_SIZE]


# проверка длины ключа и IV, создание объекта шифра для одиночных блоков
def _aes(key: bytes, iv: bytes):
    _check_key(key)
    if len(iv) != IV_SIZE:
        raise ValueError(f"IV must be {IV_SIZE} bytes, got {len(iv)}")
    return AES.new(key, AES.MODE_ECB)


# CBC: C[i] = AES(P[i] ^ C[i-1]), вместо C[0-1] берётся IV
def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = _aes(key, iv)
    ciphertext = bytearray()
    previous = iv
    for block in _blocks(pad(plaintext)):
        previous = aes.encrypt(_xor(block, previous))
        ciphertext += previous
    return bytes(ciphertext)


# CBC: P[i] = (расшифровка AES(C[i])) ^ C[i-1]
def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    aes = _aes(key, iv)
    # шифротекст CBC не бывает пустым и всегда  из целых блоков
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            f"ciphertext length must be a non-zero multiple of {BLOCK_SIZE} bytes, "
            f"got {len(ciphertext)}"
        )
    padded = bytearray()
    previous = iv
    for block in _blocks(ciphertext):
        padded += _xor(aes.decrypt(block), previous)
        previous = block
    return unpad(bytes(padded))


# CFB: C[i] = P[i] ^ AES(C[i-1]), вместо C[0-1] берётся IV
def cfb_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = _aes(key, iv)
    ciphertext = bytearray()
    feedback = iv
    for block in _blocks(plaintext):
        encrypted = _xor(block, aes.encrypt(feedback))
        ciphertext += encrypted
        feedback = encrypted
    return bytes(ciphertext)


# CFB: P[i] = C[i] ^ AES(C[i-1])
def cfb_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    aes = _aes(key, iv)
    plaintext = bytearray()
    feedback = iv
    for block in _blocks(ciphertext):
        plaintext += _xor(block, aes.encrypt(feedback))
        # в обратную связь идёт блок шифротекста, а не результат
        feedback = block
    return bytes(plaintext)


# OFB: O[i] = AES(O[i-1]), O[0-1] = IV, результат[i] = данные[i] ^ O[i]

def ofb_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    aes = _aes(key, iv)
    result = bytearray()
    keystream = iv
    for block in _blocks(data):
        keystream = aes.encrypt(keystream)
        result += _xor(block, keystream)
    return bytes(result)


# CTR: результат[i] = данные[i] ^ AES(счётчик + i), начальный счётчик = IV

def ctr_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    aes = _aes(key, iv)
    result = bytearray()
    counter = int.from_bytes(iv, "big")
    for block in _blocks(data):
        result += _xor(block, aes.encrypt(counter.to_bytes(BLOCK_SIZE, "big")))
        counter = (counter + 1) % (1 << (8 * BLOCK_SIZE))
    return bytes(result)

MODES = {
    "cbc": (cbc_encrypt, cbc_decrypt),
    "cfb": (cfb_encrypt, cfb_decrypt),
    "ofb": (ofb_crypt, ofb_crypt),
    "ctr": (ctr_crypt, ctr_crypt),
}
