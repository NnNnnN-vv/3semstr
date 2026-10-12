"""Режимы CBC, CFB, OFB и CTR для AES-128

В ECB одинаковые блоки открытого текста дают одинаковые блоки шифротекста

Эти четыре режима устраняют это с помощью IV (вектор инициализации) - 16 случайных байт,
которые подмешиваются в шифрование, IV не секретен и хранится рядом с шифротекстом

CBC - блочный режим: данные дополняются по PKCS#7, длина шифротекста кратна 16
CFB, OFB, CTR - потоковые режимы: AES вырабатывает гамму (поток псевдослучайных байт),
данные складываются с ней по XOR, дополнение не нужно, длина шифротекста = длине данных

XOR (исключающее ИЛИ) обратим: (a ^ b) ^ b = a,
поэтому повторное наложение той же гаммы возвращает исходные данные

"""

import os


from Crypto.Cipher import AES


from .ecb import BLOCK_SIZE, _check_key, pad, unpad

IV_SIZE = BLOCK_SIZE  # IV всегда равен размеру блока AES: 16 байт


def generate_iv() -> bytes:
    """Случайный IV из криптографически стойкого генератора операционной системы"""
    return os.urandom(IV_SIZE)


def _xor(a: bytes, b: bytes) -> bytes:
    """Побайтовый XOR двух строк байтов

    zip останавливается на короткой строке, поэтому неполный последний блок
    складывается только с началом блока гаммы и не меняет размер
    """
    return bytes(x ^ y for x, y in zip(a, b))


def _blocks(data: bytes):
    """Разбиение данных на блоки по 16 байт, последний может быть короче"""
    for i in range(0, len(data), BLOCK_SIZE):
        yield data[i:i + BLOCK_SIZE]


def _aes(key: bytes, iv: bytes):
    """Проверка длины ключа и IV, создание объекта шифра для одиночных блоков"""
    _check_key(key)
    if len(iv) != IV_SIZE:
        raise ValueError(f"IV must be {IV_SIZE} bytes, got {len(iv)}")
    return AES.new(key, AES.MODE_ECB)


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """CBC: C[i] = AES(P[i] ^ C[i-1]), вместо C[0-1] берётся IV

    Перед шифрованием блок складывается с предыдущим блоком шифротекста,
    поэтому каждый блок шифротекста зависит от всех предыдущих блоков
    """
    aes = _aes(key, iv)
    ciphertext = bytearray()
    # предыдущий блок шифротекста, для первого блока это IV
    previous = iv
    for block in _blocks(pad(plaintext)):
        previous = aes.encrypt(_xor(block, previous))
        ciphertext += previous
    return bytes(ciphertext)


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """CBC: P[i] = (расшифровка AES(C[i])) ^ C[i-1], затем снимается дополнение"""
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


def cfb_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """CFB: C[i] = P[i] ^ AES(C[i-1]), вместо C[0-1] берётся IV

    Гамма для блока получается шифрованием предыдущего блока шифротекста
    """
    aes = _aes(key, iv)
    ciphertext = bytearray()
    # регистр обратной связи: то, что шифруется для получения гаммы
    feedback = iv
    for block in _blocks(plaintext):
        encrypted = _xor(block, aes.encrypt(feedback))
        ciphertext += encrypted
        # в обратную связь идёт только что полученный блок шифротекста
        feedback = encrypted
    return bytes(ciphertext)


def cfb_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """CFB: P[i] = C[i] ^ AES(C[i-1])

    гамма должна получиться той же самой
    """
    aes = _aes(key, iv)
    plaintext = bytearray()
    feedback = iv
    for block in _blocks(ciphertext):
        plaintext += _xor(block, aes.encrypt(feedback))
        # в обратную связь идёт блок шифротекста, а не результат
        feedback = block
    return bytes(plaintext)


def ofb_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """OFB: O[i] = AES(O[i-1]), O[0-1] = IV, результат[i] = данные[i] ^ O[i]

    Гамма получается повторным шифрованием собственного выхода и не зависит от данных
    """
    aes = _aes(key, iv)
    result = bytearray()
    # текущий блок гаммы
    keystream = iv
    for block in _blocks(data):
        keystream = aes.encrypt(keystream)
        result += _xor(block, keystream)
    return bytes(result)


def ctr_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """CTR: результат[i] = данные[i] ^ AES(счётчик + i), начальный счётчик = IV

    Гамма получается шифрованием счётчика, который растёт на 1 для каждого блока
    Гамма не зависит от данных, шифрование и расшифрование - одна и та же операция
    """
    aes = _aes(key, iv)
    result = bytearray()
    # IV читается как одно 128-битное число, старший байт первый
    counter = int.from_bytes(iv, "big")
    for block in _blocks(data):
        result += _xor(block, aes.encrypt(counter.to_bytes(BLOCK_SIZE, "big")))
        # увеличение счётчика, после максимального значения он снова становится нулём
        counter = (counter + 1) % (1 << (8 * BLOCK_SIZE))
    return bytes(result)

MODES = {
    "cbc": (cbc_encrypt, cbc_decrypt),
    "cfb": (cfb_encrypt, cfb_decrypt),
    "ofb": (ofb_crypt, ofb_crypt),
    "ctr": (ctr_crypt, ctr_crypt),
}
