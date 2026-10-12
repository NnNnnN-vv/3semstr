"""Режим ECB для AES-128 с дополнением PKCS#7

AES - блочный шифр: превращает ровно 16 байт данных в 16 байт шифротекста
ECB - способ зашифровать данные любой длины: данные режутся на блоки по 16 байт,
каждый блок шифруется отдельно одним и тем же ключом
PKCS#7 - способ довести длину данных до кратной 16 перед шифрованием

Из библиотеки берётся только шифрование одного 16-байтового блока,
разбиение на блоки, дополнение и обход блоков написаны вручную
"""

# примитив AES из pycryptodome
from Crypto.Cipher import AES

BLOCK_SIZE = 16  # размер блока AES в байтах
KEY_SIZE = 16    # размер ключа AES-128 в байтах (128 бит)


def pad(data: bytes) -> bytes:
    """Дополнение PKCS#7: в конец дописывается N байт, каждый со значением N

    Если длина уже кратна 16, дописывается целый блок из шестнадцати байт 0x10,
    иначе при расшифровании нельзя отличить дополнение от данных
    """
    # сколько байт не хватает до следующей границы блока: от 1 до 16
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE
    # bytes([n]) - один байт со значением n, умножение повторяет его n раз
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    """Проверка и удаление дополнения PKCS#7

    Последний байт говорит, сколько байт отрезать
    Все отрезаемые байты должны быть равны этому числу
    """
    # значение последнего байта = длина дополнения
    n = data[-1]
    # дополнение неверное, если длина вне диапазона 1..16
    # или последние n байт не состоят из одинаковых значений n
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid PKCS#7 padding (wrong key or corrupted data)")
    # данные без последних n байт
    return data[:-n]


def _check_key(key: bytes) -> None:
    """Проверка длины ключа: для AES-128 нужно 16 байт"""
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-128 key must be {KEY_SIZE} bytes, got {len(key)}")


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Шифрование ECB: дополнить данные, зашифровать каждый блок отдельно, склеить"""
    _check_key(key)
    # объект шифра с заданным ключом, за один вызов получает один блок
    aes = AES.new(key, AES.MODE_ECB)
    # после дополнения длина кратна 16
    padded = pad(plaintext)
    # накапливаются зашифрованные блоки
    ciphertext = bytearray()
    # i - начало очередного блока: 0, 16, 32,
    for i in range(0, len(padded), BLOCK_SIZE):
        # срез [i:i+16] - один блок, результат шифрования дописывается в конец
        ciphertext += aes.encrypt(padded[i:i + BLOCK_SIZE])
    return bytes(ciphertext)


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Расшифрование ECB: расшифровать каждый блок отдельно, склеить, снять дополнение"""
    _check_key(key)
    # правильный шифротекст не бывает пустым и всегда состоит из целых блоков
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            f"ciphertext length must be a non-zero multiple of {BLOCK_SIZE} bytes, "
            f"got {len(ciphertext)}"
        )
    aes = AES.new(key, AES.MODE_ECB)
    # накапливаются расшифрованные блоки, последний содержит дополнение
    padded = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        padded += aes.decrypt(ciphertext[i:i + BLOCK_SIZE])
    # при неверном ключе получается мусор, и проверка дополнения выдаёт ошибку
    return unpad(bytes(padded))
