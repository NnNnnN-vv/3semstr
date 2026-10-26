
from Crypto.Cipher import AES

BLOCK_SIZE = 16  # размер блока AES в байтах
KEY_SIZE = 16    # размер ключа AES-128 в байтах


def pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([n]) * n


# проверка и удаление дополнения PKCS#7
def unpad(data: bytes) -> bytes:
    n = data[-1]
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid PKCS#7 padding (wrong key or corrupted data)")
    return data[:-n]


# проверка длины ключа
def _check_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-128 key must be {KEY_SIZE} bytes, got {len(key)}")


# шифрование ECB
def encrypt(key: bytes, plaintext: bytes) -> bytes:
    _check_key(key)
    # объект шифра с заданным ключом, за один вызов получает один блок
    aes = AES.new(key, AES.MODE_ECB)
    # после дополнения длина кратна 16
    padded = pad(plaintext)
    # накапливаются зашифрованные блоки
    ciphertext = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        # срез [i:i+16] - один блок, результат шифрования дописывается в конец
        ciphertext += aes.encrypt(padded[i:i + BLOCK_SIZE])
    return bytes(ciphertext)


# расшифрование ECB
def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    _check_key(key)
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            f"ciphertext length must be a non-zero multiple of {BLOCK_SIZE} bytes, "
            f"got {len(ciphertext)}"
        )
    aes = AES.new(key, AES.MODE_ECB)
    padded = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        padded += aes.decrypt(ciphertext[i:i + BLOCK_SIZE])
    return unpad(bytes(padded))
