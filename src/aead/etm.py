from ..mac import HMAC, constant_time_equal
from ..modes import iv_modes

TAG_SIZE = 32  # HMAC-SHA256


class AuthenticationError(Exception):
    """тег не совпал: неверный ключ, AAD или данные изменены"""

# два независимых ключа из мастер-ключа: K_e для AES-CTR, K_m для HMAC
def derive_keys(master_key: bytes) -> tuple:
    k_e = HMAC(master_key).compute(b"cryptocore encryption")
    k_m = HMAC(master_key).compute(b"cryptocore authentication")
    return bytes.fromhex(k_e)[:16], bytes.fromhex(k_m)


class EncryptThenMac:
    # ключи K_e и K_m из ключа
    def __init__(self, master_key: bytes):
        self.k_e, self.k_m = derive_keys(master_key)

    # T = HMAC(K_m, C || AAD || длина AAD), C = IV || шифротекст
    def _tag(self, c: bytes, aad: bytes) -> bytes:
        h = HMAC(self.k_m)
        h.update(c)
        h.update(aad)
        h.update(len(aad).to_bytes(8, "big"))
        return h.digest()

    # IV || C || T
    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        iv = iv_modes.generate_iv()
        c = iv + iv_modes.ctr_crypt(self.k_e, iv, plaintext)
        return c + self._tag(c, aad)

    # сначала проверка тега, потом расшифрование
    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes:
        if len(data) < iv_modes.IV_SIZE + TAG_SIZE:
            raise AuthenticationError("Authentication failed: data is too short")
        c, tag = data[:-TAG_SIZE], data[-TAG_SIZE:]
        if not constant_time_equal(self._tag(c, aad), tag):
            raise AuthenticationError("Authentication failed: AAD mismatch or ciphertext tampered")
        iv = c[:iv_modes.IV_SIZE]
        return iv_modes.ctr_crypt(self.k_e, iv, c[iv_modes.IV_SIZE:])
