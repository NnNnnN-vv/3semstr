import os
import shutil
import subprocess
import sys
import tempfile
import tracemalloc
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from Crypto.Cipher import AES

from src.aead import AuthenticationError, EncryptThenMac
from src.modes.gcm import GCM


KEY_HEX = "00112233445566778899aabbccddeeff"

KEY = bytes.fromhex(KEY_HEX)

K = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
P = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                  "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
A = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")


# запуск cryptocore отдельным процессом
def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "src.cli_parser", *args],
                          cwd=ROOT, capture_output=True)


# все варианты data с одним изменённым битом
def flipped(data: bytes):
    for i in range(len(data) * 8):
        changed = bytearray(data)
        changed[i // 8] ^= 1 << (i % 8)
        yield bytes(changed)


class TestGcm(unittest.TestCase):

    # тестовые случаи 1-4 и 6 из спецификации GCM, на которой основан SP 800-38D
    def test_nist_vectors(self):
        cases = [
            (bytes(16), bytes(12), b"", b"", "", "58e2fccefa7e3061367f1d57a4e7455a"),
            (bytes(16), bytes(12), bytes(16), b"", "0388dace60b6a392f328c2b971b2fe78",
             "ab6e47d42cec13bdf53a67b21257bddf"),
            (K, bytes.fromhex("cafebabefacedbaddecaf888"), P, b"",
             "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
             "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
             "4d5c2af327cd64a62cf35abd2ba6fab4"),
            (K, bytes.fromhex("cafebabefacedbaddecaf888"), P[:60], A,
             "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
             "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
             "5bc94fbc3221a5db94fae95ae7121a47"),
            (K, bytes.fromhex("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
                              "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b"), P[:60], A,
             "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7"
             "01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
             "619cc5aefffe0bfa462af43c1699d050"),
        ]
        for number, (key, nonce, plaintext, aad, c, tag) in zip((1, 2, 3, 4, 6), cases):
            with self.subTest(case=number):
                ciphertext, t = GCM(key, nonce).seal(plaintext, aad)
                self.assertEqual((ciphertext.hex(), t.hex()), (c, tag))
                self.assertEqual(GCM(key, nonce).open(ciphertext, t, aad), plaintext)

    # шифрование и расшифрование с тем же AAD, в том числе пустым
    def test_roundtrip(self):
        for size in (0, 1, 15, 16, 17, 100):
            for aad in (b"", b"header", os.urandom(50)):
                with self.subTest(size=size, aad=len(aad)):
                    data = os.urandom(size)
                    out = GCM(KEY).encrypt(data, aad)
                    self.assertEqual(len(out), 12 + size + 16)
                    self.assertEqual(GCM(KEY, out[:12]).decrypt(out, aad), data)

    # неверный AAD - AuthenticationError
    def test_wrong_aad(self):
        g = GCM(KEY)
        out = g.encrypt(b"Secret message", b"correct_aad")
        for aad in (b"wrong_aad", b"", b"correct_aaD"):
            with self.subTest(aad=aad):
                with self.assertRaises(AuthenticationError):
                    GCM(KEY, g.nonce).decrypt(out, aad)

    # изменён любой бит шифротекста или тега
    def test_tampered(self):
        out = GCM(KEY).encrypt(b"Another secret", b"aad")
        for bad in flipped(out[12:]):
            with self.assertRaises(AuthenticationError):
                GCM(KEY, out[:12]).decrypt(out[:12] + bad, b"aad")

    # 1000 шифрований - 1000 разных nonce
    def test_unique_nonces(self):
        self.assertEqual(len({GCM(KEY).nonce for _ in range(1000)}), 1000)

    # AAD кусками: 4 МБ, память не растёт, тег совпадает с pycryptodome
    def test_large_aad(self):
        chunks = [os.urandom(1 << 16) for _ in range(4)]
        nonce = os.urandom(12)
        ref = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
        for _ in range(16):
            for chunk in chunks:
                ref.update(chunk)
        _, expected = ref.encrypt_and_digest(b"data")
        tracemalloc.start()
        try:
            _, tag = GCM(KEY, nonce).seal(b"data", (c for _ in range(16) for c in chunks))
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(tag, expected)
        self.assertLess(peak, 1 << 20)


class TestEncryptThenMac(unittest.TestCase):

    # шифрование и расшифрование с тем же AAD
    def test_roundtrip(self):
        etm = EncryptThenMac(KEY)
        for size in (0, 1, 16, 100):
            for aad in (b"", b"header"):
                data = os.urandom(size)
                self.assertEqual(etm.decrypt(etm.encrypt(data, aad), aad), data)

    # неверный AAD или другой ключ - AuthenticationError
    def test_wrong_aad(self):
        etm = EncryptThenMac(KEY)
        out = etm.encrypt(b"Secret message", b"correct_aad")
        with self.assertRaises(AuthenticationError):
            etm.decrypt(out, b"wrong_aad")
        with self.assertRaises(AuthenticationError):
            EncryptThenMac(os.urandom(16)).decrypt(out, b"correct_aad")

    # изменён любой бит IV, шифротекста или тега
    def test_tampered(self):
        etm = EncryptThenMac(KEY)
        out = etm.encrypt(b"Another secret", b"aad")
        for bad in flipped(out):
            with self.assertRaises(AuthenticationError):
                etm.decrypt(bad, b"aad")


class TestGcmCli(unittest.TestCase):

    # временный каталог на каждый тест
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    # полный путь к файлу во временном каталоге
    def path(self, name):
        return os.path.join(self.dir, name)

    # создание файла, возвращает путь
    def write(self, name, data):
        with open(self.path(name), "wb") as f:
            f.write(data)
        return self.path(name)

    # содержимое файла
    def read(self, name):
        with open(self.path(name), "rb") as f:
            return f.read()

    # запуск cryptocore в режиме GCM
    def gcm(self, op, src, dst, *extra):
        return run_cli("--algorithm", "aes", "--mode", "gcm", op, "--key", KEY_HEX,
                       "--input", src, "--output", dst, *extra)

    # неверный AAD или изменённый файл
    def test_authentication_failure(self):
        src = self.write("p.txt", b"secret")
        self.gcm("--encrypt", src, self.path("c.bin"), "--aad", "aabbccddeeff")
        data = self.read("c.bin")
        tampered = self.write("t.bin", data[:20] + bytes([data[20] ^ 1]) + data[21:])
        cases = {
            "wrong aad": (self.path("c.bin"), ["--aad", "aabbccddee00"]),
            "no aad": (self.path("c.bin"), []),
            "tampered": (tampered, ["--aad", "aabbccddeeff"]),
        }
        for name, (enc, extra) in cases.items():
            with self.subTest(name):
                out = self.path("should_fail.txt")
                r = self.gcm("--decrypt", enc, out, *extra)
                self.assertEqual(r.returncode, 1)
                self.assertIn(b"[ERROR] Authentication failed", r.stderr)
                self.assertEqual(r.stdout, b"")
                self.assertFalse(os.path.exists(out))

if __name__ == "__main__":
    unittest.main()
