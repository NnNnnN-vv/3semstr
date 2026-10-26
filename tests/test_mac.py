import hashlib
import hmac as std_hmac
import os
import shutil
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import cli_parser, file_io
from src.hash import ALGORITHMS
from src.mac import CMAC, HMAC

KEY_HEX = "00112233445566778899aabbccddeeff"
CMAC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def run_cli(*args, cwd=ROOT):
    env = dict(os.environ, PYTHONPATH=ROOT)
    return subprocess.run([sys.executable, "-m", "src.cli_parser", *args],
                          cwd=cwd, capture_output=True, env=env)


class TestHmac(unittest.TestCase):
    """HMAC-SHA256: RFC 4231"""

    def test_rfc4231_vectors(self):
        cases = [
            ("0b" * 20, b"Hi There",
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            ("4a656665", b"what do ya want for nothing?",
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            ("aa" * 20, b"\xdd" * 50,
             "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            ("0102030405060708090a0b0c0d0e0f10111213141516171819", b"\xcd" * 50,
             "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
            ("aa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
            ("aa" * 131, b"This is a test using a larger than block-size key and a larger "
                         b"than block-size data. The key needs to be hashed before being "
                         b"used by the HMAC algorithm.",
             "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
        ]
        for number, (key, data, expected) in zip((1, 2, 3, 4, 6, 7), cases):
            with self.subTest(case=number):
                self.assertEqual(HMAC(bytes.fromhex(key), "sha256").compute(data), expected)

class TestCmac(unittest.TestCase):
    """AES-CMAC:  NIST SP 800-38B"""

    def test_nist_vectors(self):
        message = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
        expected = {
            0: "bb1d6929e95937287fa37d129b756746",
            16: "070a16b46b4d4144f79bdd9dd04a287c",
            40: "dfa66747de9ae63030ca32611497c827",
            64: "51f0bebf7e3b9d92fc49741779363cfe",
        }
        for n, mac in expected.items():
            with self.subTest(n=n):
                self.assertEqual(CMAC(CMAC_KEY).compute(message[:n]), mac)

class TestMacCli(unittest.TestCase):
    """Команда cryptocore dgst с --hmac, --cmac и --verify"""

    # временный каталог на каждый тест
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    # создание файла во временном каталоге, возвращает полный путь
    def write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    # аргументы HMAC с ключом key для файла path, дальше можно добавить свои
    def hmac_args(self, path, key=KEY_HEX, *extra):
        return ["dgst", "--algorithm", "sha256", "--hmac", "--key", key, "--input", path, *extra]

    # RFC 4231
    def test_rfc_example(self):
        path = self.write("test_file.txt", b"Hi There")
        r = run_cli(*self.hmac_args(path, "0b" * 20))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout,
            f"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 {path}\n".encode())

    # пустой файл
    def test_empty_file(self):
        path = self.write("empty.txt", b"")
        r = run_cli(*self.hmac_args(path))
        expected = std_hmac.new(bytes.fromhex(KEY_HEX), b"", hashlib.sha256).hexdigest()
        self.assertEqual(r.stdout.split()[0].decode(), expected)

    # ключи 16, 64 и 100 байт через командную строку
    def test_key_sizes(self):
        data = os.urandom(5000)
        path = self.write("data.bin", data)
        for size in (16, 64, 100):
            with self.subTest(size=size):
                key = os.urandom(size)
                r = run_cli(*self.hmac_args(path, key.hex()))
                self.assertEqual(r.stdout.split()[0].decode(),
                                 std_hmac.new(key, data, hashlib.sha256).hexdigest())

    # свой же HMAC проверяется успешно, код 0
    def test_verify_own_hmac(self):
        path = self.write("message.txt", b"original content\n")
        mac_file = os.path.join(self.dir, "expected_hmac.txt")
        r = run_cli(*self.hmac_args(path, KEY_HEX, "--output", mac_file))
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_cli(*self.hmac_args(path, KEY_HEX, "--verify", mac_file))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"[OK] HMAC verification successful", r.stdout)

    # изменён один байт файла - проверка не проходит, код 1
    def test_tampered_file(self):
        data = bytearray(b"original content\n" * 10)
        path = self.write("file.txt", bytes(data))
        mac_file = self.write("original_hmac.txt", run_cli(*self.hmac_args(path)).stdout)
        data[50] ^= 0x01
        self.write("file.txt", bytes(data))
        r = run_cli(*self.hmac_args(path, KEY_HEX, "--verify", mac_file))
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"[ERROR] HMAC verification failed", r.stderr)
        self.assertNotIn(b"[OK]", r.stdout)

    # HMAC с одним ключом, проверка другим - не проходит
    def test_wrong_key(self):
        path = self.write("file.txt", b"content")
        mac_file = self.write("original_hmac.txt", run_cli(*self.hmac_args(path)).stdout)
        r = run_cli(*self.hmac_args(path, "ff" + KEY_HEX[2:], "--verify", mac_file))
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"verification failed", r.stderr)

    # файл с ожидаемым MAC разбирается гибко: пробелы, регистр, без имени файла
    def test_verify_flexible_format(self):
        data = b"flexible"
        path = self.write("f.txt", data)
        mac = std_hmac.new(bytes.fromhex(KEY_HEX), data, hashlib.sha256).hexdigest()
        for name, content in {
            "only value": mac,
            "spaces and newline": f"  \n {mac}   \n",
            "upper case": mac.upper(),
            "two spaces and other name": f"{mac}  other_name.txt\r\n",
        }.items():
            with self.subTest(name):
                mac_file = self.write("mac.txt", content.encode())
                r = run_cli(*self.hmac_args(path, KEY_HEX, "--verify", mac_file))
                self.assertEqual(r.returncode, 0, r.stderr)

    # --output записывает ту же строку
    def test_output_file(self):
        path = self.write("f.txt", b"output test")
        out = os.path.join(self.dir, "mac.txt")
        printed = run_cli(*self.hmac_args(path)).stdout
        r = run_cli(*self.hmac_args(path, KEY_HEX, "--output", out))
        self.assertEqual(r.stdout, b"")
        with open(out, "rb") as f:
            self.assertEqual(f.read(), printed)

    # файл из нескольких кусков по 8192 байта с неровным хвостом
    def test_multi_chunk_file(self):
        data = os.urandom(5 * file_io.CHUNK_SIZE + 77)
        path = self.write("big.bin", data)
        r = run_cli(*self.hmac_args(path))
        self.assertEqual(r.stdout.split()[0].decode(),
                         std_hmac.new(bytes.fromhex(KEY_HEX), data, hashlib.sha256).hexdigest())

    # CMAC: SP 800-38B и проверка через --verify
    def test_cmac(self):
        message = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        path = self.write("m.bin", message)
        args = ["dgst", "--cmac", "--key", CMAC_KEY.hex(), "--input", path]
        r = run_cli(*args)
        self.assertEqual(r.stdout, f"070a16b46b4d4144f79bdd9dd04a287c {path}\n".encode())
        mac_file = self.write("m.cmac", r.stdout)
        r = run_cli(*args, "--verify", mac_file)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"[OK] CMAC verification successful", r.stdout)
        self.write("m.bin", message + b"!")
        r = run_cli(*args, "--verify", mac_file)
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"[ERROR] CMAC verification failed", r.stderr)

    # неверные сочетания аргументов - код 2 и сообщение в stderr
    def test_invalid_arguments(self):
        path = self.write("f.txt", b"data")
        base = ["dgst", "--input", path]
        cases = {
            "hmac without key": base + ["--algorithm", "sha256", "--hmac"],
            "key without hmac": base + ["--algorithm", "sha256", "--key", KEY_HEX],
            "verify without hmac": base + ["--algorithm", "sha256", "--verify", path],
            "key not hex": base + ["--algorithm", "sha256", "--hmac", "--key", "zz"],
            "encryption argument": base + ["--algorithm", "sha256", "--hmac", "--key", KEY_HEX,
                                           "--mode", "cbc"],
        }
        for name, args in cases.items():
            with self.subTest(name):
                r = run_cli(*args)
                self.assertEqual(r.returncode, 2)
                self.assertTrue(r.stderr.strip())
                self.assertEqual(r.stdout, b"")


class FastSha256:
    block_size = 64

    # data - начальные данные
    def __init__(self, data=b""):
        self._h = hashlib.sha256(data)

    def update(self, data):
        self._h.update(data)

    # хеш в байтах
    def digest(self):
        return self._h.digest()

    # хеш как hex-строка
    def hexdigest(self):
        return self._h.hexdigest()


class TestBigFileHmac(unittest.TestCase):
    """HMAC файла больше 1 ГБ считается по кускам, память не растёт с размером файла"""

    def test_larger_than_1gb(self):
        size = (1 << 30) + 1
        key = bytes.fromhex(KEY_HEX)
        with tempfile.TemporaryDirectory() as d:
            path, out = os.path.join(d, "big.bin"), os.path.join(d, "big.hmac")
            reference = std_hmac.new(key, digestmod=hashlib.sha256)
            with open(path, "wb") as f:
                written, i = 0, 0
                while written < size:
                    piece = (i.to_bytes(8, "big") * (1 << 17))[:min(1 << 20, size - written)]
                    f.write(piece)
                    reference.update(piece)
                    written += len(piece)
                    i += 1
            tracemalloc.start()
            try:
                with mock.patch.dict(ALGORITHMS, {"sha256": FastSha256}):
                    code = cli_parser.main(["dgst", "--algorithm", "sha256", "--hmac", "--key", KEY_HEX,
                                            "--input", path, "--output", out])
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            self.assertEqual(code, 0)
            with open(out, "rb") as f:
                self.assertEqual(f.read().split()[0].decode(), reference.hexdigest())
            self.assertLess(peak, 10 << 20)

if __name__ == "__main__":
    unittest.main()
