import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import csprng
from src.modes import ecb, iv_modes

# ключ из примеров в задании: в виде hex-строки и в виде байтов
KEY_HEX = "000102030405060708090a0b0c0d0e0f"
KEY = bytes.fromhex(KEY_HEX)
# IV из примеров в задании
IV_HEX = "AABBCCDDEEFF00112233445566778899"
IV = bytes.fromhex(IV_HEX)
# режимы с IV
IV_MODES = ["cbc", "cfb", "ofb", "ctr"]
# путь к openssl или None, если он не установлен
OPENSSL = shutil.which("openssl")


def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "src.cli_parser", *args],
                          cwd=ROOT, capture_output=True)


class TestEcb(unittest.TestCase):

    def test_nist_vector(self):
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(ecb.encrypt(KEY, plaintext)[:16], expected)

    # pad дописывает нужное число байт, unpad отбрасывает неверное дополнение
    def test_padding(self):
        # пустые данные -> целый блок из 0x10
        self.assertEqual(ecb.pad(b""), b"\x10" * 16)
        # 3 байта -> не хватает 13, дописывается тринадцать байт 0x0d
        self.assertEqual(ecb.pad(b"abc"), b"abc" + b"\x0d" * 13)
        # ровно 16 байт -> добавляется ещё один целый блок
        self.assertEqual(ecb.pad(b"a" * 16), b"a" * 16 + b"\x10" * 16)
        # неверные дополнения: длина 0, длина 17, байты дополнения не одинаковые
        for bad in (b"a" * 15 + b"\x00", b"a" * 15 + b"\x11", b"a" * 14 + b"\x01\x02"):
            with self.assertRaises(ValueError):
                ecb.unpad(bad)

class TestIvModes(unittest.TestCase):
    """Проверка алгоритмов из iv_modes.py без командной строки"""

    # NIST SP 800-38A, приложение F: первый блок шифротекста для каждого режима
    def test_nist_vectors(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected = {
            "cbc": (iv, "7649abac8119b246cee98e9b12e9197d"),
            "cfb": (iv, "3b3fd92eb72dad20333449f8e83cfb4a"),
            "ofb": (iv, "3b3fd92eb72dad20333449f8e83cfb4a"),
            # в примере NIST для CTR начальное значение счётчика другое
            "ctr": (bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                    "874d6191b620e3261bef6864990db6ce"),
        }
        for mode, (mode_iv, block) in expected.items():
            with self.subTest(mode):
                encrypt, _ = iv_modes.MODES[mode]
                self.assertEqual(encrypt(key, mode_iv, plaintext)[:16], bytes.fromhex(block))

class CliTestCase(unittest.TestCase):
    """Общие вспомогательные методы для тестов командной строки"""

    # перед каждым тестом создаётся временный каталог, после теста он удаляется
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    # полный путь к файлу во временном каталоге
    def path(self, name):
        return os.path.join(self.dir, name)

    # создание файла с заданными байтами, возвращает путь к нему
    def write(self, name, data):
        with open(self.path(name), "wb") as f:
            f.write(data)
        return self.path(name)

    # содержимое файла в виде байтов
    def read(self, name):
        with open(self.path(name), "rb") as f:
            return f.read()

    # правильный набор аргументов, op - "--encrypt" или "--decrypt"
    def base_args(self, op, src, dst=None, mode="ecb", iv=None):
        args = ["--algorithm", "aes", "--mode", mode, op, "--key", KEY_HEX, "--input", src]
        args += ["--iv", iv] if iv else []
        return args + (["--output", dst] if dst else [])


class TestCli(CliTestCase):
    """Проверка программы целиком через командную строку, режим ECB"""

    # зашифровать, расшифровать, сравнить с исходным файлом
    def test_roundtrip_text_and_binary(self):
        samples = {
            "text.txt": "Hello, CryptoCore!\r\nПривет, мир!\n".encode("utf-8"),  # текст
            "binary.bin": bytes(range(256)) * 41 + b"\x00\xff",  # все возможные значения байта
            "empty.txt": b"",                                     # пустой файл
            "exact_block.bin": b"A" * 32,                         # длина кратна 16
        }
        for name, data in samples.items():
            with self.subTest(name):
                src = self.write(name, data)
                enc, dec = self.path(name + ".enc"), self.path(name + ".out")
                r = run_cli(*self.base_args("--encrypt", src, enc))
                self.assertEqual(r.returncode, 0, r.stderr)
                r = run_cli(*self.base_args("--decrypt", enc, dec))
                self.assertEqual(r.returncode, 0, r.stderr)
                # шифротекст отличается от исходных данных
                self.assertNotEqual(self.read(name + ".enc"), data)
                # расшифрованный файл совпадает с исходным байт в байт
                self.assertEqual(self.read(name + ".out"), data)

    # каждый неверный вызов должен дать ненулевой код, текст в stderr
    # и не создать выходной файл
    def test_invalid_arguments(self):
        src = self.write("plain.txt", b"data")
        out = self.path("out.bin")
        good = self.base_args("--encrypt", src, out)

        # правильные аргументы без одного флага (и его значения, если оно есть)
        def without(flag, has_value=True):
            i = good.index(flag)
            return good[:i] + good[i + (2 if has_value else 1):]

        # правильные аргументы с другим значением ключа
        def with_key(key):
            return ["--algorithm", "aes", "--mode", "ecb", "--encrypt", "--key", key,
                    "--input", src, "--output", out]

        cases = {
            "no arguments": [],
            "missing --algorithm": without("--algorithm"),
            "missing --mode": without("--mode"),
            # при расшифровании ключ обязателен
            "missing --key on decrypt": ["--algorithm", "aes", "--mode", "ecb", "--decrypt",
                                         "--input", src, "--output", out],
            "missing --input": without("--input"),
            "missing operation": without("--encrypt", has_value=False),
            "both operations": good + ["--decrypt"],
            "unknown algorithm": ["--algorithm", "des"] + without("--algorithm"),
            "unknown mode": ["--mode", "gcm"] + without("--mode"),
            "key not hex": with_key("zz0102030405060708090a0b0c0d0e0f"),
            "key too short": with_key("000102"),
            "key too long": with_key(KEY_HEX + "00"),
            "key odd length": with_key(KEY_HEX[:-1]),
            "unknown argument": good + ["--bogus"],
        }
        for name, args in cases.items():
            with self.subTest(name):
                r = run_cli(*args)
                self.assertNotEqual(r.returncode, 0)
                self.assertTrue(r.stderr.strip())
                self.assertFalse(os.path.exists(out))

    # ошибки чтения и записи файлов дают понятное сообщение
    def test_file_errors(self):
        # входного файла не существует
        r = run_cli(*self.base_args("--encrypt", self.path("missing.txt"), self.path("o.bin")))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"cannot read input file", r.stderr)

        # вместо входного файла указан каталог
        r = run_cli(*self.base_args("--encrypt", self.dir, self.path("o.bin")))
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(r.stderr.strip())

        # выходной файл в несуществующем каталоге
        src = self.write("plain.txt", b"data")
        r = run_cli(*self.base_args("--encrypt", src, self.path("no_dir/o.bin")))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"cannot write output file", r.stderr)

    # тот же файл и тот же ключ должны дать тот же шифротекст, что и у OpenSSL
    # тест пропускается, если openssl не установлен
    @unittest.skipUnless(OPENSSL, "openssl not found in PATH")
    def test_matches_openssl(self):
        # запуск openssl enc в режиме ECB с ключом из примеров
        def openssl(*args):
            subprocess.run([OPENSSL, "enc", "-aes-128-ecb", "-K", KEY_HEX, *args], check=True)

        # один файл с длиной, не кратной 16, и один с кратной
        for name, data in {"odd.txt": b"Compare with OpenSSL\n" * 7, "multi16.bin": os.urandom(64)}.items():
            with self.subTest(name):
                src = self.write(name, data)
                ours, ref = self.path(name + ".ours"), self.path(name + ".ref")
                run_cli(*self.base_args("--encrypt", src, ours))
                openssl("-in", src, "-out", ref)
                # OpenSSL по умолчанию тоже дополняет по PKCS#7, файлы совпадают полностью
                self.assertEqual(self.read(name + ".ours"), self.read(name + ".ref"))

                # и в обратную сторону: расшифровать у себя то, что зашифровал OpenSSL
                back = self.path(name + ".back")
                r = run_cli(*self.base_args("--decrypt", ref, back))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self.read(name + ".back"), data)

        src = self.write("nopad.bin", b"B" * 32)
        run_cli(*self.base_args("--encrypt", src, self.path("nopad.ours")))
        openssl("-nopad", "-in", src, "-out", self.path("nopad.ref"))
        self.assertEqual(self.read("nopad.ours")[:32], self.read("nopad.ref"))
        self.assertEqual(len(self.read("nopad.ours")), 48)


class TestCliIvModes(CliTestCase):
    """Проверка режимов CBC, CFB, OFB, CTR через командную строку"""

    SAMPLES = {
        "text.txt": "Hello, CryptoCore!\r\nПривет, мир!\n".encode("utf-8"),  # текст
        "binary.bin": bytes(range(256)) * 5 + b"\x00\xff",  # бинарные данные, длина не кратна 16
        "empty.txt": b"",                                    # пустой файл
        "exact_block.bin": b"A" * 32,                        # длина кратна 16
    }

    def test_roundtrip(self):
        for mode in IV_MODES:
            for name, data in self.SAMPLES.items():
                with self.subTest(mode=mode, name=name):
                    src = self.write(name, data)
                    enc, dec = self.path(f"{name}.{mode}.enc"), self.path(f"{name}.{mode}.out")
                    r = run_cli(*self.base_args("--encrypt", src, enc, mode))
                    self.assertEqual(r.returncode, 0, r.stderr)
                    r = run_cli(*self.base_args("--decrypt", enc, dec, mode))
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(self.read(f"{name}.{mode}.out"), data)
                    body = len(data) - len(data) % 16 + 16 if mode == "cbc" else len(data)
                    self.assertEqual(len(self.read(f"{name}.{mode}.enc")), 16 + body)

    # --iv в неподходящем месте или неверного вида даёт ошибку
    def test_iv_argument_errors(self):
        src = self.write("plain.txt", b"data" * 8)
        out = self.path("out.bin")
        cases = {
            # при шифровании --iv не принимается
            "iv with encrypt": self.base_args("--encrypt", src, out, "cbc", iv=IV_HEX),
            # ECB не использует IV
            "iv with ecb": self.base_args("--decrypt", src, out, "ecb", iv=IV_HEX),
            "iv not hex": self.base_args("--decrypt", src, out, "cbc", iv="zz" + IV_HEX[2:]),
            "iv too short": self.base_args("--decrypt", src, out, "cbc", iv="aabbcc"),
            "iv too long": self.base_args("--decrypt", src, out, "cbc", iv=IV_HEX + "00"),
            "iv odd length": self.base_args("--decrypt", src, out, "cbc", iv=IV_HEX[:-1]),
        }
        for mode in IV_MODES:
            cases["iv with encrypt " + mode] = self.base_args("--encrypt", src, out, mode, iv=IV_HEX)
        for name, args in cases.items():
            with self.subTest(name):
                r = run_cli(*args)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(b"--iv", r.stderr)
                self.assertFalse(os.path.exists(out))

    # без --iv файл короче 16 байт не содержит полного IV
    def test_file_too_short_for_iv(self):
        out = self.path("out.bin")
        for mode in IV_MODES:
            for size in (0, 1, 15):
                with self.subTest(mode=mode, size=size):
                    src = self.write("short.bin", b"x" * size)
                    r = run_cli(*self.base_args("--decrypt", src, out, mode))
                    self.assertNotEqual(r.returncode, 0)
                    self.assertIn(b"too short", r.stderr)
                    self.assertFalse(os.path.exists(out))

    # запуск openssl enc в нужном режиме
    # aes-128-cfb в OpenSSL - это CFB с сегментом 128 бит
    def openssl(self, mode, *args):
        subprocess.run([OPENSSL, "enc", f"-aes-128-{mode}", "-K", KEY_HEX, *args], check=True)

    # шифрование cryptocore, расшифрование OpenSSL
    @unittest.skipUnless(OPENSSL, "openssl not found in PATH")
    def test_cryptocore_to_openssl(self):
        for mode in IV_MODES:
            for name, data in self.SAMPLES.items():
                with self.subTest(mode=mode, name=name):
                    src = self.write(name, data)
                    enc = self.path("ours.enc")
                    r = run_cli(*self.base_args("--encrypt", src, enc, mode))
                    self.assertEqual(r.returncode, 0, r.stderr)
                    full = self.read("ours.enc")
                    body = self.write("ours.body", full[16:])
                    self.openssl(mode, "-d", "-iv", full[:16].hex(),
                                 "-in", body, "-out", self.path("openssl.out"))
                    self.assertEqual(self.read("openssl.out"), data)

    # шифрование OpenSSL, расшифрование cryptocore
    @unittest.skipUnless(OPENSSL, "openssl not found in PATH")
    def test_openssl_to_cryptocore(self):
        for mode in IV_MODES:
            for name, data in self.SAMPLES.items():
                with self.subTest(mode=mode, name=name):
                    src = self.write(name, data)
                    enc = self.path("openssl.enc")
                    self.openssl(mode, "-iv", IV_HEX, "-in", src, "-out", enc)
                    # OpenSSL пишет шифротекст без IV, поэтому IV передаётся через --iv
                    out = self.path("ours.out")
                    r = run_cli(*self.base_args("--decrypt", enc, out, mode, iv=IV_HEX))
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(self.read("ours.out"), data)
                    # тот же шифротекст с IV в начале файла расшифровывается без --iv
                    joined = self.write("joined.enc", IV + self.read("openssl.enc"))
                    r = run_cli(*self.base_args("--decrypt", joined, out, mode))
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(self.read("ours.out"), data)


class TestCsprng(unittest.TestCase):
    """Проверка генератора случайных байт из csprng.py"""

    def test_1000_unique_keys(self):
        keys = set()
        for _ in range(1000):
            key = csprng.generate_random_bytes(16).hex()
            self.assertNotIn(key, keys, f"duplicate key found: {key}")
            keys.add(key)
        self.assertEqual(len(keys), 1000)

    def test_hamming_weight(self):
        weights = [sum(bin(b).count("1") for b in csprng.generate_random_bytes(16))
                   for _ in range(1000)]
        ratio = sum(weights) / (1000 * 128)
        self.assertGreater(ratio, 0.48)
        self.assertLess(ratio, 0.52)
        self.assertGreater(min(weights), 32)
        self.assertLess(max(weights), 96)


    def test_os_failure(self):
        for error in (OSError("device not ready"), NotImplementedError("no source")):
            with self.subTest(error=type(error).__name__):
                with mock.patch("src.csprng.os.urandom", side_effect=error):
                    with self.assertRaises(csprng.RandomGenerationError) as ctx:
                        csprng.generate_random_bytes(16)
                self.assertIn("random bytes", str(ctx.exception))
        with mock.patch("src.csprng.os.urandom", return_value=b"short"):
            with self.assertRaises(csprng.RandomGenerationError):
                csprng.generate_random_bytes(16)

class TestCliKeys(CliTestCase):
    """Проверка генерации ключа и предупреждений о слабом ключе через командную строку"""

    KEY_LINE = re.compile(rb"^\[INFO\] Generated random key: ([0-9a-f]{32})\r?$", re.M)

    # шифрование без --key, возвращает ключ, выведенный в stdout
    def encrypt_without_key(self, mode, src, dst):
        r = run_cli("--algorithm", "aes", "--mode", mode, "--encrypt",
                    "--input", src, "--output", dst)
        self.assertEqual(r.returncode, 0, r.stderr)
        # ключ выводится в stdout ровно один раз
        found = self.KEY_LINE.findall(r.stdout)
        self.assertEqual(len(found), 1, r.stdout)
        return found[0].decode()

    # шифрование без --key, расшифрование с выведенным ключом возвращает исходный файл
    def test_generated_key_roundtrip(self):
        data = "Ключ сгенерирован автоматически\n".encode("utf-8") * 5
        src = self.write("plain.txt", data)
        for mode in ["ecb", *IV_MODES]:
            with self.subTest(mode):
                enc, out = self.path(mode + ".enc"), self.path(mode + ".out")
                key_hex = self.encrypt_without_key(mode, src, enc)
                r = run_cli("--algorithm", "aes", "--mode", mode, "--decrypt", "--key", key_hex,
                            "--input", enc, "--output", out)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self.read(mode + ".out"), data)
                # ключа нет в выходном файле ни в виде байтов, ни в виде hex-строки
                encrypted = self.read(mode + ".enc")
                self.assertNotIn(bytes.fromhex(key_hex), encrypted)
                self.assertNotIn(key_hex.encode(), encrypted)
                body = len(data) - len(data) % 16 + 16 if mode in ("ecb", "cbc") else len(data)
                self.assertEqual(len(encrypted), body + (16 if mode in IV_MODES else 0))

    # расшифрование без --key - ошибка во всех режимах
    def test_decrypt_requires_key(self):
        src = self.write("plain.txt", b"x" * 32)
        out = self.path("out.bin")
        for mode in ["ecb", *IV_MODES]:
            with self.subTest(mode):
                r = run_cli("--algorithm", "aes", "--mode", mode, "--decrypt",
                            "--input", src, "--output", out)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(b"--key", r.stderr)
                self.assertFalse(os.path.exists(out))

    # слабый ключ даёт предупреждение в stderr, но шифрование работает
    def test_weak_key_warning(self):
        src = self.write("plain.txt", b"weak keys still work")
        weak = {
            "all zeros": "00" * 16,
            "ascending": "000102030405060708090a0b0c0d0e0f",
            "2-byte pattern": "abcd" * 8,
        }
        for name, key in weak.items():
            with self.subTest(name):
                enc = self.path("weak.enc")
                r = run_cli("--algorithm", "aes", "--mode", "cbc", "--encrypt", "--key", key,
                            "--input", src, "--output", enc)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(b"[WARNING]", r.stderr)
                self.assertIn(b"weak", r.stderr)
                self.assertNotIn(b"WARNING", r.stdout)
                r = run_cli("--algorithm", "aes", "--mode", "cbc", "--decrypt", "--key", key,
                            "--input", enc, "--output", self.path("weak.out"))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(b"[WARNING]", r.stderr)
                self.assertEqual(self.read("weak.out"), b"weak keys still work")

if __name__ == "__main__":
    unittest.main()
