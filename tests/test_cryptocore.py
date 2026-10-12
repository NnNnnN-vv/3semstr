"""Тесты cryptocore, запуск из корня проекта: python -m unittest discover tests -v

TestEcb и TestIvModes проверяют функции из ecb.py и iv_modes.py напрямую
TestCli и TestCliIvModes запускают программу как отдельный процесс с аргументами
командной строки и проверяют код возврата, stderr и содержимое файлов
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

# корень проекта (каталог на уровень выше tests) добавляется в пути поиска модулей,
# чтобы работал импорт src
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from Crypto.Cipher import AES
from Crypto.Util import Counter

from src.modes import ecb, iv_modes

# ключ из примеров в задании: в виде hex-строки и в виде байтов
KEY_HEX = "000102030405060708090a0b0c0d0e0f"
KEY = bytes.fromhex(KEY_HEX)
# IV из примеров в задании
IV_HEX = "AABBCCDDEEFF00112233445566778899"
IV = bytes.fromhex(IV_HEX)
# режимы с IV и те из них, что работают без дополнения
IV_MODES = ["cbc", "cfb", "ofb", "ctr"]
STREAM_MODES = ["cfb", "ofb", "ctr"]
# путь к openssl или None, если он не установлен
OPENSSL = shutil.which("openssl")


def run_cli(*args):
    """Запуск инструмента отдельным процессом, как это делает команда cryptocore

    Возвращает объект с полями returncode (код возврата) и stderr (текст ошибок)
    """
    return subprocess.run([sys.executable, "-m", "src.cli_parser", *args],
                          cwd=ROOT, capture_output=True)


class TestEcb(unittest.TestCase):
    """Проверка алгоритмов из ecb.py без командной строки"""

    def test_nist_vector(self):
        # FIPS-197, приложение C.1: официальная пара "открытый блок -> шифротекст" для AES-128
        # совпадение первого блока доказывает, что AES вызывается правильно
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(ecb.encrypt(KEY, plaintext)[:16], expected)

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

    def test_roundtrip_all_lengths(self):
        # случайные данные каждой длины от 0 до 99 байт:
        # шифротекст кратен 16, расшифрование возвращает исходные данные
        for n in range(0, 100):
            data = os.urandom(n)
            encrypted = ecb.encrypt(KEY, data)
            self.assertEqual(len(encrypted) % 16, 0)
            self.assertEqual(ecb.decrypt(KEY, encrypted), data)


class TestIvModes(unittest.TestCase):
    """Проверка алгоритмов из iv_modes.py без командной строки"""

    def reference(self, mode, iv):
        # тот же режим в готовом виде из pycryptodome, используется только как эталон
        if mode == "cbc":
            return AES.new(KEY, AES.MODE_CBC, iv=iv)
        if mode == "cfb":
            return AES.new(KEY, AES.MODE_CFB, iv=iv, segment_size=128)
        if mode == "ofb":
            return AES.new(KEY, AES.MODE_OFB, iv=iv)
        counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        return AES.new(KEY, AES.MODE_CTR, counter=counter)

    def test_nist_vectors(self):
        # NIST SP 800-38A, приложение F: первый блок шифротекста для каждого режима
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

    def test_matches_library_all_lengths(self):
        # случайные данные каждой длины от 0 до 99 байт: шифротекст совпадает с эталоном,
        # расшифрование возвращает исходные данные
        for mode in IV_MODES:
            encrypt, decrypt = iv_modes.MODES[mode]
            for n in range(0, 100):
                with self.subTest(mode=mode, n=n):
                    data, iv = os.urandom(n), os.urandom(16)
                    encrypted = encrypt(KEY, iv, data)
                    # эталону для CBC дополненные данные передаются явно
                    source = ecb.pad(data) if mode == "cbc" else data
                    self.assertEqual(encrypted, self.reference(mode, iv).encrypt(source))
                    self.assertEqual(decrypt(KEY, iv, encrypted), data)

    def test_lengths(self):
        for n in (0, 1, 15, 16, 17, 33):
            data = os.urandom(n)
            # потоковые режимы не меняют длину данных
            for mode in STREAM_MODES:
                self.assertEqual(len(iv_modes.MODES[mode][0](KEY, IV, data)), n)
            # CBC дополняет до следующей границы блока
            self.assertEqual(len(iv_modes.cbc_encrypt(KEY, IV, data)), n - n % 16 + 16)

    def test_ctr_counter_overflow(self):
        # счётчик из одних единиц после увеличения становится нулём
        data = os.urandom(40)
        iv = b"\xff" * 16
        self.assertEqual(iv_modes.ctr_crypt(KEY, iv, data), self.reference("ctr", iv).encrypt(data))

    def test_same_blocks_differ(self):
        # в отличие от ECB одинаковые блоки открытого текста дают разные блоки шифротекста
        data = b"A" * 32
        for mode in IV_MODES:
            encrypted = iv_modes.MODES[mode][0](KEY, IV, data)
            self.assertNotEqual(encrypted[:16], encrypted[16:32])

    def test_bad_input(self):
        # IV не 16 байт
        for mode in IV_MODES:
            with self.assertRaises(ValueError):
                iv_modes.MODES[mode][0](KEY, b"short", b"data")
        # шифротекст CBC пустой или не кратен 16
        for bad in (b"", b"x" * 17):
            with self.assertRaises(ValueError):
                iv_modes.cbc_decrypt(KEY, IV, bad)

    def test_generate_iv(self):
        # IV длиной 16 байт и каждый раз новый
        self.assertEqual(len(iv_modes.generate_iv()), 16)
        self.assertNotEqual(iv_modes.generate_iv(), iv_modes.generate_iv())


class CliTestCase(unittest.TestCase):
    """Общие вспомогательные методы для тестов командной строки"""

    def setUp(self):
        # перед каждым тестом создаётся временный каталог, после теста он удаляется
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def path(self, name):
        # полный путь к файлу во временном каталоге
        return os.path.join(self.dir, name)

    def write(self, name, data):
        # создание файла с заданными байтами, возвращает путь к нему
        with open(self.path(name), "wb") as f:
            f.write(data)
        return self.path(name)

    def read(self, name):
        # содержимое файла в виде байтов
        with open(self.path(name), "rb") as f:
            return f.read()

    def base_args(self, op, src, dst=None, mode="ecb", iv=None):
        # правильный набор аргументов, op - "--encrypt" или "--decrypt"
        args = ["--algorithm", "aes", "--mode", mode, op, "--key", KEY_HEX, "--input", src]
        args += ["--iv", iv] if iv else []
        return args + (["--output", dst] if dst else [])


class TestCli(CliTestCase):
    """Проверка программы целиком через командную строку, режим ECB"""

    def test_roundtrip_text_and_binary(self):
        # главный приёмочный тест: зашифровать, расшифровать, сравнить с исходным файлом
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

    def test_default_output_names(self):
        # без --output: plain.txt -> plain.txt.enc -> plain.txt.enc.dec
        src = self.write("plain.txt", b"default names")
        self.assertEqual(run_cli(*self.base_args("--encrypt", src)).returncode, 0)
        self.assertEqual(run_cli(*self.base_args("--decrypt", src + ".enc")).returncode, 0)
        self.assertEqual(self.read("plain.txt.enc.dec"), b"default names")

    def test_invalid_arguments(self):
        # каждый неверный вызов должен дать ненулевой код, текст в stderr
        # и не создать выходной файл
        src = self.write("plain.txt", b"data")
        out = self.path("out.bin")
        good = self.base_args("--encrypt", src, out)

        def without(flag, has_value=True):
            # правильные аргументы без одного флага (и его значения, если оно есть)
            i = good.index(flag)
            return good[:i] + good[i + (2 if has_value else 1):]

        def with_key(key):
            # правильные аргументы с другим значением ключа
            return ["--algorithm", "aes", "--mode", "ecb", "--encrypt", "--key", key,
                    "--input", src, "--output", out]

        cases = {
            "no arguments": [],
            "missing --algorithm": without("--algorithm"),
            "missing --mode": without("--mode"),
            "missing --key": without("--key"),
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

    def test_decrypt_bad_data(self):
        # шифротекст длиной 17 байт: не кратен 16, расшифровать нельзя
        out = self.path("out.txt")
        bad_length = self.write("bad_length.bin", b"x" * 17)
        r = run_cli(*self.base_args("--decrypt", bad_length, out))
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(r.stderr.strip())

        # расшифрование чужим ключом: получается мусор, проверка дополнения выдаёт ошибку,
        # выходной файл не создаётся
        src = self.write("plain.txt", b"secret data")
        enc = self.path("c.bin")
        run_cli(*self.base_args("--encrypt", src, enc))
        wrong_key = ["--algorithm", "aes", "--mode", "ecb", "--decrypt", "--key", "ff" * 16,
                     "--input", enc, "--output", out]
        r = run_cli(*wrong_key)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"padding", r.stderr)
        self.assertFalse(os.path.exists(out))

    # тест пропускается, если openssl не установлен
    @unittest.skipUnless(OPENSSL, "openssl not found in PATH")
    def test_matches_openssl(self):
        #  тот же файл и тот же ключ должны дать тот же шифротекст
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

        # -nopad: OpenSSL не дополняет, поэтому результат cryptocore = результат OpenSSL
        # + один блок дополнения (32 байта данных -> 48 байт шифротекста)
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
        # полный цикл для каждого режима: IV берётся из начала зашифрованного файла
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
                    # размер файла: 16 байт IV + шифротекст
                    # потоковые режимы не дополняют, CBC дополняет до границы блока
                    body = len(data) - len(data) % 16 + 16 if mode == "cbc" else len(data)
                    self.assertEqual(len(self.read(f"{name}.{mode}.enc")), 16 + body)

    def test_iv_is_random_and_first(self):
        data = b"same plaintext, same key" * 3
        src = self.write("plain.txt", data)
        for mode in IV_MODES:
            with self.subTest(mode):
                a, b = self.path(mode + ".a"), self.path(mode + ".b")
                run_cli(*self.base_args("--encrypt", src, a, mode))
                run_cli(*self.base_args("--encrypt", src, b, mode))
                first, second = self.read(mode + ".a"), self.read(mode + ".b")
                # два шифрования одного файла дают разные IV и разные шифротексты
                self.assertNotEqual(first[:16], second[:16])
                self.assertNotEqual(first[16:], second[16:])
                # первые 16 байт файла - именно тот IV, которым зашифрованы остальные
                decrypt = iv_modes.MODES[mode][1]
                self.assertEqual(decrypt(KEY, first[:16], first[16:]), data)

    def test_decrypt_with_iv_argument(self):
        # с --iv весь входной файл считается шифротекстом без IV в начале
        data = b"IV passed on the command line\n" * 3
        src = self.write("plain.txt", data)
        for mode in IV_MODES:
            with self.subTest(mode):
                enc = self.path(mode + ".enc")
                run_cli(*self.base_args("--encrypt", src, enc, mode))
                full = self.read(mode + ".enc")
                body = self.write(mode + ".body", full[16:])
                out = self.path(mode + ".out")
                # IV в верхнем регистре, как в примере из задания
                r = run_cli(*self.base_args("--decrypt", body, out, mode, iv=full[:16].hex().upper()))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self.read(mode + ".out"), data)

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

    def test_file_too_short_for_iv(self):
        # без --iv файл короче 16 байт не содержит полного IV
        out = self.path("out.bin")
        for mode in IV_MODES:
            for size in (0, 1, 15):
                with self.subTest(mode=mode, size=size):
                    src = self.write("short.bin", b"x" * size)
                    r = run_cli(*self.base_args("--decrypt", src, out, mode))
                    self.assertNotEqual(r.returncode, 0)
                    self.assertIn(b"too short", r.stderr)
                    self.assertFalse(os.path.exists(out))

    def test_decrypt_bad_data(self):
        out = self.path("out.bin")
        # CBC: после IV остаётся 0 или 17 байт
        for size in (16, 33):
            with self.subTest(size=size):
                src = self.write("bad.bin", b"x" * size)
                r = run_cli(*self.base_args("--decrypt", src, out, "cbc"))
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(b"multiple of 16", r.stderr)
        # CBC с чужим ключом
        src = self.write("plain.txt", b"secret data")
        enc = self.path("c.bin")
        run_cli(*self.base_args("--encrypt", src, enc, "cbc"))
        r = run_cli("--algorithm", "aes", "--mode", "cbc", "--decrypt", "--key", "ff" * 16,
                    "--input", enc, "--output", out)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"padding", r.stderr)
        self.assertFalse(os.path.exists(out))

    def openssl(self, mode, *args):
        # aes-128-cfb в OpenSSL - это CFB с сегментом 128 бит
        subprocess.run([OPENSSL, "enc", f"-aes-128-{mode}", "-K", KEY_HEX, *args], check=True)

    @unittest.skipUnless(OPENSSL, "openssl not found in PATH")
    def test_cryptocore_to_openssl(self):
        # шифрование cryptocore, расшифрование OpenSSL
        for mode in IV_MODES:
            for name, data in self.SAMPLES.items():
                with self.subTest(mode=mode, name=name):
                    src = self.write(name, data)
                    enc = self.path("ours.enc")
                    r = run_cli(*self.base_args("--encrypt", src, enc, mode))
                    self.assertEqual(r.returncode, 0, r.stderr)
                    # файл делится на IV (первые 16 байт) и шифротекст
                    full = self.read("ours.enc")
                    body = self.write("ours.body", full[16:])
                    self.openssl(mode, "-d", "-iv", full[:16].hex(),
                                 "-in", body, "-out", self.path("openssl.out"))
                    self.assertEqual(self.read("openssl.out"), data)

    @unittest.skipUnless(OPENSSL, "openssl not found in PATH")
    def test_openssl_to_cryptocore(self):
        # шифрование OpenSSL, расшифрование cryptocore
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


if __name__ == "__main__":
    unittest.main()
