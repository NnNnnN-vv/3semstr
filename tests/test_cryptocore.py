"""Тесты cryptocore, запуск из корня проекта: python -m unittest discover tests -v

TestEcb проверяет функции из ecb.py напрямую
TestCli запускает программу как отдельный процесс с аргументами командной строки
и проверяет код возврата, stderr и содержимое файлов
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

from src.modes import ecb

# ключ из примеров в задании: в виде hex-строки и в виде байтов
KEY_HEX = "000102030405060708090a0b0c0d0e0f"
KEY = bytes.fromhex(KEY_HEX)
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


class TestCli(unittest.TestCase):
    """Проверка программы целиком через командную строку"""

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

    def base_args(self, op, src, dst=None):
        # правильный набор аргументов, op - "--encrypt" или "--decrypt"
        args = ["--algorithm", "aes", "--mode", "ecb", op, "--key", KEY_HEX, "--input", src]
        return args + (["--output", dst] if dst else [])

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
            "unknown mode": ["--mode", "cbc"] + without("--mode"),
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


# запуск файла напрямую: python tests/test_cryptocore.py
if __name__ == "__main__":
    unittest.main()
