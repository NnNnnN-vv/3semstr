import hashlib
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
from src.hash import ALGORITHMS, SHA256, SHA3_256

ABC_448 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
ABC_896 = (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
           b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
def _git_tool(name):
    git = shutil.which("git")
    if git:
        path = os.path.join(os.path.dirname(os.path.dirname(git)), "usr", "bin", name + ".exe")
        if os.path.exists(path):
            return path
    return None


SHA256SUM = shutil.which("sha256sum") or _git_tool("sha256sum")
SHA3SUM = shutil.which("sha3sum")
OPENSSL = shutil.which("openssl")


# запуск python -m src.cli_parser с аргументами, stdin - байты для --input -
def run_cli(*args, stdin=None, cwd=ROOT):
    env = dict(os.environ, PYTHONPATH=ROOT)
    return subprocess.run([sys.executable, "-m", "src.cli_parser", *args],
                          cwd=cwd, input=stdin, capture_output=True, env=env)


class TestSha256(unittest.TestCase):
    """SHA-256: векторы NIST"""

    # примеры из FIPS 180-4 и NIST CAVP: пустая строка, abc, 448 и 896 бит, миллион 'a'
    def test_nist_vectors(self):
        vectors = {
            b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ABC_448: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ABC_896: "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            b"a" * 1_000_000: "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        }
        for data, expected in vectors.items():
            with self.subTest(len=len(data)):
                self.assertEqual(SHA256().hash(data), expected)

class TestSha3(unittest.TestCase):
    """SHA3-256: векторы NIST"""

    def test_nist_vectors(self):
        vectors = {
            b"": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            b"abc": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            ABC_448: "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
            ABC_896: "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18",
            b"a" * 1_000_000: "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
        }
        for data, expected in vectors.items():
            with self.subTest(len=len(data)):
                self.assertEqual(SHA3_256().hash(data), expected)

class TestAvalanche(unittest.TestCase):
    """Изменение одного бита входа меняет около половины битов хеша"""

    # число различающихся битов двух хешей в виде hex-строк
    @staticmethod
    def bits_changed(hash1, hash2):
        return bin(int(hash1, 16) ^ int(hash2, 16)).count("1")


    def test_example_from_task(self):
        for name, cls in ALGORITHMS.items():
            with self.subTest(name):
                diff = self.bits_changed(cls().hash(b"Hello, world!"), cls().hash(b"Hello, world?"))
                self.assertTrue(100 < diff < 156, f"only {diff} bits changed")

class TestDgstCli(unittest.TestCase):
    """Команда cryptocore dgst через командную строку"""

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

    def test_output_format(self):
        data = b"document contents\n" * 100
        path = self.write("document.txt", data)
        for name in ALGORITHMS:
            with self.subTest(name):
                r = run_cli("dgst", "--algorithm", name, "--input", path)
                self.assertEqual(r.returncode, 0, r.stderr)
                expected = getattr(hashlib, name.replace("-", "_"))(data).hexdigest()
                self.assertEqual(r.stdout, f"{expected}  {path}\n".encode())
                self.assertEqual(r.stderr, b"")

    # пустой файл даёт хеш пустой строки
    def test_empty_file(self):
        path = self.write("empty.txt", b"")
        r = run_cli("dgst", "--algorithm", "sha256", "--input", path)
        self.assertEqual(r.stdout.split()[0],
                         b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    # --input - читает stdin
    def test_stdin(self):
        cases = {
            b"abc": b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ABC_448: b"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        }
        for data, expected in cases.items():
            with self.subTest(data):
                r = run_cli("dgst", "--algorithm", "sha256", "--input", "-", stdin=data)
                self.assertEqual(r.stdout, expected + b"  -\n")

    # --output пишет в файл ту же строку, что иначе ушла бы в stdout
    def test_output_file(self):
        path = self.write("backup.tar", os.urandom(10000))
        out = os.path.join(self.dir, "backup.sha3")
        printed = run_cli("dgst", "--algorithm", "sha3-256", "--input", path)
        r = run_cli("dgst", "--algorithm", "sha3-256", "--input", path, "--output", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, b"")
        with open(out, "rb") as f:
            self.assertEqual(f.read(), printed.stdout)

    # файл в несколько кусков по 8192 байта с неровным хвостом
    def test_multi_chunk_file(self):
        data = os.urandom(3 * file_io.CHUNK_SIZE + 123)
        path = self.write("big.bin", data)
        r = run_cli("dgst", "--algorithm", "sha256", "--input", path)
        self.assertEqual(r.stdout.split()[0].decode(), hashlib.sha256(data).hexdigest())

    # ошибки: нет файла, нельзя записать результат
    def test_file_errors(self):
        r = run_cli("dgst", "--algorithm", "sha256", "--input", os.path.join(self.dir, "missing"))
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"cannot read input file", r.stderr)
        self.assertEqual(r.stdout, b"")

        path = self.write("a.txt", b"a")
        r = run_cli("dgst", "--algorithm", "sha256", "--input", path,
                    "--output", os.path.join(self.dir, "no_dir", "out"))
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"cannot write output file", r.stderr)

    # аргументы шифрования и неизвестный алгоритм команда dgst не принимает
    def test_invalid_arguments(self):
        path = self.write("a.txt", b"a")
        base = ["dgst", "--algorithm", "sha256", "--input", path]
        cases = {
            "--key": base + ["--key", "00" * 16],
            "--mode": base + ["--mode", "cbc"],
            "--iv": base + ["--iv", "00" * 16],
            "--encrypt": base + ["--encrypt"],
            "--decrypt": base + ["--decrypt"],
            "unknown algorithm": ["dgst", "--algorithm", "md5", "--input", path],
            "missing --algorithm": ["dgst", "--input", path],
            "missing --input": ["dgst", "--algorithm", "sha256"],
        }
        for name, args in cases.items():
            with self.subTest(name):
                r = run_cli(*args)
                self.assertEqual(r.returncode, 2)
                self.assertTrue(r.stderr.strip())
                self.assertEqual(r.stdout, b"")

    # вывод совпадает с sha256sum: в каталоге файла, с относительным путём
    @unittest.skipUnless(SHA256SUM, "sha256sum not found in PATH")
    def test_matches_sha256sum(self):
        for name, data in {"text.txt": b"compare with sha256sum\n" * 50,
                           "empty.bin": b"", "random.bin": os.urandom(100000)}.items():
            with self.subTest(name):
                self.write(name, data)
                ours = run_cli("dgst", "--algorithm", "sha256", "--input", name, cwd=self.dir)
                # -t: текстовый режим, в Windows без него sha256sum ставит * перед именем
                theirs = subprocess.run([SHA256SUM, "-t", name], cwd=self.dir,
                                        capture_output=True, check=True)
                self.assertEqual(ours.stdout, theirs.stdout)

    # SHA3-256 сверяется с sha3sum, а если его нет - с openssl dgst
    @unittest.skipUnless(SHA3SUM or OPENSSL, "neither sha3sum nor openssl found in PATH")
    def test_matches_system_sha3(self):
        for name, data in {"text.txt": b"compare sha3\n" * 50, "empty.bin": b"",
                           "random.bin": os.urandom(100000)}.items():
            with self.subTest(name):
                self.write(name, data)
                ours = run_cli("dgst", "--algorithm", "sha3-256", "--input", name, cwd=self.dir)
                if SHA3SUM:
                    cmd = [SHA3SUM, "-a", "256", name]
                else:
                    cmd = [OPENSSL, "dgst", "-sha3-256", "-r", name]
                theirs = subprocess.run(cmd, cwd=self.dir, capture_output=True, check=True)
                self.assertEqual(ours.stdout.split()[0], theirs.stdout.split()[0])


# hashlib.sha256 с тем же интерфейсом, что у нашего SHA256
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


def write_big_file(path, size, reference):
    with open(path, "wb") as f:
        written, i = 0, 0
        while written < size:
            piece = (i.to_bytes(8, "big") * (1 << 17))[:min(1 << 20, size - written)]
            f.write(piece)
            reference.update(piece)
            written += len(piece)
            i += 1
    return reference.hexdigest()


class TestBigFile(unittest.TestCase):
    """Файл больше 1 ГБ хешируется по кускам, память не растёт с размером файла"""

    def test_larger_than_1gb(self):
        with tempfile.TemporaryDirectory() as d:
            path, out = os.path.join(d, "big.bin"), os.path.join(d, "big.sha256")
            expected = write_big_file(path, (1 << 30) + 1, hashlib.sha256())
            tracemalloc.start()
            try:
                with mock.patch.dict(ALGORITHMS, {"sha256": FastSha256}):
                    code = cli_parser.main(["dgst", "--algorithm", "sha256",
                                            "--input", path, "--output", out])
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            self.assertEqual(code, 0)
            with open(out, "rb") as f:
                self.assertEqual(f.read().split()[0].decode(), expected)
            self.assertLess(peak, 10 << 20)

if __name__ == "__main__":
    unittest.main()
