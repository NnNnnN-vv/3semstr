# CryptoCore

Консольный инструмент для шифрования и расшифрования файлов алгоритмом AES-128 в режимах ECB, CBC, CFB, OFB и CTR, хеши SHA-256 и SHA3-256, коды аутентификации HMAC и AES-CMAC.

## Зависимости

- Python 3.8 или новее
- Pycryptodome - берётся примитив AES (ставится автоматически при установке)
- OpenSSL — необязательно, нужен только для сверки с эталонной реализацией

## Сборка и установка

```bash
git clone https://github.com/NnNnnN-vv/3semstr
cd 3semstr
pip install .
```

После этого в командной строке доступна команда `cryptocore`. Проверка:

```bash
cryptocore --help
```

## Использование

```
cryptocore --algorithm aes --mode MODE (--encrypt | --decrypt) [--key KEY] [--iv IV] --input INPUT_FILE [--output OUTPUT_FILE]
```

| Аргумент | Значение |
| :-- | :-- |
| `--algorithm` | шифр, поддерживается `aes` |
| `--mode` | режим работы: `ecb`, `cbc`, `cfb`, `ofb`, `ctr` |
| `--encrypt` / `--decrypt` | операция, указывается ровно один из флагов |
| `--key` | ключ AES-128: 32 шестнадцатеричных символа (16 байт); при шифровании необязателен |
| `--iv` | вектор инициализации: 32 шестнадцатеричных символа (16 байт), только для расшифрования в режимах `cbc`, `cfb`, `ofb`, `ctr` |
| `--input` | путь к входному файлу |
| `--output` | путь к выходному файлу; если не указан, используется `INPUT_FILE.enc` при шифровании и `INPUT_FILE.dec` при расшифровании |

При любой ошибке сообщение выводится в `stderr`, а код возврата отличен от нуля.

### Режимы

| Режим | Нужен IV | Дополнение PKCS#7 | Размер зашифрованного файла |
| :-- | :-- | :-- | :-- |
| `ecb` | нет | да | данные, дополненные до кратности 16 байт |
| `cbc` | да | да | 16 байт IV + данные, дополненные до кратности 16 байт |
| `cfb` | да | нет | 16 байт IV + столько же байт, сколько в исходном файле |
| `ofb` | да | нет | 16 байт IV + столько же байт, сколько в исходном файле |
| `ctr` | да | нет | 16 байт IV + столько же байт, сколько в исходном файле |

- `cbc` — каждый блок перед шифрованием складывается по XOR с предыдущим блоком шифротекста
- `cfb` — потоковый режим, гамма получается шифрованием предыдущего блока шифротекста, размер сегмента 128 бит
- `ofb` — потоковый режим, гамма получается повторным шифрованием IV и не зависит от данных
- `ctr` — потоковый режим, гамма получается шифрованием счётчика; счётчик начинается с IV и увеличивается на 1 для каждого блока

### Вектор инициализации (IV)

- При шифровании IV генерируется случайно (`os.urandom(16)`) и записывается в начало выходного файла: `<16 байт IV><шифротекст>`. Флаг `--iv` при шифровании не принимается — это ошибка.
- При расшифровании без `--iv` первые 16 байт входного файла считаются IV, остальное — шифротекстом. Если файл короче 16 байт, выводится ошибка.
- При расшифровании с `--iv` весь входной файл считается шифротекстом. Так расшифровываются файлы, созданные OpenSSL: он IV в файл не записывает.
- В режиме `ecb` IV не используется, флаг `--iv` с ним — ошибка.

### Примеры

ECB:

```bash
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

CBC, CFB, OFB, CTR — шифрование (IV генерируется и записывается в начало файла):

```bash
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование файла, созданного `cryptocore` (IV читается из начала файла):

```bash
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Расшифрование шифротекста без IV в файле (IV передаётся явно):

```bash
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv AABBCCDDEEFF00112233445566778899 --input openssl_cipher.bin --output decrypted.txt
```

Для других режимов меняется только значение `--mode`.

### Ключ не указан

При шифровании без `--key` генерируется случайный 16-байтовый ключ и один раз печатается в `stdout`. В файл он не пишется, сохраните его сами. При расшифровании `--key` обязателен. На слабый ключ (все байты одинаковые, байты подряд, повторы) выводится предупреждение в `stderr`.

```bash
cryptocore --algorithm aes --mode ctr --encrypt --input plain.txt --output cipher.bin
# [INFO] Generated random key: 3f9c1e0a7b52d84e6a0c91f27d3b5e08
cryptocore --algorithm aes --mode ctr --decrypt --key 3f9c1e0a7b52d84e6a0c91f27d3b5e08 --input cipher.bin --output plain.dec.txt
```

Ключи и IV берутся из `generate_random_bytes` (`src/csprng.py`), которая вызывает `os.urandom` — CSPRNG операционной системы. Его выход непредсказуем: по выданным байтам нельзя вычислить ни следующие, ни предыдущие. При сбое генератора выдаётся `RandomGenerationError`.

## Хеширование: `dgst`

```
cryptocore dgst --algorithm {sha256,sha3-256} --input FILE [--output FILE]
```

Вывод как у `sha256sum`: `хеш путь`. `--input -` читает stdin, `--output` пишет ту же строку в файл.

```bash
echo -n "abc" | cryptocore dgst --algorithm sha256 --input -
cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
```

- **SHA-256** (`src/hash/sha256.py`, FIPS 180-4)
- **SHA3-256** (`src/hash/sha3_256.py`, FIPS 202)

Оба стойки к коллизиям и поиску прообраза, изменение одного бита входа меняет примерно половину бит хеша. SHA-256 уязвим к атаке удлинением, поэтому для подписи с ключом нужен HMAC.

## HMAC и AES-CMAC

```
cryptocore dgst --algorithm ALG --hmac --key KEY --input FILE [--output FILE | --verify MAC_FILE]
cryptocore dgst --cmac --key KEY --input FILE [--output FILE | --verify MAC_FILE]
```

`--key` — hex: для HMAC любой длины, для CMAC 16 байт. Вывод: `MAC путь`. `--verify` сравнивает с первым значением в файле: `[OK]` и код 0 или `[ERROR]` и код 1.

```bash
echo -n "Hi There" > test.txt
cryptocore dgst --algorithm sha256 --hmac --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b --input test.txt
# b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 test.txt

cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt --output test.hmac
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt --verify test.hmac
# [OK] HMAC verification successful
```

**HMAC** (`src/mac/hmac.py`, RFC 2104)

```
HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))
```

Ключ длиннее блока хешируется, короче — дополняется нулями. Без ключа MAC не подделать, атака удлинением не работает.

**AES-CMAC** (`src/mac/cmac.py`, NIST SP 800-38B) — CBC-MAC на AES, последний блок перед шифрованием XOR-ится с подключом `K1` или `K2`.

## Проверка

Команды ниже рассчитаны на bash (Linux, macOS, Git Bash в Windows).

### Полный цикл: шифрование и расшифрование

```bash
echo "Hello, CryptoCore!" > plaintext.txt
for mode in ecb cbc cfb ofb ctr; do
  cryptocore --algorithm aes --mode $mode --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
  cryptocore --algorithm aes --mode $mode --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
  diff plaintext.txt decrypted.txt && echo "$mode: OK"
done
```

### Сверка с OpenSSL: ECB

```bash
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in plaintext.txt -out ciphertext_openssl.bin
diff ciphertext.bin ciphertext_openssl.bin
```

### Совместимость с OpenSSL: CBC, CFB, OFB, CTR

В этих режимах IV случайный, поэтому шифротексты двух запусков не совпадают. Проверяется другое: каждый инструмент расшифровывает то, что зашифровал другой.

**cryptocore → OpenSSL.** Файл шифруется `cryptocore`, затем делится на IV (первые 16 байт) и шифротекст, и шифротекст расшифровывается OpenSSL:

```bash
for mode in cbc cfb ofb ctr; do
  cryptocore --algorithm aes --mode $mode --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cipher.bin
  dd if=cipher.bin of=iv.bin bs=16 count=1 status=none
  dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1 status=none
  openssl enc -aes-128-$mode -d -K 000102030405060708090a0b0c0d0e0f -iv $(xxd -p iv.bin | tr -d '\n') -in ciphertext_only.bin -out decrypted_openssl.txt
  diff plaintext.txt decrypted_openssl.txt && echo "$mode: cryptocore -> openssl OK"
done
```

**OpenSSL → cryptocore.** Файл шифруется OpenSSL с известным IV, затем расшифровывается `cryptocore` с тем же IV в `--iv`:

```bash
for mode in cbc cfb ofb ctr; do
  openssl enc -aes-128-$mode -K 000102030405060708090a0b0c0d0e0f -iv AABBCCDDEEFF00112233445566778899 -in plaintext.txt -out openssl_cipher.bin
  cryptocore --algorithm aes --mode $mode --decrypt --key 000102030405060708090a0b0c0d0e0f --iv AABBCCDDEEFF00112233445566778899 --input openssl_cipher.bin --output decrypted.txt
  diff plaintext.txt decrypted.txt && echo "$mode: openssl -> cryptocore OK"
done
```

В обоих случаях для каждого из четырёх режимов выводится строка с `OK`, а `diff` не показывает различий. Режим `-aes-128-cfb` в OpenSSL — это CFB с сегментом 128 бит, как и в `cryptocore`.

### NIST STS

Скачать [NIST STS](https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software), собрать `make`, затем:

```bash
python -m src.csprng путь/sts-2.1.2/sts-2.1.2/data/cryptocore.bin 12500000
cd путь/sts-2.1.2/sts-2.1.2
printf '0\ndata/cryptocore.bin\n1\n0\n100\n1\n' | ./assess 1000000
```

Результат — в `experiments/AlgorithmTesting/finalAnalysisReport.txt`. Тест пройден, если `p-value >= 0.01`. Процедура и результаты — в TESTING.md.

### Автоматические тесты

```bash
python -m unittest discover tests -v
```

Проверяют шифрование (векторы NIST, OpenSSL), генератор ключей, хеши (векторы NIST, `sha256sum`, файл больше 1 ГБ) и HMAC/CMAC (RFC 4231, NIST SP 800-38B, `--verify`). Тесты с OpenSSL пропускаются, если его нет.

## Структура проекта

```
├── src/
│   ├── cli_parser.py     # разбор аргументов и запуск операции
│   ├── csprng.py         # генератор случайных байт
│   ├── file_io.py        # чтение и запись файлов как байтов, отделение IV
│   ├── hash/             # sha256.py, sha3_256.py
│   ├── mac/              # hmac.py, cmac.py
│   └── modes/
│       ├── ecb.py        # режим ECB и дополнение PKCS#7
│       └── iv_modes.py   # режимы CBC, CFB, OFB, CTR и генерация IV
├── tests/
│   ├── test_cryptocore.py
│   ├── test_hash.py
│   └── test_mac.py
├── pyproject.toml        # сборка и зависимости
└── README.md
```
