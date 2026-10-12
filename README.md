# CryptoCore

Консольный инструмент для шифрования и расшифрования файлов алгоритмом AES-128 в режимах ECB, CBC, CFB, OFB и CTR.

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
cryptocore --algorithm aes --mode MODE (--encrypt | --decrypt) --key KEY [--iv IV] --input INPUT_FILE [--output OUTPUT_FILE]
```

| Аргумент | Значение |
| :-- | :-- |
| `--algorithm` | шифр, поддерживается `aes` |
| `--mode` | режим работы: `ecb`, `cbc`, `cfb`, `ofb`, `ctr` |
| `--encrypt` / `--decrypt` | операция, указывается ровно один из флагов |
| `--key` | ключ AES-128: 32 шестнадцатеричных символа (16 байт) |
| `--iv` | вектор инициализации: 32 шестнадцатеричных символа (16 байт), только для расшифрования в режимах `cbc`, `cfb`, `ofb`, `ctr` |
| `--input` | путь к входному файлу |
| `--output` | путь к выходному файлу; если не указан, используется `INPUT_FILE.enc` при шифровании и `INPUT_FILE.dec` при расшифровании |

При любой ошибке (неверные аргументы, недоступный файл, повреждённый шифротекст или неверный ключ) сообщение выводится в `stderr`, а код возврата отличен от нуля.

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

### Автоматические тесты

```bash
python -m unittest discover tests -v
```

Тесты повторяют все проверки выше для текстовых, бинарных и пустых файлов, а также сверяют режимы с векторами NIST SP 800-38A. Тесты с OpenSSL пропускаются, если `openssl` не установлен.

## Структура проекта

```
├── src/
│   ├── cli_parser.py     # разбор аргументов и запуск операции
│   ├── file_io.py        # чтение и запись файлов как байтов, отделение IV
│   └── modes/
│       ├── ecb.py        # режим ECB и дополнение PKCS#7
│       └── iv_modes.py   # режимы CBC, CFB, OFB, CTR и генерация IV
├── tests/
│   └── test_cryptocore.py
├── pyproject.toml        # сборка и зависимости
└── README.md
```
