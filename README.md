# CryptoCore

Консольный инструмент для шифрования и расшифрования файлов алгоритмом AES-128 в режиме ECB.

## Зависимости

- Python 3.8 или новее
- Pycryptodome - берётся примитив AES (ставится автоматически при установке)
- OpenSSL — необязательно, нужен только для сверки с эталонной реализацией

## Сборка и установка

```bash
git clone <https://github.com/NnNnnN-vv/3semstr>
cd sprinti
pip install .
```

После этого в командной строке доступна команда `cryptocore`. Проверка:

```bash
cryptocore --help
```

## Использование

```
cryptocore --algorithm aes --mode ecb (--encrypt | --decrypt) --key KEY --input INPUT_FILE [--output OUTPUT_FILE]
```

| Аргумент | Значение |
| :-- | :-- |
| `--algorithm` | шифр, поддерживается `aes` |
| `--mode` | режим работы, поддерживается `ecb` |
| `--encrypt` / `--decrypt` | операция, указывается ровно один из флагов |
| `--key` | ключ AES-128: 32 шестнадцатеричных символа (16 байт) |
| `--input` | путь к входному файлу |
| `--output` | путь к выходному файлу; если не указан, используется `INPUT_FILE.enc` при шифровании и `INPUT_FILE.dec` при расшифровании |

Шифрование:

```bash
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование:

```bash
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

При любой ошибке (неверные аргументы, недоступный файл, повреждённый шифротекст или неверный ключ) сообщение выводится в `stderr`, а код возврата отличен от нуля.

## Проверка

### Полный цикл: шифрование и расшифрование

```bash
echo "Hello, CryptoCore!" > plaintext.txt
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
diff plaintext.txt decrypted.txt
```


### Сверка с OpenSSL

```bash
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in plaintext.txt -out ciphertext_openssl.bin
diff ciphertext.bin ciphertext_openssl.bin
```


### Автоматические тесты

```bash
python -m unittest discover tests -v
```

## Структура проекта

```
├── src/
│   ├── cli_parser.py     # разбор аргументов и запуск операции
│   ├── file_io.py        # чтение и запись файлов как байтов
│   └── modes/
│       └── ecb.py        # режим ECB и дополнение PKCS#7
├── tests/
│   └── test_cryptocore.py
├── pyproject.toml        # сборка и зависимости
└── README.md
```
