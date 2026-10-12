"""разбор аргументов -> чтение файла -> шифрование или расшифрование -> запись файла
"""

import argparse  # стандартный разбор аргументов командной строки
import sys

from .file_io import read_file, write_file
from .modes import ecb


def hex_key(value: str) -> bytes:
    """Преобразование hex-строки из --key в 16 байт ключа AES-128

    Два hex-символа дают один байт, поэтому для 16 байт нужно 32 символа
    argparse вызывает эту функцию сам для значения --key
    """
    try:
        # ошибка при посторонних символах или нечётной длине
        key = bytes.fromhex(value)
    except ValueError:
        #  сообщение об ошибке аргумента
        raise argparse.ArgumentTypeError("key must be a hexadecimal string")
    # bytes.fromhex допускает пробелы внутри строки, поэтому проверяется и длина строки
    if len(key) != ecb.KEY_SIZE or len(value) != ecb.KEY_SIZE * 2:
        raise argparse.ArgumentTypeError(
            f"key must be exactly {ecb.KEY_SIZE * 2} hex characters "
            f"({ecb.KEY_SIZE} bytes) for AES-128"
        )
    return key


def build_parser() -> argparse.ArgumentParser:
    """Описание всех аргументов и правил их проверки"""
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Encrypt or decrypt a file with AES-128 in ECB mode.",
        # запрет сокращений вроде --enc вместо --encrypt
        allow_abbrev=False,
    )
    # required - аргумент обязателен, choices - список допустимых значений
    parser.add_argument("--algorithm", required=True, choices=["aes"], help="cipher: aes")
    parser.add_argument("--mode", required=True, choices=["ecb"], help="mode of operation: ecb")
    # взаимоисключающая группа: должен быть задан ровно один флаг из двух
    operation = parser.add_mutually_exclusive_group(required=True)
    # store_true - флаг без значения: True, если указан
    operation.add_argument("--encrypt", action="store_true", help="encrypt the input file")
    operation.add_argument("--decrypt", action="store_true", help="decrypt the input file")
    # type=hex_key - значение проходит через hex_key, в args.key попадают уже байты
    parser.add_argument("--key", required=True, type=hex_key, metavar="KEY",
                        help="key as 32 hex characters, e.g. 000102030405060708090a0b0c0d0e0f")
    parser.add_argument("--input", required=True, metavar="INPUT_FILE", help="input file path")
    # --output необязателен
    parser.add_argument("--output", metavar="OUTPUT_FILE",
                        help="output file path (default: INPUT_FILE.enc or INPUT_FILE.dec)")
    return parser


def main(argv=None) -> int:
    """Запуск программы, возвращает код возврата: 0 - успех, 1 - ошибка"""
    # при ошибке в аргументах argparse пишет сообщение в stderr и выходит с кодом 2
    args = build_parser().parse_args(argv)
    # имя выходного файла по умолчанию: имя входного + .enc или .dec
    output = args.output or args.input + (".enc" if args.encrypt else ".dec")

    #чтение входного файла
    try:
        data = read_file(args.input)
    except OSError as e:
        # OSError - файл не найден, нет прав, вместо файла указан каталог
        print(f"cryptocore: error: cannot read input file '{args.input}': {e.strerror}",
              file=sys.stderr)
        return 1

    #шифрование или расшифрование
    try:
        result = ecb.encrypt(args.key, data) if args.encrypt else ecb.decrypt(args.key, data)
    except ValueError as e:
        # ValueError - неверная длина шифротекста или неверное дополнение
        print(f"cryptocore: error: {e}", file=sys.stderr)
        return 1

    # запись результата, выполняется только если шаг до этого прошёл без ошибок
    try:
        write_file(output, result)
    except OSError as e:
        print(f"cryptocore: error: cannot write output file '{output}': {e.strerror}",
              file=sys.stderr)
        return 1
    return 0



if __name__ == "__main__":
    sys.exit(main())
