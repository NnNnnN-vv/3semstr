"""разбор аргументов -> чтение файла -> шифрование или расшифрование -> запись файла
"""

import argparse  # стандартный разбор аргументов командной строки
import sys

from .file_io import read_file, split_iv, write_file
from .modes import ecb, iv_modes


def _hex_bytes(value: str, name: str, size: int) -> bytes:
    """Преобразование hex-строки в байты с проверкой длины
    Два hex-символа дают один байт, поэтому для 16 байт нужно 32 символа
    """
    try:
        # ошибка при посторонних символах или нечётной длине
        result = bytes.fromhex(value)
    except ValueError:
        #  сообщение об ошибке аргумента
        raise argparse.ArgumentTypeError(f"{name} must be a hexadecimal string")
    # bytes.fromhex допускает пробелы внутри строки, поэтому проверяется и длина строки
    if len(result) != size or len(value) != size * 2:
        raise argparse.ArgumentTypeError(
            f"{name} must be exactly {size * 2} hex characters ({size} bytes)"
        )
    return result


def hex_key(value: str) -> bytes:
    """Значение --key: 16 байт ключа AES-128, argparse вызывает эту функцию сам"""
    return _hex_bytes(value, "key", ecb.KEY_SIZE)


def hex_iv(value: str) -> bytes:
    """Значение --iv: 16 байт вектора инициализации"""
    return _hex_bytes(value, "IV", iv_modes.IV_SIZE)


def build_parser() -> argparse.ArgumentParser:
    """Описание всех аргументов и правил их проверки"""
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Шифрование файлов AES-128 в режимах ECB, CBC, CFB, OFB и CTR",
        # запрет сокращений
        allow_abbrev=False,
    )
    # required - аргумент обязателен, choices - список допустимых значений
    parser.add_argument("--algorithm", required=True, choices=["aes"], help="cipher: aes")
    parser.add_argument("--mode", required=True, choices=["ecb", *iv_modes.MODES],
                        help="mode of operation")
    # взаимоисключающая группа: должен быть задан ровно один флаг из двух
    operation = parser.add_mutually_exclusive_group(required=True)
    # store_true - флаг без значения: True, если указан
    operation.add_argument("--encrypt", action="store_true", help="encrypt the input file")
    operation.add_argument("--decrypt", action="store_true", help="decrypt the input file")
    # type=hex_key - значение проходит через hex_key, в args.key попадают уже байты
    parser.add_argument("--key", required=True, type=hex_key, metavar="KEY",
                        help="key as 32 hex characters, e.g. 000102030405060708090a0b0c0d0e0f")
    # --iv необязателен и разрешён только при расшифровании в режимах с IV
    parser.add_argument("--iv", type=hex_iv, metavar="IV",
                        help="IV as 32 hex characters, decryption only "
                             "(default: first 16 bytes of INPUT_FILE)")
    parser.add_argument("--input", required=True, metavar="INPUT_FILE", help="input file path")
    # --output необязателен
    parser.add_argument("--output", metavar="OUTPUT_FILE",
                        help="output file path (default: INPUT_FILE.enc or INPUT_FILE.dec)")
    return parser


def main(argv=None) -> int:
    """Запуск программы, возвращает код возврата: 0 - успех, 1 - ошибка"""
    parser = build_parser()
    # при ошибке в аргументах argparse пишет сообщение в stderr и выходит с кодом 2
    args = parser.parse_args(argv)
    # проверки сочетаний аргументов, parser.error тоже пишет в stderr и выходит с кодом 2
    if args.iv is not None and args.encrypt:
        # при шифровании IV всегда случайный, свой IV задать нельзя
        parser.error("argument --iv: not allowed with --encrypt, "
                     "the IV is generated automatically")
    if args.iv is not None and args.mode == "ecb":
        parser.error("argument --iv: not allowed with --mode ecb, ECB does not use an IV")
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

    #шифрование или расшифрование, result - части выходного файла по порядку
    try:
        if args.mode == "ecb":
            # ECB работает без IV
            result = [ecb.encrypt(args.key, data) if args.encrypt else ecb.decrypt(args.key, data)]
        else:
            encrypt, decrypt = iv_modes.MODES[args.mode]
            if args.encrypt:
                # новый случайный IV для каждого шифрования, в файл он пишется первым
                iv = iv_modes.generate_iv()
                result = [iv, encrypt(args.key, iv, data)]
            else:
                if args.iv is not None:
                    # IV задан в командной строке: весь файл - шифротекст
                    iv = args.iv
                else:
                    # IV не задан: первые 16 байт файла - IV, остальное - шифротекст
                    iv, data = split_iv(data, iv_modes.IV_SIZE)
                result = [decrypt(args.key, iv, data)]
    except ValueError as e:
        # ValueError - файл короче IV, неверная длина шифротекста или неверное дополнение
        print(f"cryptocore: error: {e}", file=sys.stderr)
        return 1

    # запись результата, выполняется только если шаг до этого прошёл без ошибок
    try:
        write_file(output, *result)
    except OSError as e:
        print(f"cryptocore: error: cannot write output file '{output}': {e.strerror}",
              file=sys.stderr)
        return 1
    return 0



if __name__ == "__main__":
    sys.exit(main())
