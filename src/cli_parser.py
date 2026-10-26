import argparse  #
import sys

from . import hash as hash_algorithms
from . import mac
from .csprng import RandomGenerationError, generate_random_bytes
from .file_io import read_chunks, read_file, split_iv, write_file
from .modes import ecb, iv_modes


# преобразование hex-строки в байты
def _hex_bytes(value: str, name: str, size: int) -> bytes:
    try:
        result = bytes.fromhex(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{name} must be a hexadecimal string")
    if len(result) != size or len(value) != size * 2:
        raise argparse.ArgumentTypeError(
            f"{name} must be exactly {size * 2} hex characters ({size} bytes)"
        )
    return result


# значение --key
def hex_key(value: str) -> bytes:
    return _hex_bytes(value, "key", ecb.KEY_SIZE)


# значение --iv
def hex_iv(value: str) -> bytes:
    return _hex_bytes(value, "IV", iv_modes.IV_SIZE)

def weak_key_reason(key: bytes):
    if len(set(key)) == 1:
        return "all bytes are the same"
    steps = {(b - a) % 256 for a, b in zip(key, key[1:])}
    if steps == {1} or steps == {255}:
        return "bytes are sequential"
    for period in (2, 4, 8):
        if key == key[:period] * (len(key) // period):
            return f"key repeats a {period}-byte pattern"
    return None


# описание всех аргументов и правил их проверки
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Шифрование файлов AES-128 в режимах ECB, CBC, CFB, OFB и CTR",
        epilog="хеширование: cryptocore dgst --algorithm {sha256,sha3-256} --input FILE "
               "(подробнее: cryptocore dgst --help)",
        # запрет сокращений
        allow_abbrev=False,
    )
    parser.add_argument("--algorithm", required=True, choices=["aes"], help="cipher: aes")
    parser.add_argument("--mode", required=True, choices=["ecb", *iv_modes.MODES],
                        help="mode of operation")
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true", help="encrypt the input file")
    operation.add_argument("--decrypt", action="store_true", help="decrypt the input file")
    parser.add_argument("--key", type=hex_key, metavar="KEY",
                        help="key as 32 hex characters, e.g. 000102030405060708090a0b0c0d0e0f; "
                             "required for --decrypt, generated randomly for --encrypt if omitted")
    parser.add_argument("--iv", type=hex_iv, metavar="IV",
                        help="IV as 32 hex characters, decryption only "
                             "(default: first 16 bytes of INPUT_FILE)")
    parser.add_argument("--input", required=True, metavar="INPUT_FILE", help="input file path")
    parser.add_argument("--output", metavar="OUTPUT_FILE",
                        help="output file path (default: INPUT_FILE.enc or INPUT_FILE.dec)")
    return parser


# значение --key для HMAC
def hex_mac_key(value: str) -> bytes:
    try:
        result = bytes.fromhex(value)
    except ValueError:
        raise argparse.ArgumentTypeError("key must be a hexadecimal string")
    if len(value) != len(result) * 2:
        raise argparse.ArgumentTypeError("key must be a hexadecimal string without spaces")
    if not result:
        raise argparse.ArgumentTypeError("key must not be empty")
    return result


# аргументы подкоманды dgst
def build_dgst_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore dgst",
        description="Хеш файла (SHA-256, SHA3-256) или код аутентификации (HMAC, AES-CMAC)",
        allow_abbrev=False,
    )

    parser.add_argument("--algorithm", choices=list(hash_algorithms.ALGORITHMS),
                        help="hash algorithm (required unless --cmac)")
    parser.add_argument("--input", required=True, metavar="INPUT_FILE",
                        help="file to hash, '-' for standard input")
    parser.add_argument("--output", metavar="OUTPUT_FILE",
                        help="write the hash line to this file instead of stdout")
    mac_group = parser.add_mutually_exclusive_group()
    mac_group.add_argument("--hmac", action="store_true", help="compute HMAC with --key")
    mac_group.add_argument("--cmac", action="store_true", help="compute AES-128 CMAC with --key")
    parser.add_argument("--key", type=hex_mac_key, metavar="KEY",
                        help="MAC key as hex, any length for --hmac, 32 hex characters for --cmac")
    parser.add_argument("--verify", metavar="MAC_FILE",
                        help="compare the computed MAC with the first value in MAC_FILE")
    return parser


# проверки сочетаний аргументов dgst
def check_dgst_args(parser, args) -> None:
    is_mac = args.hmac or args.cmac
    if args.cmac and args.algorithm:
        parser.error("argument --algorithm: not allowed with --cmac, CMAC always uses AES-128")
    if not args.cmac and not args.algorithm:
        parser.error("argument --algorithm: required")
    if is_mac and args.key is None:
        parser.error("argument --key: required with --hmac and --cmac")
    if not is_mac and args.key is not None:
        parser.error("argument --key: allowed only with --hmac or --cmac")
    if args.cmac and len(args.key) != ecb.KEY_SIZE:
        parser.error(f"argument --key: CMAC key must be exactly {ecb.KEY_SIZE * 2} hex characters")
    if args.verify and not is_mac:
        parser.error("argument --verify: allowed only with --hmac or --cmac")
    if args.verify and args.output:
        parser.error("argument --verify: not allowed with --output")


# первое слово файла с ожидаемым MAC
def read_expected_mac(path: str) -> bytes:
    with open(path, "rb") as f:
        words = f.read().split()
    if not words:
        raise ValueError(f"MAC file '{path}' is empty")
    try:
        return bytes.fromhex(words[0].decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError(f"MAC file '{path}' does not start with a hexadecimal value")



def dgst_main(argv) -> int:
    parser = build_dgst_parser()
    args = parser.parse_args(argv)
    check_dgst_args(parser, args)

    if args.hmac:
        hasher, name = mac.HMAC(args.key, args.algorithm), "HMAC"
    elif args.cmac:
        hasher, name = mac.CMAC(args.key), "CMAC"
    else:
        hasher, name = hash_algorithms.ALGORITHMS[args.algorithm](), None
    try:

        for chunk in read_chunks(args.input):
            hasher.update(chunk)
    except OSError as e:
        print(f"cryptocore: error: cannot read input file '{args.input}': {e.strerror}",
              file=sys.stderr)
        return 1

    if args.verify:
        try:
            expected = read_expected_mac(args.verify)
        except OSError as e:
            print(f"cryptocore: error: cannot read MAC file '{args.verify}': {e.strerror}",
                  file=sys.stderr)
            return 1
        except ValueError as e:
            print(f"cryptocore: error: {e}", file=sys.stderr)
            return 1
        # сравнение за постоянное время, чтобы по задержке нельзя было подбирать MAC
        if mac.constant_time_equal(hasher.digest(), expected):
            print(f"[OK] {name} verification successful")
            return 0
        print(f"[ERROR] {name} verification failed", file=sys.stderr)
        return 1

    separator = " " if name else "  "
    line = f"{hasher.hexdigest()}{separator}{args.input}\n".encode("utf-8")
    if args.output:
        try:
            write_file(args.output, line)
        except OSError as e:
            print(f"cryptocore: error: cannot write output file '{args.output}': {e.strerror}",
                  file=sys.stderr)
            return 1
    else:
        # байты напрямую, иначе Windows заменит \n на \r\n и вывод не совпадёт с sha256sum
        sys.stdout.buffer.write(line)
        sys.stdout.flush()
    return 0


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if argv and argv[0] == "dgst":
        return dgst_main(argv[1:])
    parser = build_parser()
    # при ошибке в аргументах
    args = parser.parse_args(argv)
    # проверки сочетаний аргументов
    if args.iv is not None and args.encrypt:
        parser.error("argument --iv: not allowed with --encrypt, "
                     "the IV is generated automatically")
    if args.iv is not None and args.mode == "ecb":
        parser.error("argument --iv: not allowed with --mode ecb, ECB does not use an IV")
    if args.key is None and args.decrypt:
        parser.error("argument --key: required for --decrypt")
    output = args.output or args.input + (".enc" if args.encrypt else ".dec")


    try:
        data = read_file(args.input)
    except OSError as e:
        print(f"cryptocore: error: cannot read input file '{args.input}': {e.strerror}",
              file=sys.stderr)
        return 1

    # ключ
    if args.key is None:
        try:
            args.key = generate_random_bytes(ecb.KEY_SIZE)
        except RandomGenerationError as e:
            print(f"cryptocore: error: {e}", file=sys.stderr)
            return 1
        print(f"[INFO] Generated random key: {args.key.hex()}", flush=True)
    else:
        reason = weak_key_reason(args.key)
        if reason:
            print(f"[WARNING] the key looks weak ({reason}), use a random key instead",
                  file=sys.stderr)

    #шифрование или расшифрование
    try:
        if args.mode == "ecb":
            # ECB работает без IV
            result = [ecb.encrypt(args.key, data) if args.encrypt else ecb.decrypt(args.key, data)]
        else:
            encrypt, decrypt = iv_modes.MODES[args.mode]
            if args.encrypt:
                # новый случайный IV для каждого шифрования
                iv = iv_modes.generate_iv()
                result = [iv, encrypt(args.key, iv, data)]
            else:
                if args.iv is not None:
                    # IV задан в командной строке
                    iv = args.iv
                else:
                    # IV не задан
                    iv, data = split_iv(data, iv_modes.IV_SIZE)
                result = [decrypt(args.key, iv, data)]
    except (ValueError, RandomGenerationError) as e:
        print(f"cryptocore: error: {e}", file=sys.stderr)
        return 1

    # запись результата
    try:
        write_file(output, *result)
    except OSError as e:
        print(f"cryptocore: error: cannot write output file '{output}': {e.strerror}",
              file=sys.stderr)
        return 1
    return 0



if __name__ == "__main__":
    sys.exit(main())
