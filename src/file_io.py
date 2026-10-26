import sys

CHUNK_SIZE = 8192  # сколько байт читать файл при хешировании


# чтение
def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# запись в файл
def write_file(path: str, *parts: bytes) -> None:
    with open(path, "wb") as f:
        for part in parts:
            f.write(part)


# разделение содержимого зашифрованного файла
def split_iv(data: bytes, iv_size: int):
    if len(data) < iv_size:
        raise ValueError(
            f"input file is too short to contain a {iv_size}-byte IV "
            f"(got {len(data)} bytes); pass the IV with --iv if the file has no IV prefix"
        )
    return data[:iv_size], data[iv_size:]



def read_chunks(path: str, chunk_size: int = CHUNK_SIZE):
    if path == "-":
        yield from iter(lambda: sys.stdin.buffer.read(chunk_size), b"")
        return
    with open(path, "rb") as f:
        yield from iter(lambda: f.read(chunk_size), b"")
