import os
import sys


class RandomGenerationError(Exception):
    """Генератор ОС не смог выдать случайные байты"""


# криптографически стойкая случайная строка байтов заданной длины
def generate_random_bytes(num_bytes: int) -> bytes:
    if not isinstance(num_bytes, int) or isinstance(num_bytes, bool):
        raise TypeError(f"num_bytes must be an int, got {type(num_bytes).__name__}")
    if num_bytes <= 0:
        raise ValueError(f"num_bytes must be positive, got {num_bytes}")
    try:
        data = os.urandom(num_bytes)
    except (OSError, NotImplementedError) as e:
        raise RandomGenerationError(
            f"cannot get {num_bytes} random bytes from the operating system: {e}"
        ) from e
    if len(data) != num_bytes:
        raise RandomGenerationError(
            f"operating system returned {len(data)} random bytes instead of {num_bytes}"
        )
    return data


def write_random_file(path: str, total_size: int, chunk_size: int = 1 << 20) -> None:
    with open(path, "wb") as f:
        written = 0
        while written < total_size:
            chunk = generate_random_bytes(min(chunk_size, total_size - written))
            f.write(chunk)
            written += len(chunk)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python -m src.csprng OUTPUT_FILE SIZE_IN_BYTES", file=sys.stderr)
        sys.exit(2)
    write_random_file(sys.argv[1], int(sys.argv[2]))
    print(f"wrote {sys.argv[2]} random bytes to {sys.argv[1]}")
