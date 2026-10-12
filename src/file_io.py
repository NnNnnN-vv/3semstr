


def read_file(path: str) -> bytes:
    """Чтение всего файла в память"""
    # "rb" - чтение в двоичном режиме, with закрывает файл даже при ошибке
    with open(path, "rb") as f:
        return f.read()


def write_file(path: str, *parts: bytes) -> None:
    """Запись частей в файл
    При шифровании с IV частей две: сначала IV, затем шифротекст
    """
    # "wb" - запись в двоичном режиме
    with open(path, "wb") as f:
        for part in parts:
            f.write(part)


def split_iv(data: bytes, iv_size: int):
    """Разделение содержимого зашифрованного файла на IV и шифротекст
    Первые iv_size байт - IV, всё остальное - шифротекст
    """
    # файл короче IV не может быть результатом шифрования
    if len(data) < iv_size:
        raise ValueError(
            f"input file is too short to contain a {iv_size}-byte IV "
            f"(got {len(data)} bytes); pass the IV with --iv if the file has no IV prefix"
        )
    return data[:iv_size], data[iv_size:]
