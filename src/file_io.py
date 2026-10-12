

def read_file(path: str) -> bytes:
    """Чтение всего файла в память"""
    # "rb" - чтение в двоичном режиме, with закрывает файл даже при ошибке
    with open(path, "rb") as f:
        return f.read()


def write_file(path: str, data: bytes) -> None:
    """Запись байтов в файл, существующий файл перезаписывается"""
    # "wb" - запись в двоичном режиме
    with open(path, "wb") as f:
        f.write(data)
