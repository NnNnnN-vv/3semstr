
from .sha256 import SHA256
from .sha3_256 import SHA3_256

# имя алгоритма в --algorithm -> класс
ALGORITHMS = {
    "sha256": SHA256,
    "sha3-256": SHA3_256,
}
