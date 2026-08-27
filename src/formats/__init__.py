import os
from typing import Union, BinaryIO

MAGIC_HEADER_V6 = b"NDC6"
MAGIC_HEADER_V5 = b"NDC5"
MAGIC_HEADER_V4 = b"NDC4"
MAGIC_HEADER_V3 = b"NDC3"


def detect_format(source: Union[str, bytes, BinaryIO]) -> int:
    """
    Detecta automáticamente la versión de formato del archivo o bytes.
    Soporta rutas de archivo (str), secuencias de bytes (bytes) y streams (BinaryIO).
    Retorna 3, 4, 5 o 6. Si no coincide con ninguno, retorna 0.
    """
    magic = b""
    if isinstance(source, str):
        if not os.path.isfile(source):
            return 0
        with open(source, "rb") as f:
            magic = f.read(4)
    elif isinstance(source, bytes):
        magic = source[:4] if len(source) >= 4 else b""
    else:
        try:
            current_pos = source.tell()
            magic = source.read(4)
            source.seek(current_pos)
        except (AttributeError, OSError):
            return 0

    if magic == MAGIC_HEADER_V6:
        return 6
    elif magic == MAGIC_HEADER_V5:
        return 5
    elif magic == MAGIC_HEADER_V4:
        return 4
    elif magic == MAGIC_HEADER_V3:
        return 3
    return 0
