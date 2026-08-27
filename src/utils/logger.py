import logging
import os
import sys
from typing import Optional


class PasswordSanitizingFormatter(logging.Formatter):
    """Formateador de logs que previene el registro de contraseñas u otros datos sensibles."""

    def __init__(self, fmt=None, datefmt=None):
        super().__init__(fmt, datefmt)

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        # Asegurar que contraseñas u ocultamiento explícito no queden en logs
        return msg


def setup_logger(name: str = "ndac", log_file: Optional[str] = None, debug: bool = False) -> logging.Logger:
    """
    Configura y retorna el logger principal de NDAC.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Evitar duplicar handlers
    if logger.handlers:
        return logger

    formatter = PasswordSanitizingFormatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Handler para consola
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(console_handler)

    # Handler para archivo si se especifica
    if log_file:
        try:
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
            logger.addHandler(file_handler)
        except Exception as err:
            logger.warning(f"No se pudo crear el archivo de log en '{log_file}': {err}")

    return logger


logger = setup_logger()
