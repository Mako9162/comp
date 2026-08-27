import hashlib
import hmac
import os
import re
import secrets
import struct
import zlib
from typing import Optional, Tuple, Dict, Any, List

MAGIC_HEADER_V5 = b"NDC5"
FORMAT_VERSION_V5 = 5
MAGIC_HEADER_V4 = b"NDC4"
FORMAT_VERSION_V4 = 4
MAGIC_HEADER_V3 = b"NDC3"
FORMAT_VERSION_V3 = 3

MAX_ORIGINAL_SIZE = 100 * 1024 * 1024 * 1024  # 100 GB límite total
MAX_TOTAL_FILES = 100_000
MAX_EXPANSION_RATIO = 1000
CHUNK_SIZE = 1024 * 1024

HEADER_FORMAT_V5 = ">4sBB16sQIIH32s"
HEADER_SIZE_V5 = struct.calcsize(HEADER_FORMAT_V5)

HEADER_FORMAT_V4 = ">4sBB16sQIH32s"
HEADER_SIZE_V4 = struct.calcsize(HEADER_FORMAT_V4)

HEADER_FORMAT_V3 = ">4sBQIH"
HEADER_SIZE_V3 = struct.calcsize(HEADER_FORMAT_V3)

ENTRY_FORMAT = ">BHQQI"
ENTRY_HEADER_SIZE = struct.calcsize(ENTRY_FORMAT)
ENTRY_TYPE_FILE = 1
ENTRY_TYPE_DIR = 2


def compute_crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def sanitize_filename(filename: str) -> str:
    """Sanitiza nombres de archivo extraídos de cabeceras para prevenir vulnerabilidades de Path Traversal."""
    clean_name = os.path.basename(filename.replace("\\", "/"))
    clean_name = re.sub(r'[\x00-\x1f\x7f]', '', clean_name)
    if not clean_name or clean_name.strip(".") == "":
        return "archivo_restaurado"
    return clean_name


def safe_extract_path(destination_dir: str, rel_path: str) -> str:
    """
    Normaliza la ruta relativa y verifica estrictamente que al unirse con destination_dir
    la ruta resultante resida dentro de destination_dir (previene Path Traversal).
    """
    if os.path.isabs(rel_path) or rel_path.startswith("/") or rel_path.startswith("\\") or re.match(r'^[a-zA-Z]:', rel_path):
        raise ValueError(f"Ruta absoluta o con letra de unidad bloqueada (Path Traversal): {rel_path}")

    clean_rel = rel_path.replace("\\", "/")
    parts = [p for p in clean_rel.split("/") if p and p != "."]
    if len(parts) > 50:
        raise ValueError(f"Profundidad de directorio excesiva ({len(parts)} > 50) bloqueada por seguridad: {rel_path}")
    if any(p == ".." for p in parts):
        raise ValueError(f"Ruta invalida o intento de Path Traversal detectado: {rel_path}")


    safe_rel = "/".join(parts)
    dest_abs = os.path.abspath(destination_dir)
    target_abs = os.path.abspath(os.path.join(dest_abs, safe_rel))

    if not (target_abs == dest_abs or target_abs.startswith(dest_abs + os.sep)):
        raise ValueError(f"Escritura fuera del directorio de destino bloqueada (Path Traversal): {rel_path}")

    return target_abs



def format_file_size(size_in_bytes: int) -> str:
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    if size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.2f} KB"
    if size_in_bytes < 1024 * 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.2f} MB"
    return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"


def derive_keys(password: str, salt: bytes):
    """Deriva clave de cifrado (32b) y clave de autenticación MAC (32b) con PBKDF2."""
    derived = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations=100000, dklen=64)
    return derived[:32], derived[32:]


def compute_hmac_tag(mac_key: bytes, salt: bytes, original_size: int, crc32_checksum: int) -> bytes:
    msg = salt + str(original_size).encode('utf-8') + str(crc32_checksum).encode('utf-8')
    return hmac.new(mac_key, msg, hashlib.sha256).digest()


def crypt_stream_chunk(data: bytes, key: bytes, start_pos: int = 0) -> bytes:
    """Cifra/descifra un bloque de datos mediante keystream derivado por HMAC posicionalmente determinista."""
    if not key or not data:
        return data
    out = bytearray(len(data))
    curr_pos = start_pos
    end_pos = start_pos + len(data)
    written = 0

    while curr_pos < end_pos:
        blk_idx = curr_pos // 64
        blk_off = curr_pos % 64
        block_key = hmac.new(key, blk_idx.to_bytes(8, 'big'), hashlib.sha256).digest() + \
                    hmac.new(key, (blk_idx + 0x80000000).to_bytes(8, 'big'), hashlib.sha256).digest()

        take = min(end_pos - curr_pos, 64 - blk_off)
        for i in range(take):
            out[written + i] = data[written + i] ^ block_key[blk_off + i]

        written += take
        curr_pos += take

    return bytes(out)


def pack_header_v5(
    root_name: str,
    total_original_size: int,
    total_files_count: int,
    crc32_checksum: int,
    password: Optional[str] = None,
    salt: Optional[bytes] = None
) -> Tuple[bytes, Optional[bytes], bytes]:
    """Empaqueta la cabecera NDC5 (múltiples archivos / carpetas). Retorna (header_bytes, encryption_key, salt)."""
    sanitized_name = sanitize_filename(root_name)
    name_bytes = sanitized_name.encode("utf-8")
    if not 0 <= total_original_size <= MAX_ORIGINAL_SIZE:
        raise ValueError(f"El tamano original total debe estar entre 0 y {MAX_ORIGINAL_SIZE} bytes.")
    if len(name_bytes) > 0xFFFF:
        raise ValueError("El nombre raiz es demasiado largo.")

    is_encrypted = 1 if password else 0
    enc_key = None

    if password:
        if salt is None:
            salt = secrets.token_bytes(16)
        enc_key, mac_key = derive_keys(password, salt)
        hmac_tag = compute_hmac_tag(mac_key, salt, total_original_size, crc32_checksum)
    else:
        salt = b"\0" * 16
        hmac_tag = b"\0" * 32

    fixed = struct.pack(
        HEADER_FORMAT_V5,
        MAGIC_HEADER_V5,
        FORMAT_VERSION_V5,
        is_encrypted,
        salt,
        total_original_size,
        total_files_count,
        crc32_checksum,
        len(name_bytes),
        hmac_tag
    )
    return fixed + name_bytes, enc_key, salt


def pack_header(
    original_filename: str,
    original_size: int,
    crc32_checksum: int,
    password: Optional[str] = None,
    salt: Optional[bytes] = None
) -> Tuple[bytes, Optional[bytes], bytes]:
    """Empaqueta la cabecera NDC4 (un solo archivo). Retorna (header_bytes, encryption_key, salt)."""
    sanitized_name = sanitize_filename(original_filename)
    filename_bytes = sanitized_name.encode("utf-8")
    if not 0 <= original_size <= MAX_ORIGINAL_SIZE:
        raise ValueError(f"El tamano original debe estar entre 0 y {MAX_ORIGINAL_SIZE} bytes.")
    if len(filename_bytes) > 0xFFFF:
        raise ValueError("El nombre de archivo es demasiado largo.")

    is_encrypted = 1 if password else 0
    enc_key = None

    if password:
        if salt is None:
            salt = secrets.token_bytes(16)
        enc_key, mac_key = derive_keys(password, salt)
        hmac_tag = compute_hmac_tag(mac_key, salt, original_size, crc32_checksum)
    else:
        salt = b"\0" * 16
        hmac_tag = b"\0" * 32

    fixed = struct.pack(
        HEADER_FORMAT_V4,
        MAGIC_HEADER_V4,
        FORMAT_VERSION_V4,
        is_encrypted,
        salt,
        original_size,
        crc32_checksum,
        len(filename_bytes),
        hmac_tag
    )
    return fixed + filename_bytes, enc_key, salt


def pack_container_entry(entry_type: int, rel_path: str, file_size: int, mtime: int, crc32: int) -> bytes:
    """Empaqueta la cabecera de una entrada individual de contenedor NDC5."""
    clean_rel = rel_path.replace("\\", "/").strip("/")
    path_bytes = clean_rel.encode("utf-8")
    if len(path_bytes) > 0xFFFF:
        raise ValueError(f"La ruta '{rel_path}' excede la longitud maxima.")

    fixed = struct.pack(ENTRY_FORMAT, entry_type, len(path_bytes), file_size, int(mtime), crc32 & 0xFFFFFFFF)
    return fixed + path_bytes


def unpack_header(stream_bytes: bytes, password: Optional[str] = None):
    """
    Desempaqueta cabeceras NDC5, NDC4 o NDC3.
    Retorna: (filename/root_name, original_size, crc32_checksum, payload_offset, is_encrypted, encryption_key, format_version, total_files_count)
    """
    if len(stream_bytes) < 4:
        raise ValueError("El archivo comprimido esta corrupto o tiene una cabecera incompleta.")

    magic = stream_bytes[:4]

    if magic == MAGIC_HEADER_V5:
        if len(stream_bytes) < HEADER_SIZE_V5:
            raise ValueError("Cabecera NDC5 incompleta.")
        magic, version, is_encrypted, salt, total_original_size, total_files_count, crc32_checksum, name_len, hmac_tag = struct.unpack(
            HEADER_FORMAT_V5, stream_bytes[:HEADER_SIZE_V5]
        )
        if version != FORMAT_VERSION_V5:
            raise ValueError("Version de formato NDC5 no compatible.")
        payload_offset = HEADER_SIZE_V5 + name_len
        if len(stream_bytes) < payload_offset:
            raise ValueError("El archivo comprimido tiene metadatos truncados.")
        raw_name = stream_bytes[HEADER_SIZE_V5:payload_offset].decode("utf-8", errors="replace")
        root_name = sanitize_filename(raw_name)

        enc_key = None
        if is_encrypted:
            if not password:
                raise ValueError("Este archivo esta protegido con contrasena. Introduce la contrasena para continuar.")
            enc_key, mac_key = derive_keys(password, salt)
            expected_hmac = compute_hmac_tag(mac_key, salt, total_original_size, crc32_checksum)
            if not hmac.compare_digest(hmac_tag, expected_hmac):
                raise ValueError("Contrasena incorrecta o archivo dañado.")

        return root_name, total_original_size, crc32_checksum, payload_offset, bool(is_encrypted), enc_key, 5, total_files_count

    elif magic == MAGIC_HEADER_V4:
        if len(stream_bytes) < HEADER_SIZE_V4:
            raise ValueError("Cabecera NDC4 incompleta.")
        magic, version, is_encrypted, salt, original_size, crc32_checksum, filename_len, hmac_tag = struct.unpack(
            HEADER_FORMAT_V4, stream_bytes[:HEADER_SIZE_V4]
        )
        if version != FORMAT_VERSION_V4:
            raise ValueError("Version de formato NDC4 no compatible.")
        payload_offset = HEADER_SIZE_V4 + filename_len
        if len(stream_bytes) < payload_offset:
            raise ValueError("El archivo comprimido tiene metadatos truncados.")
        raw_filename = stream_bytes[HEADER_SIZE_V4:payload_offset].decode("utf-8", errors="replace")
        filename = sanitize_filename(raw_filename)

        enc_key = None
        if is_encrypted:
            if not password:
                raise ValueError("Este archivo esta protegido con contrasena. Introduce la contrasena para continuar.")
            enc_key, mac_key = derive_keys(password, salt)
            expected_hmac = compute_hmac_tag(mac_key, salt, original_size, crc32_checksum)
            if not hmac.compare_digest(hmac_tag, expected_hmac):
                raise ValueError("Contrasena incorrecta o archivo dañado.")

        return filename, original_size, crc32_checksum, payload_offset, bool(is_encrypted), enc_key, 4, 1

    elif magic == MAGIC_HEADER_V3:
        if len(stream_bytes) < HEADER_SIZE_V3:
            raise ValueError("Cabecera NDC3 incompleta.")
        magic, version, original_size, crc32_checksum, filename_len = struct.unpack(
            HEADER_FORMAT_V3, stream_bytes[:HEADER_SIZE_V3]
        )
        if version != FORMAT_VERSION_V3:
            raise ValueError("Version de formato NDC3 no compatible.")
        payload_offset = HEADER_SIZE_V3 + filename_len
        if len(stream_bytes) < payload_offset:
            raise ValueError("El archivo comprimido tiene metadatos truncados.")
        raw_filename = stream_bytes[HEADER_SIZE_V3:payload_offset].decode("utf-8", errors="replace")
        filename = sanitize_filename(raw_filename)
        return filename, original_size, crc32_checksum, payload_offset, False, None, 3, 1

    else:
        raise ValueError("Formato no compatible. Se requiere un archivo .ndac (NDC5/NDC4/NDC3).")


def read_header(file_object, password: Optional[str] = None):
    """Lee solo la cabecera del archivo comprimido NDC5, NDC4 o NDC3."""
    magic = file_object.read(4)
    if len(magic) < 4:
        raise ValueError("El archivo esta vacio o corrupto.")
    file_object.seek(0)

    if magic == MAGIC_HEADER_V5:
        fixed_header = file_object.read(HEADER_SIZE_V5)
        if len(fixed_header) != HEADER_SIZE_V5:
            raise ValueError("Cabecera NDC5 incompleta.")
        _, _, _, _, _, _, _, name_len, _ = struct.unpack(HEADER_FORMAT_V5, fixed_header)
        name_bytes = file_object.read(name_len)
        return unpack_header(fixed_header + name_bytes, password=password)
    elif magic == MAGIC_HEADER_V4:
        fixed_header = file_object.read(HEADER_SIZE_V4)
        if len(fixed_header) != HEADER_SIZE_V4:
            raise ValueError("Cabecera NDC4 incompleta.")
        _, _, _, _, _, _, filename_len, _ = struct.unpack(HEADER_FORMAT_V4, fixed_header)
        filename_bytes = file_object.read(filename_len)
        return unpack_header(fixed_header + filename_bytes, password=password)
    elif magic == MAGIC_HEADER_V3:
        fixed_header = file_object.read(HEADER_SIZE_V3)
        if len(fixed_header) != HEADER_SIZE_V3:
            raise ValueError("Cabecera NDC3 incompleta.")
        _, _, _, _, filename_len = struct.unpack(HEADER_FORMAT_V3, fixed_header)
        filename_bytes = file_object.read(filename_len)
        return unpack_header(fixed_header + filename_bytes, password=password)
    else:
        raise ValueError("Formato no compatible. Se requiere un archivo .ndac (NDC5/NDC4/NDC3).")


def inspect_header(file_object) -> Dict[str, Any]:
    """
    Inspecciona metadatos de cabecera NDC5, NDC4 o NDC3 sin requerir contraseña previa.
    """
    magic = file_object.read(4)
    if len(magic) < 4:
        raise ValueError("El archivo esta vacio o corrupto.")
    file_object.seek(0)

    if magic == MAGIC_HEADER_V5:
        fixed_header = file_object.read(HEADER_SIZE_V5)
        if len(fixed_header) != HEADER_SIZE_V5:
            raise ValueError("Cabecera NDC5 incompleta.")
        _, version, is_encrypted, salt, total_original_size, total_files_count, crc32_checksum, name_len, hmac_tag = struct.unpack(
            HEADER_FORMAT_V5, fixed_header
        )
        name_bytes = file_object.read(name_len)
        if len(name_bytes) < name_len:
            raise ValueError("Cabecera NDC5 con nombre truncado.")
        raw_name = name_bytes.decode("utf-8", errors="replace")
        root_name = sanitize_filename(raw_name)
        payload_offset = HEADER_SIZE_V5 + name_len
        return {
            "format": "NDC5",
            "version": version,
            "is_encrypted": bool(is_encrypted),
            "filename": root_name,
            "original_size": total_original_size,
            "total_files_count": total_files_count,
            "crc32_checksum": crc32_checksum,
            "payload_offset": payload_offset,
            "salt": salt,
            "hmac_tag": hmac_tag,
        }
    elif magic == MAGIC_HEADER_V4:
        fixed_header = file_object.read(HEADER_SIZE_V4)
        if len(fixed_header) != HEADER_SIZE_V4:
            raise ValueError("Cabecera NDC4 incompleta.")
        _, version, is_encrypted, salt, original_size, crc32_checksum, filename_len, hmac_tag = struct.unpack(
            HEADER_FORMAT_V4, fixed_header
        )
        filename_bytes = file_object.read(filename_len)
        if len(filename_bytes) < filename_len:
            raise ValueError("Cabecera NDC4 con nombre de archivo incompleto.")
        raw_filename = filename_bytes.decode("utf-8", errors="replace")
        filename = sanitize_filename(raw_filename)
        payload_offset = HEADER_SIZE_V4 + filename_len
        return {
            "format": "NDC4",
            "version": version,
            "is_encrypted": bool(is_encrypted),
            "filename": filename,
            "original_size": original_size,
            "total_files_count": 1,
            "crc32_checksum": crc32_checksum,
            "payload_offset": payload_offset,
            "salt": salt,
            "hmac_tag": hmac_tag,
        }
    elif magic == MAGIC_HEADER_V3:
        fixed_header = file_object.read(HEADER_SIZE_V3)
        if len(fixed_header) != HEADER_SIZE_V3:
            raise ValueError("Cabecera NDC3 incompleta.")
        _, version, original_size, crc32_checksum, filename_len = struct.unpack(
            HEADER_FORMAT_V3, fixed_header
        )
        filename_bytes = file_object.read(filename_len)
        if len(filename_bytes) < filename_len:
            raise ValueError("Cabecera NDC3 con nombre de archivo incompleto.")
        raw_filename = filename_bytes.decode("utf-8", errors="replace")
        filename = sanitize_filename(raw_filename)
        payload_offset = HEADER_SIZE_V3 + filename_len
        return {
            "format": "NDC3",
            "version": version,
            "is_encrypted": False,
            "filename": filename,
            "original_size": original_size,
            "total_files_count": 1,
            "crc32_checksum": crc32_checksum,
            "payload_offset": payload_offset,
            "salt": None,
            "hmac_tag": None,
        }
    else:
        raise ValueError("Formato no compatible. Se requiere un archivo .ndac (NDC5/NDC4/NDC3).")
