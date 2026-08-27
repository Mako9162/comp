import hashlib
import hmac
import os
import re
import secrets
import struct
import zlib

MAGIC_HEADER_V4 = b"NDC4"
FORMAT_VERSION_V4 = 4
MAGIC_HEADER_V3 = b"NDC3"
FORMAT_VERSION_V3 = 3

MAX_ORIGINAL_SIZE = 4 * 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024

HEADER_FORMAT_V4 = ">4sBB16sQIH32s"
HEADER_SIZE_V4 = struct.calcsize(HEADER_FORMAT_V4)

HEADER_FORMAT_V3 = ">4sBQIH"
HEADER_SIZE_V3 = struct.calcsize(HEADER_FORMAT_V3)


def compute_crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def sanitize_filename(filename: str) -> str:
    """Sanitiza nombres de archivo extraidos de cabeceras para prevenir vulnerabilidades de Path Traversal."""
    clean_name = os.path.basename(filename.replace("\\", "/"))
    clean_name = re.sub(r'[\x00-\x1f\x7f]', '', clean_name)
    if not clean_name or clean_name.strip(".") == "":
        return "archivo_restaurado"
    return clean_name


def format_file_size(size_in_bytes: int) -> str:
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    if size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.2f} KB"
    if size_in_bytes < 1024 * 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.2f} MB"
    return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"


def derive_keys(password: str, salt: bytes):
    """Deriva clave de cifrado (32b) y clave de autenticacion MAC (32b) con PBKDF2."""
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


def pack_header(original_filename: str, original_size: int, crc32_checksum: int, password: str = None, salt: bytes = None) -> tuple[bytes, bytes, bytes]:
    """Empaqueta la cabecera NDC4. Retorna (header_bytes, encryption_key, salt)."""
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


def unpack_header(stream_bytes: bytes, password: str = None):
    """
    Desempaqueta cabeceras NDC4 o NDC3.
    Retorna: (filename, original_size, crc32_checksum, payload_offset, is_encrypted, encryption_key)
    """
    if len(stream_bytes) < 4:
        raise ValueError("El archivo comprimido esta corrupto o tiene una cabecera incompleta.")

    magic = stream_bytes[:4]

    if magic == MAGIC_HEADER_V4:
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

        return filename, original_size, crc32_checksum, payload_offset, bool(is_encrypted), enc_key

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
        return filename, original_size, crc32_checksum, payload_offset, False, None

    else:
        raise ValueError("Formato no compatible. Se requiere un archivo .ndac (NDC4/NDC3).")


def read_header(file_object, password: str = None):
    """Lee solo la cabecera del archivo comprimido."""
    magic = file_object.read(4)
    if len(magic) < 4:
        raise ValueError("El archivo esta vacio o corrupto.")
    file_object.seek(0)

    if magic == MAGIC_HEADER_V4:
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
        raise ValueError("Formato no compatible. Se requiere un archivo .ndac.")


