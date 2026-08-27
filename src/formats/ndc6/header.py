import struct
from typing import Dict, Any, Tuple, Optional, Union, BinaryIO

from .constants import (
    MAGIC_HEADER_V6, FORMAT_VERSION_V6, HEADER_FORMAT_V6, HEADER_SIZE_V6,
    KDF_ARGON2ID, CIPHER_AES_256_GCM, COMPRESSION_ZSTD,
    DEFAULT_ARGON2_MEMORY_KB, DEFAULT_ARGON2_TIME_COST, DEFAULT_CHUNK_SIZE,
    FLAG_IS_ENCRYPTED, FLAG_METADATA_ENCRYPTED
)
from .crypto import encrypt_aead_gcm, decrypt_aead_gcm


def build_header_aad(
    version: int,
    flags: int,
    kdf_algo_id: int,
    cipher_algo_id: int,
    compression_algo_id: int,
    chunk_size: int,
    kdf_param_m: int,
    kdf_param_t: int,
) -> bytes:
    """Construye el bloque de Datos Asociados Autenticados (AAD) estáticos de la cabecera NDC6."""
    return struct.pack(
        ">4sBHBBBIII",
        MAGIC_HEADER_V6,
        version,
        flags,
        kdf_algo_id,
        cipher_algo_id,
        compression_algo_id,
        chunk_size,
        kdf_param_m,
        kdf_param_t
    )


def pack_header_v6(
    flags: int,
    kdf_algo_id: int,
    cipher_algo_id: int,
    compression_algo_id: int,
    chunk_size: int,
    salt: bytes,
    base_nonce: bytes,
    kdf_param_m: int,
    kdf_param_t: int,
    encrypted_metadata_len: int,
    payload_total_chunks: int,
    meta_key: Optional[bytes] = None,
    header_aad_data: Optional[bytes] = None,
) -> bytes:
    """
    Empaqueta la cabecera fija de 80 bytes de NDC6 firmando el AAD de cabecera.
    """
    if len(salt) != 16:
        raise ValueError("El salt debe ser exactamente de 16 bytes.")
    if len(base_nonce) != 12:
        raise ValueError("El base nonce debe ser exactamente de 12 bytes.")

    aad_bytes = build_header_aad(
        FORMAT_VERSION_V6, flags, kdf_algo_id, cipher_algo_id,
        compression_algo_id, chunk_size, kdf_param_m, kdf_param_t
    )
    header_aad_len = len(aad_bytes)

    if meta_key:
        tag_blob = encrypt_aead_gcm(b"", meta_key, base_nonce, aad=aad_bytes)
        header_aead_tag = tag_blob[-16:]
    else:
        header_aead_tag = b"\x00" * 16

    header_bytes = struct.pack(
        HEADER_FORMAT_V6,
        MAGIC_HEADER_V6,
        FORMAT_VERSION_V6,
        flags,
        kdf_algo_id,
        cipher_algo_id,
        compression_algo_id,
        chunk_size,
        salt,
        base_nonce,
        kdf_param_m,
        kdf_param_t,
        header_aad_len,
        encrypted_metadata_len,
        payload_total_chunks,
        header_aead_tag
    )

    return header_bytes + aad_bytes


def unpack_header_v6(source: Union[bytes, BinaryIO]) -> Dict[str, Any]:
    """
    Desempaqueta los campos estructurales de la cabecera fija de 80 bytes de NDC6 y su AAD.
    Soporta secuencias de bytes (bytes) o streams de archivos (BinaryIO).
    """
    if isinstance(source, bytes):
        if len(source) < HEADER_SIZE_V6:
            raise ValueError(f"Cabecera NDC6 truncada (esperados {HEADER_SIZE_V6} B, recibidos {len(source)} B).")
        fixed_bytes = source[:HEADER_SIZE_V6]
        stream_mode = False
    else:
        fixed_bytes = source.read(HEADER_SIZE_V6)
        if len(fixed_bytes) < HEADER_SIZE_V6:
            raise ValueError(f"Cabecera NDC6 truncada (esperados {HEADER_SIZE_V6} B, recibidos {len(fixed_bytes)} B).")
        stream_mode = True

    (
        magic, version, flags, kdf_algo_id, cipher_algo_id,
        compression_algo_id, chunk_size, salt, base_nonce,
        kdf_param_m, kdf_param_t, header_aad_len,
        encrypted_metadata_len, payload_total_chunks,
        header_aead_tag
    ) = struct.unpack(HEADER_FORMAT_V6, fixed_bytes)

    if magic != MAGIC_HEADER_V6:
        raise ValueError(f"Firma magica invalida. Esperado '{MAGIC_HEADER_V6.decode()}', obtenido '{magic}'.")

    if version != FORMAT_VERSION_V6:
        raise ValueError(f"Version de formato NDC6 no soportada ({version}).")

    if stream_mode:
        header_aad_bytes = source.read(header_aad_len)
        if len(header_aad_bytes) < header_aad_len:
            raise ValueError("Bloque AAD de cabecera truncado.")
    else:
        aad_start = HEADER_SIZE_V6
        aad_end = aad_start + header_aad_len
        if len(source) < aad_end:
            raise ValueError("Bloque AAD de cabecera truncado.")
        header_aad_bytes = source[aad_start:aad_end]

    # Validar consistencia interna entre campos desempaquetados y bloque AAD
    expected_aad = build_header_aad(
        version, flags, kdf_algo_id, cipher_algo_id,
        compression_algo_id, chunk_size, kdf_param_m, kdf_param_t
    )
    if expected_aad != header_aad_bytes:
        raise ValueError("Inconsistencia en la cabecera AAD de NDC6; posible alteracion de metadatos.")

    return {
        "magic": magic,
        "version": version,
        "flags": flags,
        "kdf_algo_id": kdf_algo_id,
        "cipher_algo_id": cipher_algo_id,
        "compression_algo_id": compression_algo_id,
        "chunk_size": chunk_size,
        "salt": salt,
        "base_nonce": base_nonce,
        "kdf_param_m": kdf_param_m,
        "kdf_param_t": kdf_param_t,
        "header_aad_len": header_aad_len,
        "encrypted_metadata_len": encrypted_metadata_len,
        "payload_total_chunks": payload_total_chunks,
        "header_aead_tag": header_aead_tag,
        "header_aad_bytes": header_aad_bytes,
        "total_header_size": HEADER_SIZE_V6 + header_aad_len
    }


def verify_header_integrity(hdr: Dict[str, Any], meta_key: bytes) -> bool:
    """Verifica el Tag AEAD de la cabecera fija de NDC6."""
    try:
        decrypt_aead_gcm(
            b"" + hdr["header_aead_tag"],
            meta_key,
            hdr["base_nonce"],
            aad=hdr["header_aad_bytes"]
        )
        return True
    except Exception as exc:
        raise ValueError("Integridad de cabecera NDC6 violada (Tag AEAD invalido).") from exc
