import json
import zlib
from typing import Dict, Any, List, Optional
import zstandard as zstd

from .constants import COMPRESSION_NONE, COMPRESSION_DEFLATE, COMPRESSION_ZSTD
from .crypto import encrypt_aead_gcm, decrypt_aead_gcm


def pack_metadata(
    root_name: str,
    total_original_size: int,
    entries: List[Dict[str, Any]],
    compression_algo_id: int = COMPRESSION_ZSTD
) -> bytes:
    """
    Serializa la lista de entradas y metadatos en JSON UTF-8 y los comprime.
    """
    metadata_dict = {
        "root_name": root_name,
        "total_original_size": total_original_size,
        "total_files_count": len(entries),
        "entries": entries
    }
    raw_json = json.dumps(metadata_dict, ensure_ascii=False).encode("utf-8")

    if compression_algo_id == COMPRESSION_ZSTD:
        compressor = zstd.ZstdCompressor(level=3)
        compressed_payload = compressor.compress(raw_json)
    elif compression_algo_id == COMPRESSION_DEFLATE:
        compressed_payload = zlib.compress(raw_json, level=6)
    else:
        compressed_payload = raw_json

    return compressed_payload


def encrypt_metadata_blob(
    compressed_metadata: bytes,
    meta_key: bytes,
    base_nonce: bytes,
    header_aad: Optional[bytes] = None
) -> bytes:
    """
    Cifra el bloque de metadatos comprimidos usando AES-256-GCM con meta_key y AAD de cabecera.
    """
    meta_nonce = bytes(b ^ 0xFF for b in base_nonce)
    aad_data = header_aad if header_aad is not None else b"NDAC6-MetadataAAD"
    return encrypt_aead_gcm(compressed_metadata, meta_key, meta_nonce, aad=aad_data)


def decrypt_and_unpack_metadata(
    encrypted_metadata_blob: bytes,
    meta_key: bytes,
    base_nonce: bytes,
    compression_algo_id: int = COMPRESSION_ZSTD,
    header_aad: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Descifra y valida la firma AEAD de metadatos contra el AAD de la cabecera.
    Arroja ValueError si la clave es incorrecta o si cualquier campo de la cabecera fue alterado.
    """
    meta_nonce = bytes(b ^ 0xFF for b in base_nonce)
    aad_data = header_aad if header_aad is not None else b"NDAC6-MetadataAAD"
    compressed_metadata = decrypt_aead_gcm(
        encrypted_metadata_blob, meta_key, meta_nonce, aad=aad_data
    )

    if compression_algo_id == COMPRESSION_ZSTD:
        decompressor = zstd.ZstdDecompressor()
        raw_json = decompressor.decompress(compressed_metadata)
    elif compression_algo_id == COMPRESSION_DEFLATE:
        raw_json = zlib.decompress(compressed_metadata)
    else:
        raw_json = compressed_metadata

    return json.loads(raw_json.decode("utf-8"))
