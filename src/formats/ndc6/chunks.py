import struct
import zlib
from typing import BinaryIO, Tuple, Optional
import zstandard as zstd

from .constants import COMPRESSION_NONE, COMPRESSION_DEFLATE, COMPRESSION_ZSTD
from .crypto import derive_chunk_nonce, encrypt_aead_gcm, decrypt_aead_gcm

# Header de marco de chunk: Chunk Index (8B) + Ciphertext Len (4B) = 12 bytes
CHUNK_FRAME_HEADER_FORMAT = ">QI"
CHUNK_FRAME_HEADER_SIZE = 12


def write_chunk_frame(
    out_stream: BinaryIO,
    chunk_index: int,
    raw_chunk_bytes: bytes,
    payload_key: bytes,
    base_nonce: bytes,
    compression_algo_id: int = COMPRESSION_ZSTD,
    zstd_compressor: Optional[zstd.ZstdCompressor] = None
) -> int:
    """
    Comprime, cifra con AES-256-GCM y escribe un marco de chunk en el stream de salida.
    Retorna la cantidad total de bytes escritos en disco.
    """
    # 1. Compresión del bloque
    if compression_algo_id == COMPRESSION_ZSTD:
        if zstd_compressor is None:
            zstd_compressor = zstd.ZstdCompressor(level=3)
        compressed_data = zstd_compressor.compress(raw_chunk_bytes)
    elif compression_algo_id == COMPRESSION_DEFLATE:
        compressed_data = zlib.compress(raw_chunk_bytes, level=6)
    else:
        compressed_data = raw_chunk_bytes

    # 2. Nonce único determinista por chunk
    chunk_nonce = derive_chunk_nonce(base_nonce, chunk_index)

    # 3. AAD del bloque: índice de chunk + algoritmo de compresión
    chunk_aad = struct.pack(">QI", chunk_index, compression_algo_id)

    # 4. Cifrado AEAD (Ciphertext + Tag 16B)
    ciphertext_with_tag = encrypt_aead_gcm(compressed_data, payload_key, chunk_nonce, aad=chunk_aad)

    # 5. Cabecera del marco (12B)
    frame_header = struct.pack(CHUNK_FRAME_HEADER_FORMAT, chunk_index, len(ciphertext_with_tag))

    # 6. Escritura atómica a disco
    out_stream.write(frame_header)
    out_stream.write(ciphertext_with_tag)

    return len(frame_header) + len(ciphertext_with_tag)


def read_and_verify_chunk_frame(
    in_stream: BinaryIO,
    expected_chunk_index: int,
    payload_key: bytes,
    base_nonce: bytes,
    compression_algo_id: int = COMPRESSION_ZSTD,
    zstd_decompressor: Optional[zstd.ZstdDecompressor] = None
) -> bytes:
    """
    Lee, valida la firmas AEAD e índice del marco de chunk y descomprime los datos.
    Arroja ValueError si hay reordenamiento, truncamiento, desajuste de índice o alteración de datos.
    """
    header_bytes = in_stream.read(CHUNK_FRAME_HEADER_SIZE)
    if not header_bytes or len(header_bytes) < CHUNK_FRAME_HEADER_SIZE:
        raise ValueError(f"Marco de chunk #{expected_chunk_index} truncado o faltante.")

    chunk_index, ciphertext_len = struct.unpack(CHUNK_FRAME_HEADER_FORMAT, header_bytes)

    if chunk_index != expected_chunk_index:
        raise ValueError(
            f"Desorden o duplicacion de chunk. Esperado #{expected_chunk_index}, obtenido #{chunk_index}."
        )

    ciphertext_with_tag = in_stream.read(ciphertext_len)
    if len(ciphertext_with_tag) < ciphertext_len:
        raise ValueError(f"Payload de chunk #{chunk_index} truncado.")

    # Derivar nonce y verificar AAD
    chunk_nonce = derive_chunk_nonce(base_nonce, chunk_index)
    chunk_aad = struct.pack(">QI", chunk_index, compression_algo_id)

    # Descifrado y verificación de firma AEAD Tag (16B)
    compressed_data = decrypt_aead_gcm(ciphertext_with_tag, payload_key, chunk_nonce, aad=chunk_aad)

    # Descompresión
    if compression_algo_id == COMPRESSION_ZSTD:
        if zstd_decompressor is None:
            zstd_decompressor = zstd.ZstdDecompressor()
        raw_chunk_bytes = zstd_decompressor.decompress(compressed_data)
    elif compression_algo_id == COMPRESSION_DEFLATE:
        raw_chunk_bytes = zlib.decompress(compressed_data)
    else:
        raw_chunk_bytes = compressed_data

    return raw_chunk_bytes
