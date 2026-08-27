import os
import zlib
from typing import Union, List, Optional, Callable, Dict, Any, Tuple

from .constants import (
    COMPRESSION_ZSTD, KDF_ARGON2ID, CIPHER_AES_256_GCM,
    FLAG_IS_ENCRYPTED, FLAG_METADATA_ENCRYPTED, DEFAULT_CHUNK_SIZE, FORMAT_VERSION_V6
)
from .crypto import generate_salt, generate_nonce, derive_master_key, expand_subkeys
from .header import pack_header_v6, build_header_aad
from .metadata import pack_metadata, encrypt_metadata_blob
from .chunks import write_chunk_frame
from ...utils.helpers import sanitize_filename


def compute_file_crc32(filepath: str) -> int:
    """Calcula el CRC32 de un archivo en disco leyéndolo en streaming."""
    crc = 0
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            crc = zlib.crc32(chunk, crc)
    return crc & 0xFFFFFFFF


def compress_ndc6(
    sources: Union[str, List[str]],
    output_archive: str,
    password: Optional[str] = None,
    compression_level: int = 3,
    progress_callback: Optional[Callable[[int, str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None
) -> Dict[str, Any]:
    """
    Motor de compresión en streaming NDC6.
    Soporta múltiples archivos y directorios con cifrado AEAD AES-256-GCM y Argon2id.
    """
    if isinstance(sources, str):
        source_list = [sources]
    else:
        source_list = sources

    if not source_list:
        raise ValueError("No se especificaron archivos o carpetas de origen.")

    if not password:
        raise ValueError("NDAC v2.0 (NDC6) requiere una contrasena para cifrar y autenticar el contenedor.")

    # 1. Analizar estructura de archivos e inspeccionar entradas
    entries: List[Dict[str, Any]] = []
    files_to_process: List[Tuple[str, str]] = []  # (abs_path, rel_path)
    total_original_size = 0

    if len(source_list) == 1 and os.path.isfile(source_list[0]):
        root_name = os.path.basename(source_list[0])
        abs_p = os.path.abspath(source_list[0])
        f_size = os.path.getsize(abs_p)
        mtime = os.path.getmtime(abs_p)
        crc = compute_file_crc32(abs_p)
        rel_p = sanitize_filename(root_name)

        entries.append({
            "entry_type": 1,
            "rel_path": rel_p,
            "file_size": f_size,
            "mtime": mtime,
            "crc32": crc
        })
        files_to_process.append((abs_p, rel_p))
        total_original_size = f_size
    else:
        root_name = os.path.basename(os.path.abspath(source_list[0])) if len(source_list) == 1 else "conjunto_archivos"
        for src in source_list:
            abs_src = os.path.abspath(src)
            if os.path.isfile(abs_src):
                f_size = os.path.getsize(abs_src)
                mtime = os.path.getmtime(abs_src)
                crc = compute_file_crc32(abs_src)
                rel_p = sanitize_filename(os.path.basename(abs_src))
                entries.append({
                    "entry_type": 1,
                    "rel_path": rel_p,
                    "file_size": f_size,
                    "mtime": mtime,
                    "crc32": crc
                })
                files_to_process.append((abs_src, rel_p))
                total_original_size += f_size
            elif os.path.isdir(abs_src):
                base_dir_name = os.path.basename(abs_src)
                for root, dirs, files in os.walk(abs_src):
                    for d in dirs:
                        full_d = os.path.join(root, d)
                        rel_d = os.path.relpath(full_d, os.path.dirname(abs_src))
                        rel_d = sanitize_filename(rel_d.replace("\\", "/"))
                        entries.append({
                            "entry_type": 2,
                            "rel_path": rel_d,
                            "file_size": 0,
                            "mtime": os.path.getmtime(full_d),
                            "crc32": 0
                        })
                    for f in files:
                        full_f = os.path.join(root, f)
                        rel_f = os.path.relpath(full_f, os.path.dirname(abs_src))
                        rel_f = sanitize_filename(rel_f.replace("\\", "/"))
                        f_size = os.path.getsize(full_f)
                        mtime = os.path.getmtime(full_f)
                        crc = compute_file_crc32(full_f)
                        entries.append({
                            "entry_type": 1,
                            "rel_path": rel_f,
                            "file_size": f_size,
                            "mtime": mtime,
                            "crc32": crc
                        })
                        files_to_process.append((full_f, rel_f))
                        total_original_size += f_size

    # 2. Generación de claves criptográficas y nonces
    salt = generate_salt(16)
    base_nonce = generate_nonce(12)
    master_key = derive_master_key(password, salt)
    payload_key, meta_key = expand_subkeys(master_key)

    flags = FLAG_IS_ENCRYPTED | FLAG_METADATA_ENCRYPTED
    header_aad = build_header_aad(
        FORMAT_VERSION_V6, flags, KDF_ARGON2ID, CIPHER_AES_256_GCM,
        COMPRESSION_ZSTD, DEFAULT_CHUNK_SIZE, 65536, 3
    )

    # 3. Preparación de metadatos cifrados firmando el AAD estático de cabecera
    compressed_meta = pack_metadata(root_name, total_original_size, entries, compression_algo_id=COMPRESSION_ZSTD)
    encrypted_meta = encrypt_metadata_blob(compressed_meta, meta_key, base_nonce, header_aad=header_aad)

    # 4. Iniciar archivo temporal `.partial` y reservar espacio exacto de cabecera AAD
    temp_output = output_archive + ".partial"
    processed_bytes = 0
    total_chunks = 0

    placeholder_header = pack_header_v6(
        flags=flags,
        kdf_algo_id=KDF_ARGON2ID,
        cipher_algo_id=CIPHER_AES_256_GCM,
        compression_algo_id=COMPRESSION_ZSTD,
        chunk_size=DEFAULT_CHUNK_SIZE,
        salt=salt,
        base_nonce=base_nonce,
        kdf_param_m=65536,
        kdf_param_t=3,
        encrypted_metadata_len=len(encrypted_meta),
        payload_total_chunks=0,
        meta_key=meta_key
    )

    try:
        with open(temp_output, "wb") as out_f:
            out_f.write(placeholder_header)
            out_f.write(encrypted_meta)

            # Stream de datos por archivos y chunks
            for abs_path, rel_path in files_to_process:
                if cancel_callback and cancel_callback():
                    raise InterruptedError("Operacion cancelada por el usuario.")

                with open(abs_path, "rb") as in_f:
                    while True:
                        if cancel_callback and cancel_callback():
                            raise InterruptedError("Operacion cancelada por el usuario.")

                        chunk = in_f.read(DEFAULT_CHUNK_SIZE)
                        if not chunk:
                            break

                        write_chunk_frame(
                            out_f,
                            chunk_index=total_chunks,
                            raw_chunk_bytes=chunk,
                            payload_key=payload_key,
                            base_nonce=base_nonce,
                            compression_algo_id=COMPRESSION_ZSTD
                        )

                        total_chunks += 1
                        processed_bytes += len(chunk)

                        if progress_callback and total_original_size > 0:
                            pct = min(100, int((processed_bytes / total_original_size) * 100))
                            progress_callback(pct, f"Procesando {rel_path} ({pct}%)")

            # 5. Reescribir la cabecera final autenticada AAD con la cantidad real de chunks
            out_f.seek(0)
            final_header = pack_header_v6(
                flags=flags,
                kdf_algo_id=KDF_ARGON2ID,
                cipher_algo_id=CIPHER_AES_256_GCM,
                compression_algo_id=COMPRESSION_ZSTD,
                chunk_size=DEFAULT_CHUNK_SIZE,
                salt=salt,
                base_nonce=base_nonce,
                kdf_param_m=65536,
                kdf_param_t=3,
                encrypted_metadata_len=len(encrypted_meta),
                payload_total_chunks=total_chunks,
                meta_key=meta_key
            )
            out_f.write(final_header)

        # 6. Reemplazo atómico
        if os.path.exists(output_archive):
            os.remove(output_archive)
        os.rename(temp_output, output_archive)

    except Exception:
        if os.path.exists(temp_output):
            try:
                os.remove(temp_output)
            except OSError:
                pass
        raise

    compressed_size = os.path.getsize(output_archive)
    ratio = (1.0 - (compressed_size / total_original_size)) * 100.0 if total_original_size > 0 else 0.0

    return {
        "original_size": total_original_size,
        "compressed_size": compressed_size,
        "compression_ratio": ratio,
        "files_count": len(files_to_process),
        "format": "NDC6",
        "archive_path": output_archive
    }
