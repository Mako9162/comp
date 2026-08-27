import os
import zlib
from typing import Optional, Callable, Dict, Any, List

from .constants import COMPRESSION_ZSTD
from .crypto import derive_master_key, expand_subkeys
from .header import unpack_header_v6, verify_header_integrity
from .metadata import decrypt_and_unpack_metadata
from .chunks import read_and_verify_chunk_frame
from ...utils.helpers import safe_extract_path


def decompress_ndc6(
    archive_path: str,
    output_dir: str,
    password: Optional[str] = None,
    progress_callback: Optional[Callable[[int, str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None
) -> Dict[str, Any]:
    """
    Motor de descompresión y validación NDC6 en streaming.
    Soporta extracción total de contenedores multielemento con firma AEAD.
    """
    if not os.path.exists(archive_path):
        raise FileNotFoundError(f"El archivo '{archive_path}' no existe.")

    if not password:
        raise ValueError("Se requiere una contrasena para descifrar y extraer este archivo NDC6.")

    archive_size = os.path.getsize(archive_path)

    with open(archive_path, "rb") as in_f:
        hdr = unpack_header_v6(in_f)

        # Leer metadatos cifrados
        enc_meta_blob = in_f.read(hdr["encrypted_metadata_len"])

        # Derivar subclaves criptográficas
        master_key = derive_master_key(
            password=password,
            salt=hdr["salt"],
            memory_kb=hdr["kdf_param_m"],
            time_cost=hdr["kdf_param_t"]
        )
        payload_key, meta_key = expand_subkeys(master_key)

        # Verificar integridad AEAD de la cabecera fija
        verify_header_integrity(hdr, meta_key)

        # Descifrar y desempaquetar metadatos contra AAD de la cabecera
        metadata = decrypt_and_unpack_metadata(
            enc_meta_blob, meta_key, hdr["base_nonce"], hdr["compression_algo_id"],
            header_aad=hdr["header_aad_bytes"]
        )

        entries = metadata["entries"]
        total_original_size = metadata["total_original_size"]
        total_chunks = hdr["payload_total_chunks"]

        # 1. Crear directorios primero y validar rutas anti path-traversal
        files_map: List[Dict[str, Any]] = []
        for entry in entries:
            target_path = safe_extract_path(output_dir, entry["rel_path"])
            if entry["entry_type"] == 2:  # Carpeta
                os.makedirs(target_path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                files_map.append({
                    "target_path": target_path,
                    "file_size": entry["file_size"],
                    "crc32": entry.get("crc32", 0),
                    "mtime": entry.get("mtime", 0)
                })

        # 2. Reconstrucción en streaming de archivos leyendo marcos de chunk cifrados
        current_chunk_idx = 0
        restored_bytes = 0
        written_files_count = 0

        for file_info in files_map:
            if cancel_callback and cancel_callback():
                raise InterruptedError("Operacion cancelada por el usuario.")

            target_path = file_info["target_path"]
            temp_target = target_path + ".partial"
            expected_file_size = file_info["file_size"]
            file_restored = 0
            computed_crc = 0

            try:
                with open(temp_target, "wb") as out_file:
                    while file_restored < expected_file_size:
                        if cancel_callback and cancel_callback():
                            raise InterruptedError("Operacion cancelada por el usuario.")

                        # Leer y verificar firma AEAD del chunk marco
                        chunk_payload = read_and_verify_chunk_frame(
                            in_f,
                            expected_chunk_index=current_chunk_idx,
                            payload_key=payload_key,
                            base_nonce=hdr["base_nonce"],
                            compression_algo_id=hdr["compression_algo_id"]
                        )

                        # Acotar si el último chunk excede el tamaño del archivo individual
                        bytes_needed = expected_file_size - file_restored
                        chunk_to_write = chunk_payload[:bytes_needed]

                        out_file.write(chunk_to_write)
                        computed_crc = zlib.crc32(chunk_to_write, computed_crc)
                        file_restored += len(chunk_to_write)
                        restored_bytes += len(chunk_to_write)
                        current_chunk_idx += 1

                        if progress_callback and total_original_size > 0:
                            pct = min(100, int((restored_bytes / total_original_size) * 100))
                            progress_callback(pct, f"Extrayendo... ({pct}%)")

                # Verificar CRC32 de integridad si fue guardado
                if file_info["crc32"] != 0 and computed_crc != file_info["crc32"]:
                    raise ValueError(f"Error de integridad CRC32 al restaurar '{target_path}'.")

                if os.path.exists(target_path):
                    os.remove(target_path)
                os.rename(temp_target, target_path)

                if file_info["mtime"] > 0:
                    try:
                        os.utime(target_path, (file_info["mtime"], file_info["mtime"]))
                    except OSError:
                        pass

                written_files_count += 1

            except Exception:
                if os.path.exists(temp_target):
                    try:
                        os.remove(temp_target)
                    except OSError:
                        pass
                raise

    return {
        "restored_size": restored_bytes,
        "archive_size": archive_size,
        "files_extracted": written_files_count,
        "format": "NDC6"
    }


def validate_ndc6(archive_path: str, password: Optional[str] = None) -> bool:
    """Valida la integridad binaria y firmas AEAD de un archivo NDC6 sin escribir a disco."""
    if not password:
        raise ValueError("Se requiere contraseña para validar la integridad del contenedor NDC6.")

    with open(archive_path, "rb") as in_f:
        hdr = unpack_header_v6(in_f)
        enc_meta_blob = in_f.read(hdr["encrypted_metadata_len"])

        master_key = derive_master_key(password, hdr["salt"], hdr["kdf_param_m"], hdr["kdf_param_t"])
        payload_key, meta_key = expand_subkeys(master_key)

        # Verificar integridad AEAD de la cabecera fija
        verify_header_integrity(hdr, meta_key)

        # Validar metadatos contra AAD de la cabecera
        decrypt_and_unpack_metadata(
            enc_meta_blob, meta_key, hdr["base_nonce"], hdr["compression_algo_id"],
            header_aad=hdr["header_aad_bytes"]
        )

        # Validar todos los chunks de payload
        for chunk_idx in range(hdr["payload_total_chunks"]):
            read_and_verify_chunk_frame(
                in_f,
                expected_chunk_index=chunk_idx,
                payload_key=payload_key,
                base_nonce=hdr["base_nonce"],
                compression_algo_id=hdr["compression_algo_id"]
            )

    return True
