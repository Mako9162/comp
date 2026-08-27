import os
import struct
import time
import zlib
from typing import Callable, Optional, Dict, Any, List, Union, Tuple

from ..utils.helpers import (CHUNK_SIZE, MAX_ORIGINAL_SIZE, MAX_TOTAL_FILES,
                             MAX_EXPANSION_RATIO, ENTRY_FORMAT, ENTRY_HEADER_SIZE,
                             ENTRY_TYPE_DIR, ENTRY_TYPE_FILE, compute_crc32,
                             crypt_stream_chunk, format_file_size, inspect_header,
                             pack_container_entry, pack_header, pack_header_v5,
                             read_header, safe_extract_path, sanitize_filename,
                             unpack_header)
from ..utils.logger import logger


def compress_data(raw_bytes: bytes, password: Optional[str] = None, progress_callback: Optional[Callable] = None) -> bytes:
    """Comprime datos en memoria retornando bytes con formato NDC4."""
    if progress_callback:
        progress_callback(10, "Comprimiendo datos...")
    deflated = zlib.compress(raw_bytes, level=9)
    crc = compute_crc32(raw_bytes)
    header_bytes, enc_key, _ = pack_header("data.bin", len(raw_bytes), crc, password=password)
    payload = crypt_stream_chunk(deflated, enc_key, 0)
    if progress_callback:
        progress_callback(100, "Compresion completada.")
    return header_bytes + payload


def decompress_data(full_stream: bytes, password: Optional[str] = None, progress_callback: Optional[Callable] = None) -> bytes:
    """Descomprime datos en memoria a partir de bytes NDC3/NDC4."""
    header_info = unpack_header(full_stream, password=password)
    filename, target_size, expected_crc, payload_offset, is_encrypted, enc_key, version, _ = header_info

    if version == 5:
        raise ValueError("Los paquetes de múltiples archivos NDC5 requieren extracción a disco.")

    if target_size > MAX_ORIGINAL_SIZE:
        raise ValueError("El tamano declarado excede el limite seguro.")
    payload = full_stream[payload_offset:]
    decrypted_deflate = crypt_stream_chunk(payload, enc_key, 0)
    decoder = zlib.decompressobj()
    try:
        result = decoder.decompress(decrypted_deflate, target_size + 1)
    except zlib.error as exc:
        raise ValueError(f"Payload DEFLATE corrupto: {exc}") from exc
    if (len(result) != target_size or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail):
        raise ValueError("El contenido comprimido esta corrupto o no coincide con su cabecera.")
    if compute_crc32(result) != expected_crc:
        raise ValueError("La comprobacion CRC32 fallo; el archivo fue alterado.")
    if progress_callback:
        progress_callback(100, "Descompresion completada.")
    return result


def _collect_sources(sources: List[str]) -> Tuple[List[Dict[str, Any]], int, str]:
    """
    Recorre recursivamente los archivos y directorios de origen.
    Retorna (items_list, total_original_size, root_name)
    """
    items = []
    total_size = 0

    if len(sources) == 1 and os.path.isdir(sources[0]):
        root_dir = os.path.abspath(sources[0])
        root_name = os.path.basename(root_dir) or "carpeta"
        for dirpath, dirnames, filenames in os.walk(root_dir):
            rel_dir = os.path.relpath(dirpath, root_dir)
            if rel_dir != ".":
                clean_rel_dir = rel_dir.replace("\\", "/")
                items.append({
                    "type": ENTRY_TYPE_DIR,
                    "rel_path": clean_rel_dir,
                    "abs_path": dirpath,
                    "size": 0,
                    "mtime": int(os.path.getmtime(dirpath)),
                    "crc32": 0,
                })

            for fn in filenames:
                abs_fn = os.path.join(dirpath, fn)
                rel_fn = os.path.relpath(abs_fn, root_dir).replace("\\", "/")
                try:
                    st = os.stat(abs_fn)
                    sz = st.st_size
                    mt = int(st.st_mtime)
                except OSError as err:
                    logger.warning(f"No se pudo acceder a {abs_fn}: {err}")
                    continue
                total_size += sz
                items.append({
                    "type": ENTRY_TYPE_FILE,
                    "rel_path": rel_fn,
                    "abs_path": abs_fn,
                    "size": sz,
                    "mtime": mt,
                })
    else:
        # Múltiples archivos o mezcla de archivos/carpetas
        root_name = os.path.basename(sources[0]) if len(sources) == 1 else "conjunto_archivos"
        for src in sources:
            abs_src = os.path.abspath(src)
            if os.path.isdir(abs_src):
                base_dir = os.path.dirname(abs_src)
                for dirpath, dirnames, filenames in os.walk(abs_src):
                    rel_dir = os.path.relpath(dirpath, base_dir).replace("\\", "/")
                    items.append({
                        "type": ENTRY_TYPE_DIR,
                        "rel_path": rel_dir,
                        "abs_path": dirpath,
                        "size": 0,
                        "mtime": int(os.path.getmtime(dirpath)),
                        "crc32": 0,
                    })
                    for fn in filenames:
                        abs_fn = os.path.join(dirpath, fn)
                        rel_fn = os.path.relpath(abs_fn, base_dir).replace("\\", "/")
                        st = os.stat(abs_fn)
                        sz = st.st_size
                        total_size += sz
                        items.append({
                            "type": ENTRY_TYPE_FILE,
                            "rel_path": rel_fn,
                            "abs_path": abs_fn,
                            "size": sz,
                            "mtime": int(st.st_mtime),
                        })
            elif os.path.isfile(abs_src):
                rel_fn = os.path.basename(abs_src)
                st = os.stat(abs_src)
                sz = st.st_size
                total_size += sz
                items.append({
                    "type": ENTRY_TYPE_FILE,
                    "rel_path": rel_fn,
                    "abs_path": abs_src,
                    "size": sz,
                    "mtime": int(st.st_mtime),
                })

    return items, total_size, root_name


def compress(
    sources: Union[str, List[str]],
    output_path: str,
    password: Optional[str] = None,
    compression_level: int = 9,
    progress_callback: Optional[Callable[[int, str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """
    Comprime un archivo (NDC4) o múltiples archivos/carpetas (NDC5) en un archivo .ndac.
    """
    start_time = time.time()
    if isinstance(sources, str):
        sources = [sources]

    for s in sources:
        if not os.path.exists(s):
            raise FileNotFoundError(f"No existe el archivo o carpeta de origen: {s}")

    # Determinar si es compresión de 1 solo archivo (NDC4) o carpeta/múltiples elementos (NDC5)
    is_single_file = (len(sources) == 1 and os.path.isfile(sources[0]))

    if is_single_file:
        return _compress_single_file(
            sources[0], output_path, password=password,
            compression_level=compression_level,
            progress_callback=progress_callback,
            cancel_callback=cancel_callback,
            start_time=start_time
        )
    else:
        return _compress_multi_sources(
            sources, output_path, password=password,
            compression_level=compression_level,
            progress_callback=progress_callback,
            cancel_callback=cancel_callback,
            start_time=start_time
        )


def _compress_single_file(
    input_path: str,
    output_path: str,
    password: Optional[str],
    compression_level: int,
    progress_callback: Optional[Callable],
    cancel_callback: Optional[Callable],
    start_time: float
) -> Dict[str, Any]:
    original_size = os.path.getsize(input_path)
    if not 0 <= original_size <= MAX_ORIGINAL_SIZE:
        raise ValueError(f"Solo se admiten archivos hasta {format_file_size(MAX_ORIGINAL_SIZE)}.")

    level = max(1, min(9, compression_level))
    clean_filename = os.path.basename(input_path)
    placeholder_header, enc_key, salt = pack_header(clean_filename, original_size, 0, password=password)
    temp_path = f"{output_path}.{os.getpid()}.partial"
    processed = 0
    computed_crc = 0
    stream_offset = 0

    logger.info(f"Iniciando compresion NDC4 de '{clean_filename}' ({original_size} bytes)")

    try:
        compressor = zlib.compressobj(level=level)
        with open(input_path, "rb") as source, open(temp_path, "w+b") as output:
            output.write(placeholder_header)
            for block in iter(lambda: source.read(CHUNK_SIZE), b""):
                if cancel_callback and cancel_callback():
                    raise InterruptedError("Operacion cancelada por el usuario.")
                compressed_block = compressor.compress(block)
                if compressed_block:
                    encrypted_block = crypt_stream_chunk(compressed_block, enc_key, stream_offset)
                    output.write(encrypted_block)
                    stream_offset += len(compressed_block)
                processed += len(block)
                computed_crc = zlib.crc32(block, computed_crc)

                if progress_callback:
                    percent = min(95, 5 + int(processed * 90 / (original_size or 1)))
                    progress_callback(percent, f"Comprimiendo: {format_file_size(processed)} de {format_file_size(original_size)}")

            tail = compressor.flush()
            if tail:
                encrypted_tail = crypt_stream_chunk(tail, enc_key, stream_offset)
                output.write(encrypted_tail)

            final_crc = computed_crc & 0xFFFFFFFF
            final_header, _, _ = pack_header(clean_filename, original_size, final_crc, password=password, salt=salt)
            output.seek(0)
            output.write(final_header)

        if processed != original_size:
            raise ValueError("El archivo cambio de tamano durante la compresion.")

        os.replace(temp_path, output_path)

    except Exception as exc:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        logger.error(f"Error o cancelacion durante compresion NDC4: {exc}")
        raise

    elapsed = time.time() - start_time
    output_size = os.path.getsize(output_path)
    reduction = (1 - output_size / original_size) * 100 if original_size > 0 else 0.0
    speed_kb = original_size / 1024 / elapsed if elapsed > 0 else 0.0

    if progress_callback:
        progress_callback(100, "Compresion finalizada con exito.")

    return {
        "output_path": output_path,
        "format": "NDC4",
        "file_count": 1,
        "original_size": original_size,
        "compressed_size": output_size,
        "reduction": reduction,
        "elapsed_seconds": elapsed,
        "speed_kb_s": speed_kb,
        "is_encrypted": bool(password),
    }


def _compress_multi_sources(
    sources: List[str],
    output_path: str,
    password: Optional[str],
    compression_level: int,
    progress_callback: Optional[Callable],
    cancel_callback: Optional[Callable],
    start_time: float
) -> Dict[str, Any]:
    items, total_original_size, root_name = _collect_sources(sources)
    total_files_count = len(items)

    if total_files_count > MAX_TOTAL_FILES:
        raise ValueError(f"La cantidad de archivos ({total_files_count}) excede el limite seguro de {MAX_TOTAL_FILES}.")

    level = max(1, min(9, compression_level))
    placeholder_header, enc_key, salt = pack_header_v5(root_name, total_original_size, total_files_count, 0, password=password)
    temp_path = f"{output_path}.{os.getpid()}.partial"

    logger.info(f"Iniciando compresion NDC5 de '{root_name}' ({total_files_count} elementos, {total_original_size} bytes)")

    processed_bytes = 0
    overall_crc = 0
    stream_offset = 0

    try:
        compressor = zlib.compressobj(level=level)
        with open(temp_path, "w+b") as output:
            output.write(placeholder_header)

            def write_payload_chunk(chunk_bytes: bytes):
                nonlocal stream_offset, overall_crc
                if not chunk_bytes:
                    return
                overall_crc = zlib.crc32(chunk_bytes, overall_crc)
                compressed = compressor.compress(chunk_bytes)
                if compressed:
                    encrypted = crypt_stream_chunk(compressed, enc_key, stream_offset)
                    output.write(encrypted)
                    stream_offset += len(compressed)

            for idx, item in enumerate(items):
                if cancel_callback and cancel_callback():
                    raise InterruptedError("Operacion cancelada por el usuario.")

                # 1. Calcular CRC del archivo antes si es archivo
                file_crc = 0
                if item["type"] == ENTRY_TYPE_FILE:
                    with open(item["abs_path"], "rb") as f_in:
                        for chunk in iter(lambda: f_in.read(CHUNK_SIZE), b""):
                            file_crc = zlib.crc32(chunk, file_crc)
                    file_crc = file_crc & 0xFFFFFFFF

                # 2. Escribir cabecera de entrada
                entry_header_bytes = pack_container_entry(
                    item["type"], item["rel_path"], item["size"], item["mtime"], file_crc
                )
                write_payload_chunk(entry_header_bytes)

                # 3. Escribir contenido del archivo
                if item["type"] == ENTRY_TYPE_FILE:
                    with open(item["abs_path"], "rb") as f_in:
                        for chunk in iter(lambda: f_in.read(CHUNK_SIZE), b""):
                            if cancel_callback and cancel_callback():
                                raise InterruptedError("Operacion cancelada por el usuario.")
                            write_payload_chunk(chunk)
                            processed_bytes += len(chunk)

                            if progress_callback:
                                percent = min(95, 5 + int(processed_bytes * 90 / (total_original_size or 1)))
                                progress_callback(percent, f"Comprimiendo [{idx+1}/{total_files_count}]: {item['rel_path']}")

            tail = compressor.flush()
            if tail:
                encrypted_tail = crypt_stream_chunk(tail, enc_key, stream_offset)
                output.write(encrypted_tail)

            final_crc = overall_crc & 0xFFFFFFFF
            final_header, _, _ = pack_header_v5(root_name, total_original_size, total_files_count, final_crc, password=password, salt=salt)
            output.seek(0)
            output.write(final_header)

        os.replace(temp_path, output_path)

    except Exception as exc:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        logger.error(f"Error o cancelacion durante compresion NDC5: {exc}")
        raise

    elapsed = time.time() - start_time
    output_size = os.path.getsize(output_path)
    reduction = (1 - output_size / total_original_size) * 100 if total_original_size > 0 else 0.0
    speed_kb = total_original_size / 1024 / elapsed if elapsed > 0 else 0.0

    if progress_callback:
        progress_callback(100, "Compresion finalizada con exito.")

    return {
        "output_path": output_path,
        "format": "NDC5",
        "root_name": root_name,
        "file_count": total_files_count,
        "original_size": total_original_size,
        "compressed_size": output_size,
        "reduction": reduction,
        "elapsed_seconds": elapsed,
        "speed_kb_s": speed_kb,
        "is_encrypted": bool(password),
    }


def decompress(
    input_path: str,
    output_path: str,
    password: Optional[str] = None,
    progress_callback: Optional[Callable[[int, str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """
    Descomprime un archivo .ndac (NDC3, NDC4 o NDC5) en output_path.
    Reconstruye directorios, carpetas vacías y fechas mtime de forma segura.
    """
    start_time = time.time()
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"No se encontro el archivo comprimido: {input_path}")

    input_size = os.path.getsize(input_path)
    if progress_callback:
        progress_callback(1, "Verificando cabecera y contrasena...")

    with open(input_path, "rb") as source:
        header_info = read_header(source, password=password)
        root_name, target_size, expected_crc, payload_offset, is_encrypted, enc_key, version, total_files_count = header_info

        if version in (3, 4):
            return _decompress_single_file_stream(
                source, output_path, root_name, target_size, expected_crc,
                enc_key, is_encrypted, input_size, progress_callback, cancel_callback, start_time
            )
        elif version == 5:
            return _decompress_ndc5_stream(
                source, output_path, root_name, target_size, total_files_count, expected_crc,
                enc_key, is_encrypted, input_size, progress_callback, cancel_callback, start_time
            )
        else:
            raise ValueError(f"Version de formato no soportada: {version}")


def _decompress_single_file_stream(
    source, output_path, root_name, target_size, expected_crc,
    enc_key, is_encrypted, input_size, progress_callback, cancel_callback, start_time
) -> Dict[str, Any]:
    # Si output_path es un directorio existente, formar la ruta del archivo destino
    if os.path.isdir(output_path) or output_path.endswith("/") or output_path.endswith("\\") or not os.path.splitext(output_path)[1]:
        dest_file = os.path.join(output_path, root_name)
    else:
        dest_file = output_path


    temp_path = f"{dest_file}.{os.getpid()}.partial"
    decoder = zlib.decompressobj()
    crc = 0
    restored = 0
    processed = source.tell()
    stream_offset = 0

    try:
        dest_dir = os.path.dirname(dest_file)
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)

        with open(temp_path, "w+b") as output:
            for block in iter(lambda: source.read(CHUNK_SIZE), b""):
                if cancel_callback and cancel_callback():
                    raise InterruptedError("Operacion cancelada por el usuario.")
                decrypted_block = crypt_stream_chunk(block, enc_key, stream_offset)
                stream_offset += len(block)
                pending = decrypted_block
                while pending:
                    remaining = target_size - restored
                    data = decoder.decompress(pending, remaining + 1)
                    if len(data) > remaining:
                        raise ValueError("El archivo intenta restaurar mas datos de los declarados.")
                    output.write(data)
                    restored += len(data)
                    crc = zlib.crc32(data, crc)
                    pending = decoder.unconsumed_tail
                    if decoder.unused_data:
                        raise ValueError("El archivo contiene datos adicionales no esperados.")

                processed += len(block)
                if progress_callback:
                    percent = min(95, int(processed * 95 / input_size))
                    progress_callback(percent, f"Descomprimiendo: {format_file_size(restored)} de {format_file_size(target_size)}")

            tail = decoder.flush()
            if tail or not decoder.eof or decoder.unused_data:
                raise ValueError("El contenido comprimido esta corrupto.")

        if restored != target_size or (crc & 0xFFFFFFFF) != expected_crc:
            raise ValueError("La comprobacion de integridad CRC32 fallo; el archivo fue alterado.")

        os.replace(temp_path, dest_file)

    except Exception as exc:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise

    elapsed = time.time() - start_time
    speed_kb = target_size / 1024 / elapsed if elapsed > 0 else 0.0

    if progress_callback:
        progress_callback(100, "Descompresion finalizada con exito.")

    return {
        "output_path": dest_file,
        "format": "NDC4" if is_encrypted else "NDC3",
        "file_count": 1,
        "restored_filename": root_name,
        "original_size": target_size,
        "compressed_size": input_size,
        "elapsed_seconds": elapsed,
        "speed_kb_s": speed_kb,
        "is_encrypted": is_encrypted,
    }


def _decompress_ndc5_stream(
    source, output_dir, root_name, target_size, total_files_count, expected_crc,
    enc_key, is_encrypted, input_size, progress_callback, cancel_callback, start_time
) -> Dict[str, Any]:
    dest_dir = os.path.abspath(output_dir)
    os.makedirs(dest_dir, exist_ok=True)

    decoder = zlib.decompressobj()
    overall_crc = 0
    stream_offset = 0
    restored_bytes = 0
    extracted_items = 0

    buffer = bytearray()

    def feed_and_read(amount: int) -> bytes:
        nonlocal stream_offset, overall_crc, buffer
        while len(buffer) < amount:
            raw = source.read(CHUNK_SIZE)
            if not raw:
                break
            decrypted = crypt_stream_chunk(raw, enc_key, stream_offset)
            stream_offset += len(raw)
            decompressed = decoder.decompress(decrypted)
            if decompressed:
                overall_crc = zlib.crc32(decompressed, overall_crc)
                buffer.extend(decompressed)

        if len(buffer) < amount:
            raise ValueError("El paquete NDC5 finalizo inesperadamente antes de completar las entradas.")
        data = bytes(buffer[:amount])
        del buffer[:amount]
        return data

    created_files_and_mtimes = []

    try:
        while extracted_items < total_files_count:
            if cancel_callback and cancel_callback():
                raise InterruptedError("Operacion cancelada por el usuario.")

            entry_fixed = feed_and_read(ENTRY_HEADER_SIZE)
            entry_type, path_len, file_size, mtime, file_crc = struct.unpack(ENTRY_FORMAT, entry_fixed)
            rel_path = feed_and_read(path_len).decode("utf-8", errors="replace")

            # Seguridad Anti Path-Traversal
            target_path = safe_extract_path(dest_dir, rel_path)

            # Protección contra Compression Bomb
            if restored_bytes + file_size > MAX_ORIGINAL_SIZE:
                raise ValueError("Proteccion Zip-Bomb: el tamano descompuesto excede los limites seguros.")

            if entry_type == ENTRY_TYPE_DIR:
                os.makedirs(target_path, exist_ok=True)
                if mtime > 0:
                    created_files_and_mtimes.append((target_path, mtime))
                extracted_items += 1
            elif entry_type == ENTRY_TYPE_FILE:
                parent_dir = os.path.dirname(target_path)
                if parent_dir:
                    os.makedirs(parent_dir, exist_ok=True)

                temp_file = f"{target_path}.{os.getpid()}.partial"
                actual_file_crc = 0
                file_restored = 0

                try:
                    with open(temp_file, "wb") as f_out:
                        remaining = file_size
                        while remaining > 0:
                            if cancel_callback and cancel_callback():
                                raise InterruptedError("Operacion cancelada por el usuario.")
                            chunk_size = min(remaining, CHUNK_SIZE)
                            chunk_data = feed_and_read(chunk_size)
                            f_out.write(chunk_data)
                            actual_file_crc = zlib.crc32(chunk_data, actual_file_crc)
                            file_restored += len(chunk_data)
                            remaining -= len(chunk_data)
                            restored_bytes += len(chunk_data)

                            if progress_callback:
                                percent = min(95, int(restored_bytes * 95 / (target_size or 1)))
                                progress_callback(percent, f"Extrayendo [{extracted_items+1}/{total_files_count}]: {rel_path}")

                    if (actual_file_crc & 0xFFFFFFFF) != file_crc:
                        raise ValueError(f"Integridad fallo en archivo individual '{rel_path}' (CRC no coincide).")

                    os.replace(temp_file, target_path)
                    if mtime > 0:
                        created_files_and_mtimes.append((target_path, mtime))

                    extracted_items += 1

                except Exception:
                    if os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                        except OSError:
                            pass
                    raise

        # Vaciar cualquier residuo final del descompresor DEFLATE
        tail = decoder.flush()
        if tail:
            overall_crc = zlib.crc32(tail, overall_crc)

        final_crc = overall_crc & 0xFFFFFFFF
        if final_crc != expected_crc:
            raise ValueError(f"CRC32 global de contenedor NDC5 no coincide (calculado: {hex(final_crc)}, esperado: {hex(expected_crc)}).")

        # Aplicar marcas de tiempo mtime
        for path_item, mtime_val in created_files_and_mtimes:
            try:
                os.utime(path_item, (mtime_val, mtime_val))
            except OSError:
                pass

    except Exception as exc:
        logger.error(f"Error durante descompresion NDC5: {exc}")
        raise

    elapsed = time.time() - start_time
    speed_kb = target_size / 1024 / elapsed if elapsed > 0 else 0.0

    if progress_callback:
        progress_callback(100, "Descompresion finalizada con exito.")

    return {
        "output_path": dest_dir,
        "format": "NDC5",
        "file_count": extracted_items,
        "root_name": root_name,
        "original_size": target_size,
        "compressed_size": input_size,
        "elapsed_seconds": elapsed,
        "speed_kb_s": speed_kb,
        "is_encrypted": is_encrypted,
    }


def validate_archive(archive_path: str, password: Optional[str] = None) -> Dict[str, Any]:
    """
    Valida la integridad de un archivo NDC3, NDC4 o NDC5 sin escribir nada en el disco.
    """
    if not os.path.isfile(archive_path):
        return {"valid": False, "error": "El archivo no existe.", "archive_path": archive_path}

    compressed_size = os.path.getsize(archive_path)
    try:
        with open(archive_path, "rb") as source:
            header_info = read_header(source, password=password)
            root_name, target_size, expected_crc, payload_offset, is_encrypted, enc_key, version, total_files_count = header_info

            decoder = zlib.decompressobj()
            overall_crc = 0
            stream_offset = 0

            for block in iter(lambda: source.read(CHUNK_SIZE), b""):
                decrypted = crypt_stream_chunk(block, enc_key, stream_offset)
                stream_offset += len(block)
                decompressed = decoder.decompress(decrypted)
                if decompressed:
                    overall_crc = zlib.crc32(decompressed, overall_crc)

            tail = decoder.flush()
            if tail:
                overall_crc = zlib.crc32(tail, overall_crc)

            final_crc = overall_crc & 0xFFFFFFFF
            if final_crc != expected_crc:
                raise ValueError(f"CRC32 no coincide (calculado: {hex(final_crc)}, esperado: {hex(expected_crc)}).")

            return {
                "valid": True,
                "archive_path": archive_path,
                "format": f"NDC{version}",
                "filename": root_name,
                "file_count": total_files_count,
                "original_size": target_size,
                "compressed_size": compressed_size,
                "reduction_percent": (1 - compressed_size / target_size) * 100 if target_size > 0 else 0.0,
                "crc32_match": True,
                "is_encrypted": is_encrypted,
                "error": None,
            }

    except Exception as exc:
        return {
            "valid": False,
            "archive_path": archive_path,
            "compressed_size": compressed_size,
            "error": str(exc),
        }


def get_archive_info(archive_path: str) -> Dict[str, Any]:
    """
    Obtiene metadatos de un archivo .ndac leyendo unicamente la cabecera.
    """
    if not os.path.isfile(archive_path):
        raise FileNotFoundError(f"No existe el archivo: {archive_path}")

    compressed_size = os.path.getsize(archive_path)
    with open(archive_path, "rb") as f:
        meta = inspect_header(f)

    target_size = meta["original_size"]
    reduction = (1 - compressed_size / target_size) * 100 if target_size > 0 else 0.0

    return {
        "archive_path": archive_path,
        "format": meta["format"],
        "version": meta["version"],
        "filename": meta["filename"],
        "file_count": meta["total_files_count"],
        "original_size": target_size,
        "compressed_size": compressed_size,
        "reduction_percent": reduction,
        "is_encrypted": meta["is_encrypted"],
        "crc32_checksum": hex(meta["crc32_checksum"]),
        "compression_algorithm": "DEFLATE (zlib)",
    }
