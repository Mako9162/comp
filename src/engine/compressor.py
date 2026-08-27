import os
import time
import zlib

from PyQt6.QtCore import QThread, pyqtSignal

from ..utils.helpers import (CHUNK_SIZE, MAX_ORIGINAL_SIZE, compute_crc32,
                             crypt_stream_chunk, format_file_size, pack_header,
                             read_header, unpack_header)


def compress_data(raw_bytes: bytes, password: str = None, progress_callback=None) -> bytes:
    if progress_callback:
        progress_callback(10, "Comprimiendo datos...")
    deflated = zlib.compress(raw_bytes, level=9)
    crc = compute_crc32(raw_bytes)
    header_bytes, enc_key, _ = pack_header("data.bin", len(raw_bytes), crc, password=password)
    payload = crypt_stream_chunk(deflated, enc_key, 0)
    if progress_callback:
        progress_callback(100, "Compresion completada.")
    return header_bytes + payload


def decompress_data(full_stream: bytes, password: str = None, progress_callback=None) -> bytes:
    filename, target_size, expected_crc, payload_offset, is_encrypted, enc_key = unpack_header(full_stream, password=password)
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


class CompressionWorker(QThread):
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(str, str, float)
    error = pyqtSignal(str)

    def __init__(self, mode: str, input_path: str, output_path: str, password: str = None):
        super().__init__()
        self.mode = mode.lower()
        self.input_path = input_path
        self.output_path = output_path
        self.password = password
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def run(self):
        try:
            start_time = time.time()
            if self.mode == "compress":
                self._run_compression(start_time)
            elif self.mode == "decompress":
                self._run_decompression(start_time)
            else:
                raise ValueError(f"Modo desconocido: {self.mode}")
        except Exception as exc:
            self.error.emit(f"Operacion no completada: {exc}")

    def _emit_progress(self, processed, total, action):
        percent = min(95, 5 + int(processed * 90 / total))
        self.progress.emit(percent, f"{action}: {format_file_size(processed)} de {format_file_size(total)}")

    def _run_compression(self, start_time):
        if not os.path.isfile(self.input_path):
            raise FileNotFoundError("No se encontro el archivo seleccionado.")
        self.progress.emit(1, "Verificando archivo...")
        original_size = os.path.getsize(self.input_path)
        if not 0 < original_size <= MAX_ORIGINAL_SIZE:
            raise ValueError(f"Solo se admiten archivos entre 1 byte y {format_file_size(MAX_ORIGINAL_SIZE)}.")

        clean_filename = os.path.basename(self.input_path)
        placeholder_header, enc_key, salt = pack_header(clean_filename, original_size, 0, password=self.password)
        temp_path = f"{self.output_path}.{os.getpid()}.partial"
        processed = 0
        computed_crc = 0
        stream_offset = 0
        try:
            compressor = zlib.compressobj(level=9)
            with open(self.input_path, "rb") as source, open(temp_path, "w+b") as output:
                output.write(placeholder_header)
                for block in iter(lambda: source.read(CHUNK_SIZE), b""):
                    if self._is_cancelled:
                        raise InterruptedError("Operacion cancelada por el usuario.")
                    compressed_block = compressor.compress(block)
                    if compressed_block:
                        encrypted_block = crypt_stream_chunk(compressed_block, enc_key, stream_offset)
                        output.write(encrypted_block)
                        stream_offset += len(compressed_block)
                    processed += len(block)
                    computed_crc = zlib.crc32(block, computed_crc)
                    self._emit_progress(processed, original_size, "Comprimiendo")
                tail = compressor.flush()
                if tail:
                    encrypted_tail = crypt_stream_chunk(tail, enc_key, stream_offset)
                    output.write(encrypted_tail)

                final_crc = computed_crc & 0xFFFFFFFF
                final_header, _, _ = pack_header(clean_filename, original_size, final_crc, password=self.password, salt=salt)
                output.seek(0)
                output.write(final_header)

            if processed != original_size:
                raise ValueError("El archivo cambio de tamano mientras se comprimia. Intenta nuevamente.")
            os.replace(temp_path, self.output_path)
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
        elapsed = time.time() - start_time
        output_size = os.path.getsize(self.output_path)
        reduction = (1 - output_size / original_size) * 100 if original_size > 0 else 0
        speed = original_size / 1024 / elapsed if elapsed else 0
        lock_status = "🔒 Protegido con contrasena" if self.password else "🔓 Sin contrasena"
        self.finished.emit(self.output_path,
            f"Original: {format_file_size(original_size)} | Comprimido: {format_file_size(output_size)} "
            f"({reduction:.1f}% reduccion) | {lock_status} | Velocidad: {speed:.1f} KB/s", elapsed)

    def _run_decompression(self, start_time):
        if not os.path.isfile(self.input_path):
            raise FileNotFoundError("No se encontro el archivo comprimido.")
        input_size = os.path.getsize(self.input_path)
        self.progress.emit(1, "Verificando formato y contrasena...")
        with open(self.input_path, "rb") as source:
            fname, target_size, expected_crc, payload_offset, is_encrypted, enc_key = read_header(source, password=self.password)
            temp_path = f"{self.output_path}.{os.getpid()}.partial"
            decoder = zlib.decompressobj()
            crc = 0
            restored = 0
            processed = source.tell()
            stream_offset = 0
            try:
                with open(temp_path, "xb") as output:
                    for block in iter(lambda: source.read(CHUNK_SIZE), b""):
                        if self._is_cancelled:
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
                        self._emit_progress(processed, input_size, "Descomprimiendo")
                    tail = decoder.flush()
                    if tail or not decoder.eof or decoder.unused_data:
                        raise ValueError("El contenido comprimido esta corrupto o contiene datos adicionales.")
                if restored != target_size or (crc & 0xFFFFFFFF) != expected_crc:
                    raise ValueError("La comprobacion de integridad fallo; el archivo puede estar dañado.")
                os.replace(temp_path, self.output_path)
            except Exception:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise
        elapsed = time.time() - start_time
        speed = target_size / 1024 / elapsed if elapsed else 0
        self.finished.emit(self.output_path,
            f"Restaurado: {format_file_size(target_size)} | Integridad y clave verificadas | Velocidad: {speed:.1f} KB/s", elapsed)

