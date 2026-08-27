import os
from typing import Union, List
from PyQt6.QtCore import QThread, pyqtSignal

from .compressor import compress, decompress
from ..utils.helpers import format_file_size


class CompressionWorker(QThread):
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(str, str, float)
    error = pyqtSignal(str)

    def __init__(
        self,
        mode: str,
        input_path: Union[str, List[str]],
        output_path: str,
        password: str = None,
        compression_level: int = 9,
    ):
        super().__init__()
        self.mode = mode.lower()
        self.input_path = input_path
        self.output_path = output_path
        self.password = password
        self.compression_level = compression_level
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def _check_cancel(self) -> bool:
        return self._is_cancelled

    def _on_progress(self, percent: int, message: str):
        self.progress.emit(percent, message)

    def run(self):
        try:
            if self.mode == "compress":
                res = compress(
                    self.input_path,
                    self.output_path,
                    password=self.password,
                    compression_level=self.compression_level,
                    progress_callback=self._on_progress,
                    cancel_callback=self._check_cancel,
                )
                orig = format_file_size(res["original_size"])
                comp = format_file_size(res["compressed_size"])
                red = res["reduction"]
                speed = res["speed_kb_s"]
                elapsed = res["elapsed_seconds"]
                file_count = res.get("file_count", 1)
                fmt = res.get("format", "NDC4")
                lock_status = "🔒 Protegido con contrasena" if self.password else "🔓 Sin contrasena"
                info = (
                    f"Formato: {fmt} ({file_count} elementos) | Original: {orig} | Comprimido: {comp} "
                    f"({red:.1f}% reduccion) | {lock_status} | Velocidad: {speed:.1f} KB/s"
                )
                self.finished.emit(self.output_path, info, elapsed)

            elif self.mode == "decompress":
                res = decompress(
                    self.input_path,
                    self.output_path,
                    password=self.password,
                    progress_callback=self._on_progress,
                    cancel_callback=self._check_cancel,
                )
                orig = format_file_size(res["original_size"])
                speed = res["speed_kb_s"]
                elapsed = res["elapsed_seconds"]
                file_count = res.get("file_count", 1)
                fmt = res.get("format", "NDC4")
                info = f"Restaurado: {orig} ({file_count} elementos, {fmt}) | Integridad y clave verificadas | Velocidad: {speed:.1f} KB/s"
                self.finished.emit(self.output_path, info, elapsed)
            else:
                raise ValueError(f"Modo desconocido: {self.mode}")

        except Exception as exc:
            self.error.emit(f"Operacion no completada: {exc}")
