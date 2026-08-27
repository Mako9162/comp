import os
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QFont, QIcon
from PyQt6.QtWidgets import (QButtonGroup, QFileDialog, QGroupBox, QHBoxLayout,
                             QInputDialog, QLabel, QLineEdit, QMainWindow,
                             QMessageBox, QProgressBar, QPushButton,
                             QRadioButton, QTextEdit, QVBoxLayout, QWidget)

from .styles import CYBER_DARK_GLASS_THEME
from ..engine.compressor import CompressionWorker
from ..utils.helpers import format_file_size, read_header


class StatCard(QWidget):
    def __init__(self, title, default_val="--", parent=None):
        super().__init__(parent)
        self.setObjectName("StatCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(2)

        self.lbl_title = QLabel(title)
        self.lbl_title.setObjectName("StatTitle")
        self.lbl_val = QLabel(default_val)
        self.lbl_val.setObjectName("StatValue")

        layout.addWidget(self.lbl_title)
        layout.addWidget(self.lbl_val)

    def set_value(self, val):
        self.lbl_val.setText(val)


class DropZoneWidget(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setAcceptDrops(True)
        self.setText("📁 Arrastra y suelta un archivo aqui\no usa 'Examinar archivo'")
        self.setMinimumHeight(120)
        self.file_dropped_callback = None

    def set_callback(self, callback):
        self.file_dropped_callback = callback

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setProperty("dragActive", True)
            self.style().unpolish(self)
            self.style().polish(self)

    def dragLeaveEvent(self, event):
        self.setProperty("dragActive", False)
        self.style().unpolish(self)
        self.style().polish(self)

    def dropEvent(self, event: QDropEvent):
        self.setProperty("dragActive", False)
        self.style().unpolish(self)
        self.style().polish(self)
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.isfile(path) and self.file_dropped_callback:
                self.file_dropped_callback(path)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Compresor de Archivos NDC4 - Cifrado PBKDF2")
        self.resize(800, 700)
        self.setStyleSheet(CYBER_DARK_GLASS_THEME)

        icon_path = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "app_icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.selected_file_path = None
        self.worker = None
        self._init_ui()

    def _init_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Compresor de Archivos Ultra (NDC4)")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #38BDF8;")
        subtitle = QLabel("Compresion local sin perdida con cifrado PBKDF2-HMAC-SHA256 opcional.")
        subtitle.setStyleSheet("color: #94A3B8; font-size: 12px;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_layout.addLayout(title_box, 1)

        layout.addLayout(header_layout)

        # Drop Zone & File Selection
        self.drop_zone = DropZoneWidget()
        self.drop_zone.set_callback(self.on_file_selected)
        layout.addWidget(self.drop_zone)

        selection = QHBoxLayout()
        self.btn_select_file = QPushButton("Examinar archivo")
        self.btn_select_file.setObjectName("SecondaryBtn")
        self.btn_select_file.clicked.connect(self.browse_file)
        self.lbl_selected_info = QLabel("Ningun archivo seleccionado")
        self.lbl_selected_info.setStyleSheet("color: #94A3B8;")
        selection.addWidget(self.btn_select_file)
        selection.addWidget(self.lbl_selected_info, 1)
        layout.addLayout(selection)

        # Mode Selection & Password Option
        opts_layout = QHBoxLayout()

        mode_box = QGroupBox("Modo de Operacion")
        mode_layout = QHBoxLayout(mode_box)
        self.radio_compress = QRadioButton("Comprimir a .ndac")
        self.radio_decompress = QRadioButton("Descomprimir .ndac")
        self.radio_compress.setChecked(True)
        group = QButtonGroup(self)
        group.addButton(self.radio_compress)
        group.addButton(self.radio_decompress)
        mode_layout.addWidget(self.radio_compress)
        mode_layout.addWidget(self.radio_decompress)
        opts_layout.addWidget(mode_box, 1)

        pass_box = QGroupBox("Proteccion con Contrasena (Opcional)")
        pass_inner = QHBoxLayout(pass_box)
        self.txt_password = QLineEdit()
        self.txt_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_password.setPlaceholderText("Introduce contrasena para proteger...")
        self.btn_toggle_eye = QPushButton("👁️")
        self.btn_toggle_eye.setObjectName("ToggleEyeBtn")
        self.btn_toggle_eye.setToolTip("Mostrar/Ocultar contrasena")
        self.btn_toggle_eye.clicked.connect(self.toggle_password_visibility)

        pass_inner.addWidget(self.txt_password, 1)
        pass_inner.addWidget(self.btn_toggle_eye)
        opts_layout.addWidget(pass_box, 1)

        layout.addLayout(opts_layout)

        # Live Metrics / Stats Cards
        stats_layout = QHBoxLayout()
        self.card_orig = StatCard("Tamano Original")
        self.card_comp = StatCard("Resultado")
        self.card_speed = StatCard("Velocidad")
        stats_layout.addWidget(self.card_orig)
        stats_layout.addWidget(self.card_comp)
        stats_layout.addWidget(self.card_speed)
        layout.addLayout(stats_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        # Action Buttons
        buttons = QHBoxLayout()
        self.btn_start = QPushButton("🚀 Iniciar proceso")
        self.btn_start.clicked.connect(self.start_process)

        self.btn_cancel = QPushButton("❌ Cancelar")
        self.btn_cancel.setObjectName("CancelBtn")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel_process)

        self.btn_open_folder = QPushButton("📂 Abrir ubicacion")
        self.btn_open_folder.setObjectName("SecondaryBtn")
        self.btn_open_folder.setEnabled(False)
        self.btn_open_folder.clicked.connect(self.open_output_folder)

        buttons.addWidget(self.btn_start, 2)
        buttons.addWidget(self.btn_cancel, 1)
        buttons.addWidget(self.btn_open_folder, 1)
        layout.addLayout(buttons)

        # Log Terminal Console
        log_box = QGroupBox("Registro de Operaciones")
        log_layout = QVBoxLayout(log_box)
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        log_layout.addWidget(self.txt_log)
        layout.addWidget(log_box, 1)

        self.log_message("Sistema NDC4 iniciado y listo.")

    def toggle_password_visibility(self):
        if self.txt_password.echoMode() == QLineEdit.EchoMode.Password:
            self.txt_password.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_toggle_eye.setText("🙈")
        else:
            self.txt_password.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_toggle_eye.setText("👁️")

    def log_message(self, message):
        self.txt_log.append(f"> {message}")

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo")
        if path:
            self.on_file_selected(path)

    def on_file_selected(self, path):
        self.selected_file_path = path
        name = os.path.basename(path)
        size_bytes = os.path.getsize(path)
        size_formatted = format_file_size(size_bytes)

        self.lbl_selected_info.setText(f"{name} ({size_formatted})")
        self.drop_zone.setText(f"📄 Archivo Seleccionado:\n{name}\n({size_formatted})")
        self.drop_zone.setProperty("fileLoaded", True)
        self.drop_zone.style().unpolish(self.drop_zone)
        self.drop_zone.style().polish(self.drop_zone)

        self.card_orig.set_value(size_formatted)
        self.card_comp.set_value("--")
        self.card_speed.set_value("--")

        if path.lower().endswith(".ndac"):
            self.radio_decompress.setChecked(True)
            self.log_message(f"Archivo .ndac cargado. Listo para restaurar {name}.")
        else:
            self.radio_compress.setChecked(True)
            self.log_message(f"Archivo cargado: {name}. Listo para comprimir a .ndac.")

    @staticmethod
    def _available_output_path(directory, filename, label):
        candidate = os.path.join(directory, filename)
        if not os.path.exists(candidate):
            return candidate
        stem, extension = os.path.splitext(filename)
        index = 1
        while True:
            suffix = f" ({label})" if index == 1 else f" ({label} {index})"
            candidate = os.path.join(directory, f"{stem}{suffix}{extension}")
            if not os.path.exists(candidate):
                return candidate
            index += 1

    def start_process(self):
        if not self.selected_file_path or not os.path.isfile(self.selected_file_path):
            QMessageBox.warning(self, "Archivo requerido", "Selecciona un archivo valido antes de continuar.")
            return

        is_compress = self.radio_compress.isChecked()
        password = self.txt_password.text().strip() or None

        if is_compress:
            output_path = self._available_output_path(
                os.path.dirname(self.selected_file_path),
                os.path.basename(self.selected_file_path) + ".ndac", "comprimido"
            )
        else:
            try:
                with open(self.selected_file_path, "rb") as compressed_file:
                    header_info = read_header(compressed_file, password=password)
                    original_filename, target_size, _, _, is_encrypted, _ = header_info

                output_path = self._available_output_path(
                    os.path.dirname(self.selected_file_path),
                    os.path.basename(original_filename) or "archivo_restaurado", "restaurado"
                )
            except ValueError as val_err:
                if "protegido con contrasena" in str(val_err) or "Contrasena incorrecta" in str(val_err):
                    pass_input, ok = QInputDialog.getText(
                        self, "Contrasena requerida",
                        "El archivo esta protegido. Introduce la contrasena:",
                        QLineEdit.EchoMode.Password
                    )
                    if ok and pass_input:
                        self.txt_password.setText(pass_input)
                        password = pass_input
                        try:
                            with open(self.selected_file_path, "rb") as compressed_file:
                                header_info = read_header(compressed_file, password=password)
                                original_filename = header_info[0]
                            output_path = self._available_output_path(
                                os.path.dirname(self.selected_file_path),
                                os.path.basename(original_filename) or "archivo_restaurado", "restaurado"
                            )
                        except Exception as inner_exc:
                            QMessageBox.critical(self, "Error de contrasena", str(inner_exc))
                            return
                    else:
                        return
                else:
                    QMessageBox.warning(self, "Archivo no compatible", str(val_err))
                    return
            except Exception as exc:
                QMessageBox.warning(self, "Archivo no compatible", str(exc))
                return

        self.btn_start.setEnabled(False)
        self.btn_select_file.setEnabled(False)
        self.btn_open_folder.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setValue(0)

        mode = "compress" if is_compress else "decompress"
        action_name = "compresion" if is_compress else "descompresion"
        lock_msg = " 🔒 (Protegido con cifrado)" if password else " 🔓 (Sin cifrado)"

        self.log_message(f"Iniciando {action_name}{lock_msg}...")
        self.log_message(f"Ubicacion de salida: {output_path}")

        self.worker = CompressionWorker(mode, self.selected_file_path, output_path, password=password)
        self.worker.progress.connect(self.on_worker_progress)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.error.connect(self.on_worker_error)
        self.worker.error.connect(self.worker.deleteLater)
        self.worker.start()

    def cancel_process(self):
        if self.worker and self.worker.isRunning():
            self.log_message("Enviando solicitud de cancelacion...")
            self.worker.cancel()
            self.btn_cancel.setEnabled(False)

    def on_worker_progress(self, progress, message):
        self.progress_bar.setValue(progress)
        if message:
            self.log_message(message)

    def on_worker_finished(self, output_path, info, elapsed_seconds):
        self.progress_bar.setValue(100)
        self.btn_start.setEnabled(True)
        self.btn_select_file.setEnabled(True)
        self.btn_open_folder.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.last_output_path = output_path

        out_size = format_file_size(os.path.getsize(output_path))
        self.card_comp.set_value(out_size)
        if elapsed_seconds > 0:
            speed_kb = os.path.getsize(output_path) / 1024 / elapsed_seconds
            self.card_speed.set_value(f"{speed_kb:.1f} KB/s")

        self.log_message(f"Proceso finalizado con exito en {elapsed_seconds:.2f} s")
        self.log_message(info)
        QMessageBox.information(self, "Operacion exitosa", f"{info}\n\nGuardado en:\n{output_path}")

    def on_worker_error(self, error_message):
        self.btn_start.setEnabled(True)
        self.btn_select_file.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.log_message(f"ERROR: {error_message}")
        QMessageBox.critical(self, "Error en el proceso", error_message)

    def open_output_folder(self):
        if hasattr(self, "last_output_path") and os.path.exists(self.last_output_path):
            folder = os.path.dirname(self.last_output_path)
            if sys.platform == "win32":
                os.startfile(folder)
            else:
                import subprocess
                subprocess.run(["open" if sys.platform == "darwin" else "xdg-open", folder])

