import os
import sys
import re
from typing import List, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QFont, QIcon
from PyQt6.QtWidgets import (QAbstractItemView, QButtonGroup, QCheckBox,
                             QFileDialog, QGroupBox, QHBoxLayout, QHeaderView,
                             QInputDialog, QLabel, QLineEdit, QMainWindow,
                             QMessageBox, QProgressBar, QPushButton,
                             QRadioButton, QTableWidget, QTableWidgetItem,
                             QTextEdit, QVBoxLayout, QWidget)

from .dialogs import ArchiveInfoDialog, ArchiveValidationDialog, SettingsDialog
from .styles import CYBER_DARK_GLASS_THEME
from ..engine import CompressionWorker, get_archive_info
from ..utils.helpers import format_file_size
from ..utils.logger import logger
from ..utils.i18n import tr



def calculate_password_strength(password: str) -> tuple[str, str]:
    """Calcula la fortaleza de la contraseña y retorna (etiqueta, color_hex)."""
    if not password:
        return "Sin contrasena", "#64748B"
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1

    if score <= 2:
        return "Debil", "#EF4444"
    elif score <= 4:
        return "Media", "#EAB308"
    else:
        return "Fuerte", "#22C55E"


class StatCard(QWidget):
    def __init__(self, title: str, default_val: str = "--", parent=None):
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

    def set_value(self, val: str):
        self.lbl_val.setText(val)


class DropZoneWidget(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setAcceptDrops(True)
        self.setText("📦 Arrastra tus archivos o carpetas aqui\no haz clic para examinar")
        self.setMinimumHeight(100)
        self.paths_dropped_callback = None

    def set_callback(self, callback):
        self.paths_dropped_callback = callback

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
        if urls and self.paths_dropped_callback:
            paths = [u.toLocalFile() for u in urls if u.toLocalFile()]
            if paths:
                self.paths_dropped_callback(paths)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.paths_dropped_callback:
            # Invocar selector predeterminado si se hace clic
            pass


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NDAC — Compresor y Protector de Archivos Ultra (NDC5/NDC4/NDC3)")
        self.resize(900, 780)
        self.setStyleSheet(CYBER_DARK_GLASS_THEME)

        icon_path = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "app_icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.selected_paths: List[str] = []
        self.worker: Optional[CompressionWorker] = None
        self.settings = {
            "auto_open_folder": True,
            "confirm_overwrite": True,
            "compression_level": 9,
        }

        self._init_ui()

    def handle_launch_args(self, args: List[str]):
        if not args:
            return
        cmd = args[0].lower()
        if cmd in ("compress", "c"):
            self.radio_compress.setChecked(True)
            self.add_paths(args[1:])
        elif cmd in ("extract", "x", "decompress", "d"):
            self.radio_decompress.setChecked(True)
            self.add_paths(args[1:])
        else:
            self.add_paths(args)

    def _init_ui(self):

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setSpacing(12)
        layout.setContentsMargins(18, 16, 18, 16)

        # Header bar & Tool buttons
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        self.lbl_title = QLabel("NDAC — Compresor de Archivos Ultra")
        self.lbl_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        self.lbl_title.setStyleSheet("color: #38BDF8;")
        self.lbl_subtitle = QLabel("Compresion multielemento (NDC5) con cifrado PBKDF2-HMAC-SHA256.")
        self.lbl_subtitle.setStyleSheet("color: #94A3B8; font-size: 12px;")
        title_box.addWidget(self.lbl_title)
        title_box.addWidget(self.lbl_subtitle)
        header_layout.addLayout(title_box, 1)

        # Menú superior de herramientas
        self.btn_validate = QPushButton("🔍 Validar")
        self.btn_validate.setObjectName("SecondaryBtn")
        self.btn_validate.setToolTip("Comprobar integridad de un archivo .ndac")
        self.btn_validate.clicked.connect(self.action_validate)

        self.btn_info = QPushButton("ℹ️ Propiedades")
        self.btn_info.setObjectName("SecondaryBtn")
        self.btn_info.setToolTip("Ver informacion de un archivo .ndac")
        self.btn_info.clicked.connect(self.action_info)

        self.btn_settings = QPushButton("⚙️ Opciones")
        self.btn_settings.setObjectName("SecondaryBtn")
        self.btn_settings.clicked.connect(self.action_settings)

        header_layout.addWidget(self.btn_validate)
        header_layout.addWidget(self.btn_info)
        header_layout.addWidget(self.btn_settings)
        layout.addLayout(header_layout)

        # Drop Zone & Item Table
        self.drop_zone = DropZoneWidget()
        self.drop_zone.set_callback(self.add_paths)
        layout.addWidget(self.drop_zone)

        # Lista / Tabla de Elementos
        self.items_box = QGroupBox("Elementos Seleccionados para Procesar")
        items_layout = QVBoxLayout(self.items_box)

        self.tbl_items = QTableWidget(0, 3)
        self.tbl_items.setHorizontalHeaderLabels(["Nombre / Ruta", "Tipo", "Tamano"])
        self.tbl_items.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tbl_items.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl_items.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl_items.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl_items.setMinimumHeight(130)

        items_layout.addWidget(self.tbl_items)

        # Botones de gestión de lista
        list_btns = QHBoxLayout()
        self.btn_add_files = QPushButton("+ Agregar Archivos")
        self.btn_add_files.setObjectName("SecondaryBtn")
        self.btn_add_files.clicked.connect(self.browse_files)

        self.btn_add_folder = QPushButton("+ Agregar Carpeta")
        self.btn_add_folder.setObjectName("SecondaryBtn")
        self.btn_add_folder.clicked.connect(self.browse_folder)

        self.btn_remove_item = QPushButton("🗑️ Eliminar")
        self.btn_remove_item.setObjectName("SecondaryBtn")
        self.btn_remove_item.clicked.connect(self.remove_selected_items)

        self.btn_clear_list = QPushButton("🧹 Limpiar Lista")
        self.btn_clear_list.setObjectName("SecondaryBtn")
        self.btn_clear_list.clicked.connect(self.clear_items)

        self.lbl_list_summary = QLabel("0 elementos | 0 B")
        self.lbl_list_summary.setStyleSheet("color: #38BDF8; font-weight: bold;")

        list_btns.addWidget(self.btn_add_files)
        list_btns.addWidget(self.btn_add_folder)
        list_btns.addWidget(self.btn_remove_item)
        list_btns.addWidget(self.btn_clear_list)
        list_btns.addStretch(1)
        list_btns.addWidget(self.lbl_list_summary)

        items_layout.addLayout(list_btns)
        layout.addWidget(self.items_box)

        # Operación y Protección por Contraseña
        opts_layout = QHBoxLayout()

        self.mode_box = QGroupBox("Modo de Operacion")
        mode_layout = QHBoxLayout(self.mode_box)
        self.radio_compress = QRadioButton("Comprimir a .ndac")
        self.radio_decompress = QRadioButton("Descomprimir .ndac")
        self.radio_compress.setChecked(True)
        group = QButtonGroup(self)
        group.addButton(self.radio_compress)
        group.addButton(self.radio_decompress)
        mode_layout.addWidget(self.radio_compress)
        mode_layout.addWidget(self.radio_decompress)
        opts_layout.addWidget(self.mode_box, 1)

        self.pass_box = QGroupBox("Proteccion con Contrasena")
        pass_layout = QVBoxLayout(self.pass_box)

        pass_row = QHBoxLayout()
        self.chk_use_password = QCheckBox("Proteger con contrasena")
        self.chk_use_password.toggled.connect(self.toggle_password_fields)
        pass_row.addWidget(self.chk_use_password)

        self.lbl_strength = QLabel("")
        self.lbl_strength.setStyleSheet("font-weight: bold;")
        pass_row.addStretch()
        pass_row.addWidget(self.lbl_strength)
        pass_layout.addLayout(pass_row)

        fields_row = QHBoxLayout()
        self.txt_password = QLineEdit()
        self.txt_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_password.setPlaceholderText("Contrasena...")
        self.txt_password.setEnabled(False)
        self.txt_password.textChanged.connect(self.on_password_changed)

        self.txt_confirm_password = QLineEdit()
        self.txt_confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_confirm_password.setPlaceholderText("Confirmar...")
        self.txt_confirm_password.setEnabled(False)

        self.btn_toggle_eye = QPushButton("👁️")
        self.btn_toggle_eye.setObjectName("ToggleEyeBtn")
        self.btn_toggle_eye.clicked.connect(self.toggle_password_visibility)

        fields_row.addWidget(self.txt_password, 1)
        fields_row.addWidget(self.txt_confirm_password, 1)
        fields_row.addWidget(self.btn_toggle_eye)
        pass_layout.addLayout(fields_row)

        opts_layout.addWidget(self.pass_box, 1)
        layout.addLayout(opts_layout)

        # Stat Cards
        stats_layout = QHBoxLayout()
        self.card_orig = StatCard("Tamano Original")
        self.card_comp = StatCard("Resultado")
        self.card_speed = StatCard("Velocidad / ETA")
        stats_layout.addWidget(self.card_orig)
        stats_layout.addWidget(self.card_comp)
        stats_layout.addWidget(self.card_speed)
        layout.addLayout(stats_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        # Action Buttons
        buttons = QHBoxLayout()
        self.btn_start = QPushButton("🚀 Iniciar Proceso")
        self.btn_start.clicked.connect(self.start_process)

        self.btn_cancel = QPushButton("❌ Cancelar")
        self.btn_cancel.setObjectName("CancelBtn")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel_process)

        self.btn_open_folder = QPushButton("📂 Abrir Ubicacion")
        self.btn_open_folder.setObjectName("SecondaryBtn")
        self.btn_open_folder.setEnabled(False)
        self.btn_open_folder.clicked.connect(self.open_output_folder)

        buttons.addWidget(self.btn_start, 2)
        buttons.addWidget(self.btn_cancel, 1)
        buttons.addWidget(self.btn_open_folder, 1)
        layout.addLayout(buttons)

        # Terminal console log
        self.log_box = QGroupBox("Registro de Operaciones")
        log_layout = QVBoxLayout(self.log_box)
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setMaximumHeight(100)
        log_layout.addWidget(self.txt_log)
        layout.addWidget(self.log_box)

        self.refresh_ui_texts()


        self.log_message("Sistema NDAC iniciado (Compatibilidad NDC3/NDC4/NDC5).")

    def toggle_password_fields(self, enabled: bool):
        self.txt_password.setEnabled(enabled)
        self.txt_confirm_password.setEnabled(enabled)
        if not enabled:
            self.txt_password.clear()
            self.txt_confirm_password.clear()
            self.lbl_strength.setText("")

    def on_password_changed(self, text: str):
        if not self.chk_use_password.isChecked():
            self.lbl_strength.setText("")
            return
        label, color = calculate_password_strength(text)
        self.lbl_strength.setText(f"Fortaleza: {label}")
        self.lbl_strength.setStyleSheet(f"color: {color}; font-weight: bold;")

    def toggle_password_visibility(self):
        if self.txt_password.echoMode() == QLineEdit.EchoMode.Password:
            self.txt_password.setEchoMode(QLineEdit.EchoMode.Normal)
            self.txt_confirm_password.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_toggle_eye.setText("🙈")
        else:
            self.txt_password.setEchoMode(QLineEdit.EchoMode.Password)
            self.txt_confirm_password.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_toggle_eye.setText("👁️")

    def log_message(self, message: str):
        self.txt_log.append(f"> {message}")
        logger.info(message)

    def add_paths(self, paths: List[str]):
        for p in paths:
            if p and p not in self.selected_paths and os.path.exists(p):
                self.selected_paths.append(p)

        self.update_items_table()

    def browse_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Seleccionar Archivos")
        if paths:
            self.add_paths(paths)

    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar Carpeta")
        if folder:
            self.add_paths([folder])

    def remove_selected_items(self):
        selected_rows = sorted(set(index.row() for index in self.tbl_items.selectedIndexes()), reverse=True)
        for r in selected_rows:
            if 0 <= r < len(self.selected_paths):
                del self.selected_paths[r]
        self.update_items_table()

    def clear_items(self):
        self.selected_paths.clear()
        self.update_items_table()

    def update_items_table(self):
        self.tbl_items.setRowCount(0)
        total_bytes = 0

        for p in self.selected_paths:
            row = self.tbl_items.rowCount()
            self.tbl_items.insertRow(row)

            name_item = QTableWidgetItem(os.path.basename(p) or p)
            name_item.setToolTip(p)

            if os.path.isdir(p):
                type_item = QTableWidgetItem("📁 Carpeta")
                dir_bytes = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fn in os.walk(p) for f in fn)
                size_item = QTableWidgetItem(format_file_size(dir_bytes))
                total_bytes += dir_bytes
            else:
                type_item = QTableWidgetItem("📄 Archivo")
                sz = os.path.getsize(p)
                size_item = QTableWidgetItem(format_file_size(sz))
                total_bytes += sz

            self.tbl_items.setItem(row, 0, name_item)
            self.tbl_items.setItem(row, 1, type_item)
            self.tbl_items.setItem(row, 2, size_item)

        count = len(self.selected_paths)
        formatted_total = format_file_size(total_bytes)
        self.lbl_list_summary.setText(f"{count} elementos | {formatted_total}")

        self.card_orig.set_value(formatted_total if count > 0 else "--")
        self.card_comp.set_value("--")
        self.card_speed.set_value("--")

        # Auto-detectar descompresión si se agrega un único archivo .ndac
        if count == 1 and self.selected_paths[0].lower().endswith(".ndac"):
            self.radio_decompress.setChecked(True)
            self.log_message(f"Archivo .ndac detectado: {os.path.basename(self.selected_paths[0])}")
        elif count > 0:
            self.radio_compress.setChecked(True)

    @staticmethod
    def _available_output_path(directory: str, filename: str, label: str) -> str:
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
        if not self.selected_paths:
            QMessageBox.warning(self, "Elementos requeridos", "Selecciona al menos un archivo o carpeta antes de continuar.")
            return

        is_compress = self.radio_compress.isChecked()
        password = None

        if self.chk_use_password.isChecked():
            pass_val = self.txt_password.text()
            confirm_val = self.txt_confirm_password.text()
            if is_compress:
                if not pass_val:
                    QMessageBox.warning(self, "Contrasena requerida", "Introduce una contrasena para proteger el archivo.")
                    return
                if pass_val != confirm_val:
                    QMessageBox.warning(self, "Error de coincidencia", "Las contrasenas no coinciden.")
                    return
            password = pass_val

        if is_compress:
            first = self.selected_paths[0]
            base_dir = os.path.dirname(first) or os.getcwd()
            default_name = (os.path.basename(first) if len(self.selected_paths) == 1 else "conjunto_archivos") + ".ndac"

            output_path = self._available_output_path(base_dir, default_name, "comprimido")
        else:
            compressed_file = self.selected_paths[0]
            try:
                info = get_archive_info(compressed_file)
                default_name = info.get("filename", "restaurado")
                output_path = os.path.dirname(compressed_file)
            except Exception as exc:
                QMessageBox.warning(self, "Archivo invalido", f"No se pudo leer la cabecera: {exc}")
                return

        self.btn_start.setEnabled(False)
        self.btn_add_files.setEnabled(False)
        self.btn_add_folder.setEnabled(False)
        self.btn_clear_list.setEnabled(False)
        self.btn_open_folder.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setValue(0)

        mode = "compress" if is_compress else "decompress"
        action_name = "compresion" if is_compress else "descompresion"
        lock_msg = " 🔒 (Protegido)" if password else " 🔓 (Sin cifrado)"

        self.log_message(f"Iniciando {action_name}{lock_msg}...")
        self.log_message(f"Ubicacion de salida: {output_path}")

        level = self.settings.get("compression_level", 9)
        input_param = self.selected_paths if is_compress else self.selected_paths[0]

        self.worker = CompressionWorker(
            mode, input_param, output_path, password=password, compression_level=level
        )
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

    def on_worker_progress(self, percent: int, message: str):
        self.progress_bar.setValue(percent)
        if message:
            self.card_speed.set_value(message.split(":")[-1].strip() if ":" in message else message)

    def on_worker_finished(self, output_path: str, info: str, elapsed_seconds: float):
        self.progress_bar.setValue(100)
        self.btn_start.setEnabled(True)
        self.btn_add_files.setEnabled(True)
        self.btn_add_folder.setEnabled(True)
        self.btn_clear_list.setEnabled(True)
        self.btn_open_folder.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.last_output_path = output_path

        out_size = format_file_size(os.path.getsize(output_path) if os.path.isfile(output_path) else 0)
        self.card_comp.set_value(out_size)
        self.card_speed.set_value(f"{elapsed_seconds:.2f} s")

        self.log_message(f"Proceso finalizado con exito en {elapsed_seconds:.2f} s")
        self.log_message(info)

        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Operacion completada")
        msg_box.setText(f"✓ Operacion completada con exito en {elapsed_seconds:.2f} s.\n\n{info}\n\nUbicacion:\n{output_path}")

        btn_open = msg_box.addButton("📂 Abrir ubicacion", QMessageBox.ButtonRole.ActionRole)
        msg_box.addButton(QMessageBox.StandardButton.Ok)
        msg_box.exec()

        if msg_box.clickedButton() == btn_open:
            self.open_output_folder()

    def on_worker_error(self, error_message: str):
        self.btn_start.setEnabled(True)
        self.btn_add_files.setEnabled(True)
        self.btn_add_folder.setEnabled(True)
        self.btn_clear_list.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.log_message(f"ERROR: {error_message}")
        QMessageBox.critical(self, "Error en la operacion", error_message)

    def open_output_folder(self):
        if hasattr(self, "last_output_path") and os.path.exists(self.last_output_path):
            folder = os.path.dirname(self.last_output_path) if os.path.isfile(self.last_output_path) else self.last_output_path
            if sys.platform == "win32":
                os.startfile(folder)
            else:
                import subprocess
                subprocess.run(["open" if sys.platform == "darwin" else "xdg-open", folder])

    def _get_target_ndac_path(self, title: str) -> Optional[str]:
        # Si ya hay un archivo .ndac cargado en la lista, usarlo directamente
        for p in self.selected_paths:
            if p.lower().endswith(".ndac") and os.path.isfile(p):
                return p
        # Si no, solicitar al usuario que seleccione uno
        path, _ = QFileDialog.getOpenFileName(self, title, "", "Archivos NDAC (*.ndac)")
        return path or None

    def action_validate(self):
        path = self._get_target_ndac_path("Seleccionar archivo .ndac para validar")
        if path:
            password = None
            if self.chk_use_password.isChecked():
                password = self.txt_password.text() or None
            dlg = ArchiveValidationDialog(path, password=password, parent=self)
            dlg.exec()

    def action_info(self):
        path = self._get_target_ndac_path("Seleccionar archivo .ndac para propiedades")
        if path:
            try:
                info = get_archive_info(path)
                dlg = ArchiveInfoDialog(info, parent=self)
                dlg.exec()
            except Exception as exc:
                QMessageBox.warning(self, "Error al leer propiedades", str(exc))


    def refresh_ui_texts(self):
        lang = self.settings.get("language", "es")
        self.setWindowTitle(tr("app_title", lang))
        self.lbl_title.setText(tr("app_title", lang))
        self.lbl_subtitle.setText(tr("app_subtitle", lang))
        self.btn_validate.setText(tr("btn_validate", lang))
        self.btn_info.setText(tr("btn_info", lang))
        self.btn_settings.setText(tr("btn_settings", lang))
        self.drop_zone.setText(tr("drop_zone_text", lang))
        self.items_box.setTitle(tr("selected_items_title", lang))
        self.tbl_items.setHorizontalHeaderLabels([tr("col_name", lang), tr("col_type", lang), tr("col_size", lang)])
        self.btn_add_files.setText(tr("btn_add_files", lang))
        self.btn_add_folder.setText(tr("btn_add_folder", lang))
        self.btn_remove_item.setText(tr("btn_remove", lang))
        self.btn_clear_list.setText(tr("btn_clear", lang))
        self.mode_box.setTitle(tr("mode_operation", lang))
        self.radio_compress.setText(tr("radio_compress", lang))
        self.radio_decompress.setText(tr("radio_decompress", lang))
        self.pass_box.setTitle(tr("pass_protection", lang))
        self.chk_use_password.setText(tr("chk_use_password", lang))
        self.txt_password.setPlaceholderText(tr("ph_password", lang))
        self.txt_confirm_password.setPlaceholderText(tr("ph_confirm_password", lang))
        self.card_orig.lbl_title.setText(tr("stat_original_size", lang))
        self.card_comp.lbl_title.setText(tr("stat_result_size", lang))
        self.card_speed.lbl_title.setText(tr("stat_speed_eta", lang))
        self.btn_start.setText(tr("btn_start", lang))
        self.btn_cancel.setText(tr("btn_cancel", lang))
        self.btn_open_folder.setText(tr("btn_open_folder", lang))
        self.log_box.setTitle(tr("log_console_title", lang))

    def action_settings(self):
        dlg = SettingsDialog(self.settings, parent=self)
        if dlg.exec() == SettingsDialog.DialogCode.Accepted:
            self.settings = dlg.get_settings()
            self.refresh_ui_texts()
            self.log_message("Configuracion de usuario actualizada.")

