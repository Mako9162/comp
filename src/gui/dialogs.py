import os
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QComboBox, QCheckBox, QGroupBox,
                             QFormLayout, QTextEdit)

from ..utils.helpers import format_file_size
from ..engine import validate_archive, get_archive_info


class ArchiveInfoDialog(QDialog):
    """Diálogo que muestra las propiedades detalladas de un archivo .ndac."""

    def __init__(self, info: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Propiedades del Archivo NDAC")
        self.setMinimumWidth(420)
        self.setStyleSheet(parent.styleSheet() if parent else "")

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        header = QLabel("Informacion del Archivo NDAC")
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #38BDF8;")
        layout.addWidget(header)

        box = QGroupBox("Metadatos y Compresion")
        form = QFormLayout(box)
        form.setSpacing(8)

        form.addRow("Archivo:", QLabel(os.path.basename(info.get("archive_path", ""))))
        form.addRow("Formato:", QLabel(f"{info.get('format', 'NDC4')} (Version {info.get('version', 4)})"))
        form.addRow("Elementos contenidos:", QLabel(str(info.get("file_count", 1))))
        form.addRow("Tamano original:", QLabel(format_file_size(info.get("original_size", 0))))
        form.addRow("Tamano comprimido:", QLabel(format_file_size(info.get("compressed_size", 0))))

        red = info.get("reduction_percent", 0.0)
        lbl_red = QLabel(f"{red:.1f}%")
        lbl_red.setStyleSheet("color: #4ADE80; font-weight: bold;" if red > 0 else "")
        form.addRow("Reduccion:", lbl_red)

        form.addRow("Algoritmo:", QLabel(info.get("compression_algorithm", "DEFLATE (zlib)")))
        
        is_enc = info.get("is_encrypted", False)
        lbl_enc = QLabel("🔒 Si (PBKDF2-HMAC-SHA256)" if is_enc else "🔓 No")
        form.addRow("Cifrado:", lbl_enc)

        form.addRow("Checksum CRC32:", QLabel(info.get("crc32_checksum", "--")))

        layout.addWidget(box)

        btn_close = QPushButton("Cerrar")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignmentFlag.AlignRight)


class ArchiveValidationDialog(QDialog):
    """Diálogo para validar la integridad de un archivo .ndac."""

    def __init__(self, archive_path: str, password: str = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Validacion de Archivo NDAC")
        self.setMinimumWidth(450)
        self.setStyleSheet(parent.styleSheet() if parent else "")

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        header = QLabel("Informe de Validacion e Integridad")
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #38BDF8;")
        layout.addWidget(header)

        val_result = validate_archive(archive_path, password=password)

        if val_result.get("valid"):
            status_box = QGroupBox("✓ Archivo Valido")
            status_box.setStyleSheet("QGroupBox { border: 1px solid #22C55E; color: #22C55E; }")
            box_layout = QVBoxLayout(status_box)

            info_text = (
                f"Formato: {val_result.get('format')}\n"
                f"Elementos: {val_result.get('file_count')}\n"
                f"Tamano original: {format_file_size(val_result.get('original_size', 0))}\n"
                f"Tamano comprimido: {format_file_size(val_result.get('compressed_size', 0))}\n"
                f"Reduccion: {val_result.get('reduction_percent', 0):.1f}%\n"
                f"Integridad CRC32: OK\n"
                f"Cifrado: {'Protegido con clave' if val_result.get('is_encrypted') else 'Sin cifrado'}"
            )
            txt = QTextEdit()
            txt.setPlainText(info_text)
            txt.setReadOnly(True)
            box_layout.addWidget(txt)
            layout.addWidget(status_box)
        else:
            status_box = QGroupBox("✗ Archivo Corrupto o Invalido")
            status_box.setStyleSheet("QGroupBox { border: 1px solid #EF4444; color: #EF4444; }")
            box_layout = QVBoxLayout(status_box)

            err_msg = val_result.get("error", "Error de integridad desconocido.")
            txt = QTextEdit()
            txt.setPlainText(f"Motivo del fallo:\n{err_msg}")
            txt.setReadOnly(True)
            box_layout.addWidget(txt)
            layout.addWidget(status_box)

        btn_close = QPushButton("Cerrar")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignmentFlag.AlignRight)


class SettingsDialog(QDialog):
    """Diálogo de configuración de la aplicación NDAC."""

    def __init__(self, settings: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configuracion - NDAC")
        self.setMinimumWidth(400)
        self.setStyleSheet(parent.styleSheet() if parent else "")
        self.settings = settings.copy()

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        header = QLabel("Preferencias Generales")
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #38BDF8;")
        layout.addWidget(header)

        box_gen = QGroupBox("General")
        form_gen = QFormLayout(box_gen)

        self.chk_auto_open = QCheckBox("Abrir carpeta de destino al finalizar")
        self.chk_auto_open.setChecked(self.settings.get("auto_open_folder", True))

        self.chk_confirm_overwrite = QCheckBox("Confirmar antes de sobrescribir archivos")
        self.chk_confirm_overwrite.setChecked(self.settings.get("confirm_overwrite", True))

        form_gen.addRow(self.chk_auto_open)
        form_gen.addRow(self.chk_confirm_overwrite)
        layout.addWidget(box_gen)

        box_comp = QGroupBox("Compresion e Idioma")
        form_comp = QFormLayout(box_comp)

        self.combo_language = QComboBox()
        self.combo_language.addItem("Español", "es")
        self.combo_language.addItem("English", "en")
        current_lang = self.settings.get("language", "es")
        self.combo_language.setCurrentIndex(0 if current_lang == "es" else 1)

        self.combo_level = QComboBox()
        self.combo_level.addItem("Rapida (Menor CPU, menor compresion)", 1)
        self.combo_level.addItem("Normal (Equilibrio recomendado)", 6)
        self.combo_level.addItem("Maxima (Mayor CPU, mejor compresion)", 9)

        lvl = self.settings.get("compression_level", 9)
        idx = 0 if lvl == 1 else (1 if lvl == 6 else 2)
        self.combo_level.setCurrentIndex(idx)

        form_comp.addRow("Idioma / Language:", self.combo_language)
        form_comp.addRow("Nivel predeterminado:", self.combo_level)
        layout.addWidget(box_comp)

        # Botones Acción
        btns = QHBoxLayout()
        btn_save = QPushButton("Guardar")
        btn_save.clicked.connect(self.save_settings)
        btn_cancel = QPushButton("Cancelar")
        btn_cancel.setObjectName("CancelBtn")
        btn_cancel.clicked.connect(self.reject)

        btns.addStretch()
        btns.addWidget(btn_cancel)
        btns.addWidget(btn_save)
        layout.addLayout(btns)

    def save_settings(self):
        self.settings["auto_open_folder"] = self.chk_auto_open.isChecked()
        self.settings["confirm_overwrite"] = self.chk_confirm_overwrite.isChecked()
        self.settings["compression_level"] = self.combo_level.currentData()
        self.settings["language"] = self.combo_language.currentData()
        self.accept()

    def get_settings(self) -> dict:
        return self.settings

