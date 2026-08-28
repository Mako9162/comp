# Style Sheet moderno QSS para PyQt6 (Tema Cyber Dark Glass)

CYBER_DARK_GLASS_THEME = """
QMainWindow, QDialog {
    background-color: #0B0F19;
    color: #F8FAFC;
}

QWidget {
    font-family: 'Segoe UI', 'Inter', -apple-system, sans-serif;
    font-size: 13px;
    color: #E2E8F0;
}

/* ScrollArea y ScrollBars Adaptativos */
QScrollArea {
    background-color: transparent;
    border: none;
}

QScrollBar:vertical {
    background-color: #0B0F19;
    width: 10px;
    margin: 0px;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background-color: #1E293B;
    min-height: 25px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background-color: #0284C7;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
    border: none;
    background: none;
}

QScrollBar:horizontal {
    background-color: #0B0F19;
    height: 10px;
    margin: 0px;
    border-radius: 5px;
}

QScrollBar::handle:horizontal {
    background-color: #1E293B;
    min-width: 25px;
    border-radius: 5px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #0284C7;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
    border: none;
    background: none;
}

/* Tarjetas y Contenedores */
QGroupBox {
    background-color: #131B2E;
    border: 1px solid #1E293B;
    border-radius: 14px;
    margin-top: 14px;
    font-weight: 700;
    color: #38BDF8;
    padding: 16px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 10px;
}

/* Zona de Arrastrar y Soltar (Drop Zone) */
#DropZone {
    background-color: #131B2E;
    border: 2px dashed #0284C7;
    border-radius: 16px;
    color: #94A3B8;
    padding: 20px;
    text-align: center;
    font-size: 14px;
    font-weight: 500;
}

#DropZone[dragActive="true"] {
    background-color: #0C4A6E;
    border-color: #38BDF8;
    color: #FFFFFF;
}

#DropZone[fileLoaded="true"] {
    border-style: solid;
    border-color: #10B981;
    background-color: #064E3B;
    color: #ECFDF5;
}

/* Tabla de elementos seleccionados */
QTableWidget {
    background-color: #070A12;
    border: 1px solid #1E293B;
    border-radius: 10px;
    gridline-color: #1E293B;
    color: #F8FAFC;
    selection-background-color: #0284C7;
    selection-color: #FFFFFF;
}

QHeaderView::section {
    background-color: #0F172A;
    color: #38BDF8;
    padding: 6px;
    border: 1px solid #1E293B;
    font-weight: 600;
}

/* Campos de entrada */
QLineEdit, QComboBox {
    background-color: #070A12;
    border: 1px solid #334155;
    border-radius: 8px;
    color: #F8FAFC;
    padding: 8px 12px;
    font-size: 13px;
}

QLineEdit:focus, QComboBox:focus {
    border: 1px solid #38BDF8;
    background-color: #0F172A;
}

QComboBox QAbstractItemView {
    background-color: #0F172A;
    border: 1px solid #334155;
    selection-background-color: #0284C7;
    color: #F8FAFC;
}

/* Botones Principales */
QPushButton {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563EB, stop:1 #0284C7);
    color: #FFFFFF;
    border: none;
    border-radius: 9px;
    padding: 10px 20px;
    font-weight: 600;
    font-size: 13px;
}

QPushButton:hover {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1D4ED8, stop:1 #0369A1);
}

QPushButton:pressed {
    background-color: #1E40AF;
}

QPushButton:disabled {
    background-color: #1E293B;
    color: #64748B;
}

QPushButton#SecondaryBtn {
    background-color: #1E293B;
    color: #F8FAFC;
    border: 1px solid #334155;
}

QPushButton#SecondaryBtn:hover {
    background-color: #334155;
    border-color: #475569;
}

QPushButton#CancelBtn {
    background-color: #991B1B;
    color: #FEF2F2;
}

QPushButton#CancelBtn:hover {
    background-color: #DC2626;
}

QPushButton#ToggleEyeBtn {
    background-color: transparent;
    border: none;
    padding: 4px;
    font-size: 14px;
}

/* Stat Cards */
#StatCard {
    background-color: #0F172A;
    border: 1px solid #1E293B;
    border-radius: 10px;
    padding: 10px;
}

#StatTitle {
    color: #64748B;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
}

#StatValue {
    color: #F8FAFC;
    font-size: 14px;
    font-weight: 700;
}

/* Barra de progreso */
QProgressBar {
    border: 1px solid #1E293B;
    border-radius: 8px;
    text-align: center;
    background-color: #070A12;
    color: #F8FAFC;
    font-weight: bold;
    height: 22px;
}

QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #06B6D4, stop:1 #3B82F6);
    border-radius: 7px;
}

/* Indicador de Fortaleza de Contraseña */
#StrengthMeter {
    border-radius: 4px;
    height: 6px;
    background-color: #334155;
}

/* Consola de Logs */
QTextEdit {
    background-color: #05080E;
    border: 1px solid #1E293B;
    border-radius: 8px;
    color: #38BDF8;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    padding: 10px;
}

/* Radio buttons & Checkboxes */
QRadioButton, QCheckBox {
    spacing: 8px;
    font-size: 13px;
    font-weight: 500;
}

QRadioButton::indicator, QCheckBox::indicator {
    width: 18px;
    height: 18px;
}
"""
