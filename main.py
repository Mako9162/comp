import sys

from src.cli import run_cli

CLI_SUBCOMMANDS = {"compress", "c", "extract", "x", "validate", "v", "info", "i", "--help", "-h", "--version", "-v"}


def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() in CLI_SUBCOMMANDS:
        exit_code = run_cli(sys.argv[1:])
        sys.exit(exit_code)

    # Modo GUI (interfaz gráfica)
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication
    from src.gui.main_window import MainWindow

    if hasattr(Qt, "HighDpiScaleFactorRoundingPolicy"):
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )
    app = QApplication(sys.argv)
    app.setApplicationName("NDAC Compresor de Archivos")
    window = MainWindow()

    if len(sys.argv) > 1:
        window.handle_launch_args(sys.argv[1:])

    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
