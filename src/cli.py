import argparse
import getpass
import os
import sys
from typing import List, Optional

from .engine import compress, decompress, validate_archive, get_archive_info
from .utils.helpers import format_file_size

VERSION = "2.0.0"

# Códigos de salida estándar
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_INVALID_FILE = 2
EXIT_WRONG_PASSWORD = 3
EXIT_CANCELLED = 4
EXIT_IO_ERROR = 5


def run_cli(args: List[str]) -> int:
    """
    Ejecuta el comando CLI indicado en args y retorna el código de salida entero.
    """
    parser = argparse.ArgumentParser(
        prog="ndac",
        description="NDAC — Compresor y Protector de Archivos Ultra (NDC6/NDC5/NDC4/NDC3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", "-v", action="version", version=f"NDAC versión {VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Comando a ejecutar")

    # 1. Subcomando compress
    p_comp = subparsers.add_parser("compress", aliases=["c"], help="Comprimir archivos o carpetas a .ndac")
    p_comp.add_argument("sources", nargs="+", help="Archivo(s) o carpeta(s) a comprimir")
    p_comp.add_argument("-o", "--output", help="Ruta del archivo de salida .ndac")
    p_comp.add_argument("-p", "--password", nargs="?", const="", help="Proteger con contrasena")
    p_comp.add_argument("-l", "--level", type=int, default=9, choices=range(1, 10), help="Nivel de compresion (1-9)")
    p_comp.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso (sin salida en consola)")

    # 2. Subcomando extract
    p_ext = subparsers.add_parser("extract", aliases=["x"], help="Descomprimir un archivo .ndac")
    p_ext.add_argument("source", help="Archivo .ndac a descomprimir")
    p_ext.add_argument("-o", "--output", help="Directorio o ruta de destino para extraer")
    p_ext.add_argument("-p", "--password", nargs="?", const="", help="Contrasena de descifrado")
    p_ext.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso")

    # 3. Subcomando validate
    p_val = subparsers.add_parser("validate", aliases=["v"], help="Validar la integridad de un archivo .ndac")
    p_val.add_argument("archive", help="Archivo .ndac a validar")
    p_val.add_argument("-p", "--password", nargs="?", const="", help="Contrasena si esta protegido")
    p_val.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso")

    # 4. Subcomando info
    p_inf = subparsers.add_parser("info", aliases=["i"], help="Mostrar metadatos de un archivo .ndac")
    p_inf.add_argument("archive", help="Archivo .ndac")
    p_inf.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso")

    try:
        parsed = parser.parse_args(args)
    except SystemExit as sys_exit:
        return EXIT_SUCCESS if sys_exit.code == 0 else EXIT_GENERAL_ERROR

    cmd = parsed.command
    if not cmd:
        parser.print_help()
        return EXIT_SUCCESS

    if cmd in ("compress", "c"):
        return _cli_compress(parsed)
    elif cmd in ("extract", "x"):
        return _cli_extract(parsed)
    elif cmd in ("validate", "v"):
        return _cli_validate(parsed)
    elif cmd in ("info", "i"):
        return _cli_info(parsed)

    return EXIT_GENERAL_ERROR


def _resolve_password(password_arg: Optional[str], quiet: bool) -> Optional[str]:
    if password_arg is None:
        return None
    if password_arg == "":
        if quiet:
            return ""
        return getpass.getpass("Introduce contrasena: ")
    return password_arg


def _cli_compress(parsed) -> int:
    quiet = parsed.quiet
    password = _resolve_password(parsed.password, quiet)

    sources = parsed.sources
    output_path = parsed.output

    if not output_path:
        first = sources[0]
        base_dir = os.path.dirname(first) or os.getcwd()
        default_name = (os.path.basename(first) if len(sources) == 1 else "conjunto_archivos") + ".ndac"
        output_path = os.path.join(base_dir, default_name)

    def progress_cb(percent, msg):
        if not quiet:
            sys.stdout.write(f"\rComprimiendo [{percent:3d}%]: {msg:<60}")
            sys.stdout.flush()

    try:
        res = compress(
            sources,
            output_path,
            password=password,
            compression_level=parsed.level,
            progress_callback=progress_cb if not quiet else None,
        )
        if not quiet:
            sys.stdout.write("\n")
            print(f"✓ Compresion completada exitosamente.")
            print(f"Formato: {res.get('format')} | Elementos: {res.get('file_count', 1)}")
            print(f"Original: {format_file_size(res['original_size'])} -> Comprimido: {format_file_size(res['compressed_size'])} ({res['reduction']:.1f}% reduccion)")
            print(f"Guardado en: {res['output_path']}")
        return EXIT_SUCCESS

    except FileNotFoundError as err:
        if not quiet:
            print(f"Error de E/S: {err}")
        return EXIT_IO_ERROR
    except InterruptedError:
        if not quiet:
            print("\nOperacion cancelada por el usuario.")
        return EXIT_CANCELLED
    except PermissionError as err:
        if not quiet:
            print(f"Error de permisos: {err}")
        return EXIT_IO_ERROR
    except ValueError as err:
        if not quiet:
            print(f"Error de validacion: {err}")
        return EXIT_INVALID_FILE
    except Exception as err:
        if not quiet:
            print(f"Error inesperado: {err}")
        return EXIT_GENERAL_ERROR


def _cli_extract(parsed) -> int:
    quiet = parsed.quiet
    archive = parsed.source

    if not os.path.isfile(archive):
        if not quiet:
            print(f"Error: No se encuentra el archivo comprimido '{archive}'.")
        return EXIT_INVALID_FILE

    output_dir = parsed.output or os.path.dirname(os.path.abspath(archive)) or "."
    password = _resolve_password(parsed.password, quiet)

    def progress_cb(percent, msg):
        if not quiet:
            sys.stdout.write(f"\rExtrayendo [{percent:3d}%]: {msg:<60}")
            sys.stdout.flush()

    try:
        res = decompress(
            archive,
            output_dir,
            password=password,
            progress_callback=progress_cb if not quiet else None,
        )
        if not quiet:
            sys.stdout.write("\n")
            print(f"✓ Extraccion completada exitosamente.")
            print(f"Formato: {res.get('format')} | Elementos restaurados: {res.get('file_count', 1)}")
            print(f"Destino: {res['output_path']}")
        return EXIT_SUCCESS

    except FileNotFoundError as err:
        if not quiet:
            print(f"Error de archivo no encontrado: {err}")
        return EXIT_INVALID_FILE
    except InterruptedError:
        if not quiet:
            print("\nOperacion cancelada por el usuario.")
        return EXIT_CANCELLED
    except ValueError as err:
        err_str = str(err)
        if "protegido con contrasena" in err_str or "Contrasena incorrecta" in err_str:
            if not quiet:
                print(f"Error de autenticacion: {err_str}")
            return EXIT_WRONG_PASSWORD
        else:
            if not quiet:
                print(f"Error de formato/integridad: {err_str}")
            return EXIT_INVALID_FILE
    except OSError as err:
        if not quiet:
            print(f"Error de E/S: {err}")
        return EXIT_IO_ERROR
    except Exception as err:
        if not quiet:
            print(f"Error general: {err}")
        return EXIT_GENERAL_ERROR


def _cli_validate(parsed) -> int:
    quiet = parsed.quiet
    archive = parsed.archive
    password = _resolve_password(parsed.password, quiet)

    res = validate_archive(archive, password=password)

    if res.get("valid"):
        if not quiet:
            print(f"✓ Archivo valido: {archive}")
            print(f"Formato: {res.get('format')} | Elementos: {res.get('file_count')}")
            print(f"Original: {format_file_size(res.get('original_size', 0))} | Comprimido: {format_file_size(res.get('compressed_size', 0))}")
            print(f"Integridad CRC32: OK | Cifrado: {'Si' if res.get('is_encrypted') else 'No'}")
        return EXIT_SUCCESS
    else:
        err = res.get("error", "Archivo corrupto")
        if not quiet:
            print(f"✗ Archivo invalido o corrupto: {archive}")
            print(f"Motivo: {err}")
        if "contrasena" in str(err).lower() or "password" in str(err).lower():
            return EXIT_WRONG_PASSWORD
        return EXIT_INVALID_FILE


def _cli_info(parsed) -> int:
    quiet = parsed.quiet
    archive = parsed.archive

    try:
        info = get_archive_info(archive)
        if not quiet:
            print(f"Informacion NDAC ({os.path.basename(archive)})")
            print(f"Formato: {info.get('format')} (Version {info.get('version')})")
            print(f"Nombre raiz: {info.get('filename')}")
            print(f"Cantidad de elementos: {info.get('file_count')}")
            print(f"Tamano original: {format_file_size(info.get('original_size', 0))}")
            print(f"Tamano comprimido: {format_file_size(info.get('compressed_size', 0))}")
            print(f"Reduccion: {info.get('reduction_percent', 0):.1f}%")
            print(f"Compresion: {info.get('compression_algorithm')}")
            print(f"Cifrado: {'Si' if info.get('is_encrypted') else 'No'}")
            print(f"CRC32 Checksum: {info.get('crc32_checksum')}")
        return EXIT_SUCCESS
    except Exception as err:
        if not quiet:
            print(f"Error al leer metadatos: {err}")
        return EXIT_INVALID_FILE
