import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.engine import compress, decompress, compress_data, decompress_data
from src.utils.helpers import safe_extract_path, pack_header, unpack_header


class TestSecurity(unittest.TestCase):
    def test_path_traversal_variations_blocked(self):
        with tempfile.TemporaryDirectory() as dest_dir:
            malicious_paths = [
                "../../etc/passwd",
                "..\\..\\Windows\\System32\\cmd.exe",
                "/etc/shadow",
                "\\System32\\config\\SAM",
                "C:\\evil.exe",
                "D:/backdoor.sh",
                "sub/dir/../../../../outside.txt",
            ]

            for path in malicious_paths:
                with self.assertRaises(ValueError, msg=f"No se bloqueo la ruta maliciosa: {path}"):
                    safe_extract_path(dest_dir, path)

    def test_excessive_path_depth_blocked(self):
        with tempfile.TemporaryDirectory() as dest_dir:
            deep_path = "/".join(["folder"] * 60) + "/file.txt"
            with self.assertRaises(ValueError):
                safe_extract_path(dest_dir, deep_path)

    def test_hmac_tampering_rejection(self):
        content = b"Datos confidenciales de prueba para verificacion HMAC."
        password = "MasterPassword2026!"

        compressed = compress_data(content, password=password)

        # 1. Tamper con byte en la cabecera (HMAC o Salt)
        tampered_bytes = bytearray(compressed)
        tampered_bytes[20] ^= 0xFF  # Alterar byte dentro del HMAC tag
        tampered_compressed = bytes(tampered_bytes)

        # Debe fallar al desempaquetar o descomprimir
        with self.assertRaises(ValueError):
            decompress_data(tampered_compressed, password=password)

    def test_corrupted_payload_rejection(self):
        content = b"Contenido importante protegido."
        password = "Password123"

        compressed = compress_data(content, password=password)
        header_len = 72  # Tamaño de cabecera NDC4

        # Alterar un byte dentro del payload comprimido cifrado
        tampered = bytearray(compressed)
        tampered[header_len + 5] ^= 0x55

        with self.assertRaises(ValueError):
            decompress_data(bytes(tampered), password=password)


if __name__ == "__main__":
    unittest.main()
