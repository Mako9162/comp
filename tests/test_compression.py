import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.engine import (CompressionWorker, compress, decompress, validate_archive,
                        get_archive_info, compress_data, decompress_data)
from src.utils.helpers import (MAX_ORIGINAL_SIZE, compute_crc32, pack_header,
                                safe_extract_path, sanitize_filename, unpack_header)


class TestFileCompressor(unittest.TestCase):
    def test_header_roundtrip(self):
        packed, _, _ = pack_header("documento.txt", 2048, 0x12345678)
        filename, size, crc, offset, is_enc, key, ver, fcount = unpack_header(packed)
        self.assertEqual((filename, size, crc, is_enc, ver, fcount), ("documento.txt", 2048, 0x12345678, False, 4, 1))
        self.assertEqual(offset, len(packed))

    def test_header_password_protection(self):
        packed, key, _ = pack_header("secreto.pdf", 4096, 0x98765432, password="MiClaveSegura123")
        filename, size, crc, offset, is_enc, dec_key, ver, fcount = unpack_header(packed, password="MiClaveSegura123")
        self.assertEqual((filename, size, crc, is_enc), ("secreto.pdf", 4096, 0x98765432, True))
        self.assertEqual(key, dec_key)

        with self.assertRaises(ValueError):
            unpack_header(packed, password="ClaveIncorrecta")

    def test_sanitize_filename_prevents_path_traversal(self):
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("C:\\Windows\\System32\\cmd.exe"), "cmd.exe")
        self.assertEqual(sanitize_filename("..\\..\\malicious.sh"), "malicious.sh")
        self.assertEqual(sanitize_filename("..."), "archivo_restaurado")
        self.assertEqual(sanitize_filename(""), "archivo_restaurado")

    def test_safe_extract_path_blocks_path_traversal(self):
        with tempfile.TemporaryDirectory() as dest_dir:
            # Rutas válidas
            safe_target = safe_extract_path(dest_dir, "subfolder/doc.txt")
            self.assertTrue(safe_target.startswith(os.path.abspath(dest_dir)))

            # Intentos de Path Traversal
            with self.assertRaises(ValueError):
                safe_extract_path(dest_dir, "../../etc/passwd")

            with self.assertRaises(ValueError):
                safe_extract_path(dest_dir, "..\\..\\windows\\system32\\cmd.exe")

            with self.assertRaises(ValueError):
                safe_extract_path(dest_dir, "/etc/shadow")

    def test_rejects_invalid_or_unsafe_header(self):
        with self.assertRaises(ValueError):
            unpack_header(b"NDC2" + b"\0" * 64)
        with self.assertRaises(ValueError):
            pack_header("test.bin", MAX_ORIGINAL_SIZE + 1, 0)

    def test_lossless_roundtrip_with_password(self):
        original = (b"texto confidencial repetido para comprobar cifrado NDC4\n" * 300)
        password = "ClaveDePrueba456!"

        compressed = compress_data(original, password=password)
        restored = decompress_data(compressed, password=password)
        self.assertEqual(restored, original)
        self.assertEqual(compute_crc32(restored), compute_crc32(original))

        with self.assertRaises(ValueError):
            decompress_data(compressed, password="ClaveIncorrecta!")

    def test_pure_compress_and_decompress_api_single_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, "datos.csv")
            compressed_file = os.path.join(tmpdir, "datos.csv.ndac")
            restored_file = os.path.join(tmpdir, "datos_restaurados.csv")
            content = b"col1,col2,col3\n" + b"value1,value2,value3\n" * 5000

            with open(input_file, "wb") as f:
                f.write(content)

            c_res = compress(input_file, compressed_file, password="Password123", compression_level=6)
            self.assertTrue(os.path.isfile(compressed_file))
            self.assertEqual(c_res["format"], "NDC4")
            self.assertTrue(c_res["is_encrypted"])

            d_res = decompress(compressed_file, restored_file, password="Password123")
            self.assertTrue(os.path.isfile(restored_file))
            with open(restored_file, "rb") as f:
                self.assertEqual(f.read(), content)

    def test_directory_compression_and_decompression_ndc5(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            proj_dir = os.path.join(tmpdir, "MiProyecto")
            sub_dir = os.path.join(proj_dir, "src", "modules")
            empty_dir = os.path.join(proj_dir, "vacio")
            os.makedirs(sub_dir, exist_ok=True)
            os.makedirs(empty_dir, exist_ok=True)

            f1 = os.path.join(proj_dir, "README.md")
            f2 = os.path.join(sub_dir, "main.py")

            with open(f1, "wb") as f:
                f.write(b"# Documentacion del Proyecto\n" * 200)
            with open(f2, "wb") as f:
                f.write(b"print('Hola Mundo')\n" * 300)

            compressed_archive = os.path.join(tmpdir, "MiProyecto.ndac")
            dest_dir = os.path.join(tmpdir, "Restaurado")

            # 1. Comprimir directorio completo a NDC5
            c_res = compress(proj_dir, compressed_archive, password="SecretFolderPass99")
            self.assertTrue(os.path.isfile(compressed_archive))
            self.assertEqual(c_res["format"], "NDC5")
            self.assertEqual(c_res["file_count"], 5)  # 2 archivos + 3 carpetas (src, src/modules y vacio)

            # 2. Verificar información del archivo
            info = get_archive_info(compressed_archive)
            self.assertEqual(info["format"], "NDC5")
            self.assertEqual(info["filename"], "MiProyecto")
            self.assertEqual(info["file_count"], 5)

            # 3. Validar archivo comprimido
            v_res = validate_archive(compressed_archive, password="SecretFolderPass99")
            self.assertTrue(v_res["valid"])
            self.assertEqual(v_res["file_count"], 5)

            # 4. Descomprimir a carpeta de destino
            d_res = decompress(compressed_archive, dest_dir, password="SecretFolderPass99")
            self.assertTrue(os.path.isdir(dest_dir))
            self.assertEqual(d_res["format"], "NDC5")

            # 5. Verificar que se restauró la estructura exacta
            res_f1 = os.path.join(dest_dir, "README.md")
            res_f2 = os.path.join(dest_dir, "src", "modules", "main.py")
            res_empty = os.path.join(dest_dir, "vacio")

            self.assertTrue(os.path.isfile(res_f1))
            self.assertTrue(os.path.isfile(res_f2))
            self.assertTrue(os.path.isdir(res_empty))

            with open(res_f1, "rb") as f:
                self.assertEqual(f.read(), b"# Documentacion del Proyecto\n" * 200)
            with open(res_f2, "rb") as f:
                self.assertEqual(f.read(), b"print('Hola Mundo')\n" * 300)

    def test_multi_file_compression_ndc5(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f1 = os.path.join(tmpdir, "doc1.txt")
            f2 = os.path.join(tmpdir, "doc2.txt")
            compressed_archive = os.path.join(tmpdir, "paquete.ndac")
            dest_dir = os.path.join(tmpdir, "extraido")

            with open(f1, "wb") as f:
                f.write(b"Contenido del documento 1\n" * 100)
            with open(f2, "wb") as f:
                f.write(b"Contenido del documento 2\n" * 100)

            c_res = compress([f1, f2], compressed_archive)
            self.assertEqual(c_res["format"], "NDC5")
            self.assertEqual(c_res["file_count"], 2)

            decompress(compressed_archive, dest_dir)
            self.assertTrue(os.path.isfile(os.path.join(dest_dir, "doc1.txt")))
            self.assertTrue(os.path.isfile(os.path.join(dest_dir, "doc2.txt")))

    def test_cancellation_cleans_temporary_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, "big.dat")
            compressed_file = os.path.join(tmpdir, "big.dat.ndac")
            content = b"X" * (2 * 1024 * 1024)

            with open(input_file, "wb") as f:
                f.write(content)

            cancel_requested = False

            def progress_cb(percent, msg):
                nonlocal cancel_requested
                if percent >= 10:
                    cancel_requested = True

            def cancel_cb():
                return cancel_requested

            with self.assertRaises(InterruptedError):
                compress(input_file, compressed_file, progress_callback=progress_cb, cancel_callback=cancel_cb)

            self.assertFalse(os.path.exists(compressed_file))
            partials = [f for f in os.listdir(tmpdir) if f.endswith(".partial")]
            self.assertEqual(len(partials), 0)


if __name__ == "__main__":
    unittest.main()
