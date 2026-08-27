import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.engine.compressor import CompressionWorker, compress_data, decompress_data
from src.utils.helpers import (MAX_ORIGINAL_SIZE, compute_crc32, pack_header,
                                read_header, sanitize_filename, unpack_header)


class TestFileCompressor(unittest.TestCase):
    def test_header_roundtrip(self):
        packed, _, _ = pack_header("documento.txt", 2048, 0x12345678)
        filename, size, crc, offset, is_enc, key = unpack_header(packed)
        self.assertEqual((filename, size, crc, is_enc), ("documento.txt", 2048, 0x12345678, False))
        self.assertEqual(offset, len(packed))

    def test_header_password_protection(self):
        packed, key, _ = pack_header("secreto.pdf", 4096, 0x98765432, password="MiClaveSegura123")
        filename, size, crc, offset, is_enc, dec_key = unpack_header(packed, password="MiClaveSegura123")
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

        # Intentar descifrar con clave errónea debe fallar
        with self.assertRaises(ValueError):
            decompress_data(compressed, password="ClaveIncorrecta!")

    def test_worker_compression_and_decompression_with_password(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, "secreto.txt")
            compressed_file = os.path.join(tmpdir, "secreto.txt.ndac")
            restored_file = os.path.join(tmpdir, "restaurado.txt")
            password = "SuperPassword2026"

            content = b"Datos protegidos por compresion NDC4 con 1-Pass I/O.\n" * 1500
            with open(input_file, "wb") as f:
                f.write(content)

            # Compresión worker cifrada
            worker_c = CompressionWorker("compress", input_file, compressed_file, password=password)
            worker_c.run()
            self.assertTrue(os.path.isfile(compressed_file))

            # Verificar rechazo con clave errónea
            worker_err = CompressionWorker("decompress", compressed_file, restored_file, password="Wrong")
            worker_err.run()
            self.assertFalse(os.path.isfile(restored_file))

            # Descompresión worker con clave correcta
            worker_d = CompressionWorker("decompress", compressed_file, restored_file, password=password)
            worker_d.run()
            self.assertTrue(os.path.isfile(restored_file))

            with open(restored_file, "rb") as f:
                self.assertEqual(f.read(), content)


if __name__ == "__main__":
    unittest.main()


