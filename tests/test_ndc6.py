import os
import shutil
import tempfile
import unittest
import hashlib

from src.formats.ndc6 import compress_ndc6, decompress_ndc6, validate_ndc6


class TestNDC6Engine(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ndc6_test_")
        self.output_dir = tempfile.mkdtemp(prefix="ndc6_out_")
        self.archive_path = os.path.join(self.test_dir, "test_package.ndac")
        self.password = "Secr3t_P@ssw0rd_NDC6!"

        # Crear archivo de prueba
        self.file1 = os.path.join(self.test_dir, "sample.txt")
        with open(self.file1, "wb") as f:
            f.write(b"NDAC v2.0 NDC6 Test Content " * 500)

        # Crear subdirectorio con archivo
        self.sub_dir = os.path.join(self.test_dir, "subdir")
        os.makedirs(self.sub_dir, exist_ok=True)
        self.file2 = os.path.join(self.sub_dir, "image_data.bin")
        with open(self.file2, "wb") as f:
            f.write(os.urandom(1024 * 1024 * 2))  # 2 MB de datos aleatorios

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        shutil.rmtree(self.output_dir, ignore_errors=True)

    def test_01_compress_and_decompress_roundtrip(self):
        """Compresión y descompresión completa roundtrip en formato NDC6."""
        res_comp = compress_ndc6(
            sources=[self.file1, self.sub_dir],
            output_archive=self.archive_path,
            password=self.password
        )
        self.assertEqual(res_comp["format"], "NDC6")
        self.assertTrue(os.path.exists(self.archive_path))

        # Validar archivo sin escribir a disco
        self.assertTrue(validate_ndc6(self.archive_path, password=self.password))

        # Extracción
        res_decomp = decompress_ndc6(
            archive_path=self.archive_path,
            output_dir=self.output_dir,
            password=self.password
        )
        self.assertEqual(res_decomp["format"], "NDC6")

        # Comprobar digest SHA256 del archivo restaurado
        restored_file1 = os.path.join(self.output_dir, "sample.txt")
        self.assertTrue(os.path.exists(restored_file1))
        with open(self.file1, "rb") as f_orig:
            h_orig = hashlib.sha256(f_orig.read()).hexdigest()
        with open(restored_file1, "rb") as f_rest:
            h_rest = hashlib.sha256(f_rest.read()).hexdigest()
        self.assertEqual(h_orig, h_rest)

    def test_02_wrong_password_rejection(self):
        """Rechazo inmediato si la contraseña es incorrecta."""
        compress_ndc6(
            sources=self.file1,
            output_archive=self.archive_path,
            password=self.password
        )
        with self.assertRaises(ValueError):
            decompress_ndc6(
                archive_path=self.archive_path,
                output_dir=self.output_dir,
                password="WrongPassword123"
            )


if __name__ == "__main__":
    unittest.main()
