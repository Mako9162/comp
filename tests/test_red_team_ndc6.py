import os
import shutil
import tempfile
import unittest
import secrets

from src.formats.ndc6 import compress_ndc6, decompress_ndc6
from src.formats.ndc6.header import unpack_header_v6


class TestRedTeamNDC6(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="rt_ndc6_")
        self.output_dir = tempfile.mkdtemp(prefix="rt_ndc6_out_")
        self.archive_path = os.path.join(self.test_dir, "target.ndac")
        self.password = "RedTeam_Pass_2026!"

        self.sample_file = os.path.join(self.test_dir, "data.txt")
        with open(self.sample_file, "wb") as f:
            f.write(b"Informacion critica protegida por NDC6 " * 200)

        compress_ndc6(self.sample_file, self.archive_path, password=self.password)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        shutil.rmtree(self.output_dir, ignore_errors=True)

    def test_01_header_bit_flipping_rejection(self):
        """Demostrar que cualquier alteración en la cabecera fija o AAD de NDC6 se rechaza."""
        with open(self.archive_path, "rb") as f:
            raw_data = bytearray(f.read())

        # Bit flip en el campo de versión o flags de cabecera AAD
        raw_data[5] ^= 0xFF

        bad_archive = os.path.join(self.test_dir, "bad_header.ndac")
        with open(bad_archive, "wb") as f:
            f.write(raw_data)

        with self.assertRaises(ValueError):
            decompress_ndc6(bad_archive, self.output_dir, password=self.password)

    def test_02_chunk_truncation_rejection(self):
        """Demostrar rechazo atómico ante truncamiento del archivo contenedor."""
        with open(self.archive_path, "rb") as f:
            raw_data = f.read()

        # Truncar los últimos 20 bytes
        truncated_data = raw_data[:-20]
        bad_archive = os.path.join(self.test_dir, "truncated.ndac")
        with open(bad_archive, "wb") as f:
            f.write(truncated_data)

        with self.assertRaises(ValueError):
            decompress_ndc6(bad_archive, self.output_dir, password=self.password)

    def test_03_fuzzing_ndc6_header_parser(self):
        """Fuzzing de 1,000 iteraciones aleatorias sobre el parser unpack_header_v6."""
        crashes = 0
        for _ in range(1000):
            fuzz_bytes = secrets.token_bytes(secrets.randbelow(120))
            try:
                unpack_header_v6(fuzz_bytes)
            except ValueError:
                pass
            except Exception as exc:
                crashes += 1

        self.assertEqual(crashes, 0, f"Se detectaron unhandled exceptions o crashes en parser NDC6: {crashes}")


if __name__ == "__main__":
    unittest.main()
