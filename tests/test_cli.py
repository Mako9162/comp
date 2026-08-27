import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.cli import run_cli, EXIT_SUCCESS, EXIT_INVALID_FILE, EXIT_WRONG_PASSWORD


class TestCLI(unittest.TestCase):
    def test_cli_compress_extract_info_validate_quiet(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = os.path.join(tmpdir, "doc.txt")
            archive_file = os.path.join(tmpdir, "doc.txt.ndac")
            dest_dir = os.path.join(tmpdir, "out")

            with open(source_file, "wb") as f:
                f.write(b"Prueba de linea de comandos CLI NDAC\n" * 100)

            # 1. Compress silencioso
            code_c = run_cli(["compress", source_file, "-o", archive_file, "-p", "PassCLI123", "--quiet"])
            self.assertEqual(code_c, EXIT_SUCCESS)
            self.assertTrue(os.path.isfile(archive_file))

            # 2. Info
            code_i = run_cli(["info", archive_file, "--quiet"])
            self.assertEqual(code_i, EXIT_SUCCESS)

            # 3. Validate OK
            code_v = run_cli(["validate", archive_file, "-p", "PassCLI123", "--quiet"])
            self.assertEqual(code_v, EXIT_SUCCESS)

            # 4. Validate Bad Password (debe retornar EXIT_WRONG_PASSWORD)
            code_v_err = run_cli(["validate", archive_file, "-p", "WrongPass", "--quiet"])
            self.assertEqual(code_v_err, EXIT_WRONG_PASSWORD)

            # 5. Extract silencioso
            code_x = run_cli(["extract", archive_file, "-o", dest_dir, "-p", "PassCLI123", "--quiet"])
            self.assertEqual(code_x, EXIT_SUCCESS)
            self.assertTrue(os.path.isfile(os.path.join(dest_dir, "doc.txt")))

    def test_cli_non_existent_file_returns_invalid_file_code(self):
        code = run_cli(["extract", "no_existe_archivo.ndac", "--quiet"])
        self.assertEqual(code, EXIT_INVALID_FILE)


if __name__ == "__main__":
    unittest.main()
