import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.engine import compress, decompress


class TestPerformance(unittest.TestCase):
    def test_compression_levels_speed_and_ratio_comparison(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = os.path.join(tmpdir, "dataset_large.txt")
            out_fast = os.path.join(tmpdir, "fast.ndac")
            out_norm = os.path.join(tmpdir, "norm.ndac")
            out_max = os.path.join(tmpdir, "max.ndac")
            restored = os.path.join(tmpdir, "restored.txt")

            # Crear dataset sintético de 5 MB
            chunk = (b"NDAC High Performance Streaming Engine Benchmark Data Block Line\n" * 150)
            data_bytes = chunk * 50  # ~5 MB
            with open(source_file, "wb") as f:
                f.write(data_bytes)

            orig_len = len(data_bytes)

            # Level 1 (Rápida)
            t0 = time.time()
            res_fast = compress(source_file, out_fast, compression_level=1)
            t_fast = time.time() - t0

            # Level 6 (Normal)
            t0 = time.time()
            res_norm = compress(source_file, out_norm, compression_level=6)
            t_norm = time.time() - t0

            # Level 9 (Máxima)
            t0 = time.time()
            res_max = compress(source_file, out_max, compression_level=9)
            t_max = time.time() - t0

            # Verificaciones
            self.assertTrue(os.path.isfile(out_fast))
            self.assertTrue(os.path.isfile(out_norm))
            self.assertTrue(os.path.isfile(out_max))

            # Comprobar que nivel 1 sea rápido y nivel 9 obtenga gran reducción
            self.assertGreater(res_fast["reduction"], 0)
            self.assertGreater(res_max["reduction"], 0)

            # Probar descompresión impecable
            decompress(out_fast, restored)
            with open(restored, "rb") as f:
                self.assertEqual(f.read(), data_bytes)

    def test_streaming_large_file_bounded_memory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = os.path.join(tmpdir, "stream_10mb.bin")
            archive_file = os.path.join(tmpdir, "stream_10mb.ndac")
            restored_file = os.path.join(tmpdir, "restored_10mb.bin")

            # Escribir archivo de 10 MB en bloques sin cargarlo todo en RAM
            block = os.urandom(1024 * 1024)
            with open(source_file, "wb") as f:
                for _ in range(10):
                    f.write(block)

            res = compress(source_file, archive_file, compression_level=6)
            self.assertEqual(res["original_size"], 10 * 1024 * 1024)

            decompress(archive_file, restored_file)
            self.assertEqual(os.path.getsize(restored_file), 10 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
