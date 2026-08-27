import hashlib
import hmac
import os
import secrets
import struct
import sys
import tempfile
import time
import unittest
import zlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.engine import compress, decompress, compress_data, decompress_data
from src.utils.helpers import (
    HEADER_SIZE_V4, HEADER_SIZE_V5, MAGIC_HEADER_V3, MAGIC_HEADER_V4, MAGIC_HEADER_V5,
    compute_crc32, compute_hmac_tag, crypt_stream_chunk, derive_keys,
    pack_header, pack_header_v5, safe_extract_path, sanitize_filename,
    unpack_header
)



class TestRedTeamCrypto(unittest.TestCase):
    """
    Suite de Pruebas Ofensivas / Red Team Criptográfico para NDAC v1.5.0.
    Verifica resistencia ante manipulación de cabeceras, bit flipping,
    path traversal, degradación de formato, truncamiento y fuzzing del parser.
    """

    def setUp(self):
        self.password = "RedTeamPassword2026!"
        self.sample_data = b"Contenido confidencial de prueba para la auditoria ofensiva de NDAC."
        self.tmpdir = tempfile.TemporaryDirectory()
        self.src_file = os.path.join(self.tmpdir.name, "secret.txt")
        with open(self.src_file, "wb") as f:
            f.write(self.sample_data)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_header_tampering_matrix(self):
        """Ataque de modificación de cada campo de la cabecera NDC4."""
        output_ndac = os.path.join(self.tmpdir.name, "sample.ndac")
        compress(self.src_file, output_ndac, password=self.password)

        with open(output_ndac, "rb") as f:
            valid_bytes = f.read()

        # Matriz de campos y sus offsets en HEADER_FORMAT_V4 (>4sBB16sQIH32s - 68 bytes fijos + filename)
        tamper_cases = [
            ("magic", 0, b"XXXX"),
            ("version", 4, b"\x00"),
            ("is_encrypted", 5, b"\x00"),
            ("salt", 6, b"\xFF" * 16),
            ("original_size", 22, struct.pack(">Q", 999999)),
            ("crc32_checksum", 30, struct.pack(">I", 0xDEADBEEF)),
            ("filename_len", 34, struct.pack(">H", 100)),
            ("hmac_tag", 36, b"\x00" * 32),
        ]

        for field_name, offset, new_bytes in tamper_cases:
            tampered = bytearray(valid_bytes)
            tampered[offset:offset+len(new_bytes)] = new_bytes

            with self.assertRaises((ValueError, zlib.error), msg=f"Campo {field_name} modificado no fue rechazado"):
                decompress_data(bytes(tampered), password=self.password)

    def test_02_filename_unauthenticated_metadata_finding(self):
        """
        Ataque a la cabecera NDC4: Modificar el campo filename_bytes.
        Demuestra que filename_bytes no está incluido dentro de compute_hmac_tag.
        """
        original_file = os.path.join(self.tmpdir.name, "doc_original.txt")
        with open(original_file, "wb") as f:
            f.write(b"Datos del archivo original para prueba de metadatos.")

        ndac_file = os.path.join(self.tmpdir.name, "doc_original.ndac")
        compress(original_file, ndac_file, password=self.password)

        with open(ndac_file, "rb") as f:
            data = bytearray(f.read())

        # En NDC4, filename_bytes comienza tras los 68 bytes fijos
        # Cambiamos "doc_original.txt" (16 bytes) por "doc_alterado.txt" (16 bytes)
        old_name = b"doc_original.txt"
        new_name = b"doc_alterado.txt"
        idx = data.find(old_name)
        self.assertGreater(idx, 0, "No se encontro el nombre de archivo en la cabecera")

        data[idx:idx+len(new_name)] = new_name

        # El unpack_header debe pasar sin error de HMAC porque filename no esta en el HMAC digest
        header_info = unpack_header(bytes(data), password=self.password)
        restored_name = header_info[0]

        # Se confirma que el nombre retornado es el alterado, demostrando que filename es metadato no firmado por HMAC
        self.assertEqual(restored_name, "doc_alterado.txt")

    def test_03_bit_flipping_ciphertext_rejection(self):
        """Ataque de bit flipping en el payload cifrado (Compress-then-Encrypt)."""
        compressed = compress_data(self.sample_data, password=self.password)
        header_size = 68 + len("data.bin")

        for offset in range(header_size, len(compressed), max(1, (len(compressed) - header_size) // 10)):
            tampered = bytearray(compressed)
            tampered[offset] ^= 0x01  # Invertir 1 bit

            with self.assertRaises((ValueError, zlib.error), msg=f"Bit flip en offset {offset} no provoco rechazo"):
                decompress_data(bytes(tampered), password=self.password)

    def test_04_malleability_and_crc32_tamper_rejection(self):
        """Intentar modificar ciphertext + CRC32 para probar maleabilidad del cifrado."""
        compressed = bytearray(compress_data(self.sample_data, password=self.password))

        # Modificar CRC32 (offset 30 a 34 en NDC4)
        compressed[30:34] = struct.pack(">I", 0x12345678)

        # Cualquier intento de alterar el CRC32 o HMAC debe ser rechazado inmediatamente en unpack_header
        with self.assertRaises(ValueError):
            decompress_data(bytes(compressed), password=self.password)

    def test_05_keystream_independence_between_files(self):
        """Verificar matemáticamente que dos archivos cifrados con la misma clave usen keystreams independientes."""
        data_a = b"A" * 500
        data_b = b"A" * 500

        c_a = compress_data(data_a, password=self.password)
        c_b = compress_data(data_b, password=self.password)

        header_len = 68 + len("data.bin")
        payload_a = c_a[header_len:]
        payload_b = c_b[header_len:]

        # XOR entre los dos ciphertexts
        xor_result = bytes(a ^ b for a, b in zip(payload_a, payload_b))

        # Si el keystream se reutilizara, xor_result seria puro 0x00. Verificamos que sea totalmente pseudo-aleatorio.
        zero_count = xor_result.count(0x00)
        self.assertLess(zero_count, len(xor_result) * 0.1, "Se detecto alta correlacion/reutilización de keystream")

    def test_06_counter_wraparound_safety(self):
        """Verificar la función crypt_stream_chunk ante valores límite del contador blk_idx."""
        key = secrets.token_bytes(32)
        data = b"Test" * 16

        # Posiciones límite cercanas a 2^32 bytes
        pos_low = 0
        pos_high = 0x80000000 * 64

        res_low = crypt_stream_chunk(data, key, start_pos=pos_low)
        res_high = crypt_stream_chunk(data, key, start_pos=pos_high)

        self.assertNotEqual(res_low, res_high, "El contador genero el mismo keystream en la frontera de 2^31 bloques")

    def test_07_truncation_rejection_matrix(self):
        """Verificar que cualquier truncamiento del archivo sea rechazado."""
        compressed = compress_data(self.sample_data, password=self.password)

        truncations = [1, 5, 10, 30, len(compressed) // 2, len(compressed) - 1]
        for t in truncations:
            truncated_bytes = compressed[:-t]
            with self.assertRaises((ValueError, zlib.error), msg=f"Truncamiento de -{t} bytes no fue rechazado"):
                decompress_data(truncated_bytes, password=self.password)

    def test_08_format_downgrade_attacks(self):
        """Verificar resistencia ante ataques de degradación de formato (NDC5 -> NDC4 o NDC4 -> NDC3)."""
        compressed_ndc4 = compress_data(self.sample_data, password=self.password)

        # Intentar cambiar Magic NDC4 -> NDC3 (para forzar bypass de contraseña)
        downgraded = bytearray(compressed_ndc4)
        downgraded[0:4] = MAGIC_HEADER_V3
        downgraded[4] = 3

        with self.assertRaises((ValueError, zlib.error), msg="Degradación NDC4->NDC3 no fue rechazada"):
            decompress_data(bytes(downgraded), password=self.password)

    def test_09_advanced_path_traversal_vectors(self):
        """Prueba exhaustiva de vectores maliciosos de Path Traversal en safe_extract_path."""
        vectors = [
            "../../etc/passwd",
            "..\\..\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\malware.exe",
            "D:/backdoor.sh",
            "/var/root/.bashrc",
            "sub/dir/../../../../outside.txt",
            "....//....//evil.txt",
            "CON.txt",
            "PRN.png",
            "AUX",
            "NUL",
            "COM1.bat",
            "LPT1.sys",
        ]

        with tempfile.TemporaryDirectory() as dest:
            for vec in vectors:
                # Comprobar que o bien lanza ValueError o sanitiza completamente la ruta dentro de dest
                try:
                    target = safe_extract_path(dest, vec)
                    # Si retornó una ruta, debe estar estrictamente dentro del destino
                    dest_abs = os.path.abspath(dest)
                    self.assertTrue(
                        target == dest_abs or target.startswith(dest_abs + os.sep),
                        f"Vectores {vec} escapo del directorio destino: {target}"
                    )
                except ValueError:
                    pass  # Bloqueado exitosamente por excepción

    def test_10_parser_fuzzing_and_boundary_safety(self):
        """Fuzzing básico del parser unpack_header con bytes aleatorios y truncados."""
        for _ in range(100):
            fuzzy_bytes = secrets.token_bytes(secrets.randbelow(150))
            try:
                unpack_header(fuzzy_bytes, password="fuzz_password")
            except ValueError:
                pass  # Excepción esperada y controlada

    def test_11_pbkdf2_iteration_benchmarks(self):
        """Benchmark informativo de iteraciones PBKDF2."""
        salt = secrets.token_bytes(16)
        iterations_list = [100000, 250000]

        for iters in iterations_list:
            t0 = time.time()
            hashlib.pbkdf2_hmac("sha256", b"TestPassword", salt, iterations=iters, dklen=64)
            elapsed = time.time() - t0
            self.assertGreater(elapsed, 0.001)


if __name__ == "__main__":
    unittest.main()
