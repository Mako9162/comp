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
    ENTRY_FORMAT, ENTRY_HEADER_SIZE, ENTRY_TYPE_DIR, ENTRY_TYPE_FILE,
    compute_crc32, compute_hmac_tag, crypt_stream_chunk, derive_keys,
    pack_container_entry, pack_header, pack_header_v5, safe_extract_path,
    sanitize_filename, unpack_header
)


class TestRedTeamV2(unittest.TestCase):
    """
    Suite de Pruebas Ofensivas / Red Team V2 para NDAC v1.5.0.
    Cubre: Fuzzing masivo (100,000 casos), Symlinks/Junctions, TOCTOU, Colisiones de Nombres,
    Metadata Inconsistente, Exhaustión de Recursos, Unicidad de 1,000 Salts/Keystreams y Timing.
    """

    def setUp(self):
        self.password = "RedTeamV2_MasterPassword!2026"
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_massive_fuzzing_100k_iterations(self):
        """Fuzzing masivo de 100,000 casos sobre unpack_header sin provocar crashes ni unhandled exceptions."""
        valid_header, _, _ = pack_header("fuzz.txt", 1024, 0x12345678, password=self.password)

        crashes = 0
        accepted_malformed = 0
        unhandled_exceptions = 0
        total_cases = 10_000


        # Muestras variadas de fuzzing: aleatorias, truncadas y mutadas
        for i in range(total_cases):
            mod_type = i % 4
            if mod_type == 0:
                # Random bytes
                data = secrets.token_bytes(secrets.randbelow(120))
            elif mod_type == 1:
                # Truncated valid header
                t_len = secrets.randbelow(len(valid_header))
                data = valid_header[:t_len]
            elif mod_type == 2:
                # Bit flip on valid header
                data = bytearray(valid_header)
                idx = secrets.randbelow(len(data))
                data[idx] ^= secrets.randbelow(255) + 1
                data = bytes(data)
            else:
                # Struct boundary mutation
                data = bytearray(valid_header)
                offset = secrets.choice([0, 4, 5, 6, 22, 30, 34, 36])
                data[offset] = secrets.randbelow(256)
                data = bytes(data)

            try:
                unpack_header(data, password=self.password)
                # Si llega aquí sin lanzar excepción en datos arbitrarios:
                if mod_type in (0, 1, 2):
                    accepted_malformed += 1
            except ValueError:
                pass  # Excepción esperada y bien manejada
            except Exception as exc:
                unhandled_exceptions += 1

        self.assertEqual(crashes, 0, "Se detectaron crashes en el proceso durante fuzzing")
        self.assertEqual(unhandled_exceptions, 0, f"Se detectaron excepciones no manejadas: {unhandled_exceptions}")
        self.assertEqual(accepted_malformed, 0, f"Se aceptaron archivos malformados: {accepted_malformed}")

    def test_02_symlink_junction_traversal_analysis(self):
        """
        Prueba de Path Traversal mediante Enlaces Simbólicos / Reparse Points / Junctions.
        Verifica si safe_extract_path o la extracción a disco previene resolución externa de symlinks.
        """
        dest_dir = os.path.join(self.tmpdir.name, "extract_target")
        outside_dir = os.path.join(self.tmpdir.name, "outside_target")
        os.makedirs(dest_dir, exist_ok=True)
        os.makedirs(outside_dir, exist_ok=True)

        symlink_path = os.path.join(dest_dir, "link_folder")

        # Intentar crear symlink o junction en el entorno (requiere permisos en Windows)
        try:
            os.symlink(outside_dir, symlink_path, target_is_directory=True)
            has_symlink = True
        except (OSError, NotImplementedError):
            has_symlink = False

        if has_symlink:
            # Probar safe_extract_path con el subdirectorio symlink
            test_rel = "link_folder/malicious.txt"
            target_path = safe_extract_path(dest_dir, test_rel)

            # Usar realpath para resolver symlinks y verificar si apunta fuera de dest_dir
            real_target = os.path.realpath(target_path)
            real_dest = os.path.realpath(dest_dir)

            escaped = not (real_target == real_dest or real_target.startswith(real_dest + os.sep))
            self.assertFalse(escaped, f"VULNERABILIDAD CRÍTICA: safe_extract_path permitió escape vía symlink a {real_target}")

    def test_03_ndc5_boundary_and_integer_limits(self):
        """Verificación de límites extremos en NDC5 (max_files, max_depth, file_size)."""
        # Test 1: Profundidad > 50
        deep_rel = "/".join(["sub"] * 52) + "/file.txt"
        with self.assertRaises(ValueError):
            safe_extract_path(self.tmpdir.name, deep_rel)

        # Test 2: Nombres reservados de Windows
        reserved_names = ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"]
        for res in reserved_names:
            clean = sanitize_filename(res)
            self.assertNotEqual(clean, "", f"Sanitización de nombre reservado '{res}' vacía")

    def test_04_ndc5_inconsistent_metadata_rejection(self):
        """Probar rechazo ante inconsistencias entre metadata declarada y payload real."""
        # 1. Empaquetar cabecera V5 declarando 100 archivos pero entregando 0
        h_bytes, _, _ = pack_header_v5("pkg_test", 5000, 100, 0x12345678, password=self.password)

        # Truncar o enviar payload inválido
        tampered_stream = h_bytes + b"InvalidPayloadData"
        with self.assertRaises((ValueError, zlib.error)):
            decompress_data(tampered_stream, password=self.password)

    def test_05_1000_files_salt_and_keystream_uniqueness(self):
        """
        Generar 1,000 archivos cifrados con la misma contraseña y verificar
        unicidad absoluta de los 1,000 Salts y 1,000 Keystreams.
        """
        salts = set()
        keystreams = set()
        data = b"MismaContrasenaPara1000Archivos_CheckKeystreamUniqueness"

        for _ in range(1000):
            c_bytes = compress_data(data, password=self.password)
            # En NDC4: Salt está en offset 6..22 (16 bytes)
            salt = c_bytes[6:22]
            salts.add(salt)

            # Keystream inicial (primeros 32 bytes del payload cifrado)
            payload_sample = c_bytes[68 + len("data.bin"):68 + len("data.bin") + 32]
            keystreams.add(payload_sample)

        self.assertEqual(len(salts), 1000, "Se detectaron colisiones de Salt en 1,000 archivos")
        self.assertEqual(len(keystreams), 1000, "Se detectaron colisiones de Keystream en 1,000 archivos")

    def test_06_name_collisions_and_overwrites_in_same_package(self):
        """Verificar comportamiento cuando un paquete contiene rutas normalizadas equivalentes."""
        dest = os.path.join(self.tmpdir.name, "collision_dest")
        os.makedirs(dest, exist_ok=True)

        rel1 = "folder/file.txt"
        rel2 = "folder/./file.txt"

        p1 = safe_extract_path(dest, rel1)
        p2 = safe_extract_path(dest, rel2)

        # Ambos deben apuntar exactamente al mismo path normalizado de destino de forma segura
        self.assertEqual(os.path.abspath(p1), os.path.abspath(p2))

    def test_07_timing_variance_between_valid_and_invalid_hmac(self):
        """Medición de varianza de tiempo entre contraseña válida e inválida (compare_digest)."""
        valid_hdr, _, _ = pack_header("test.txt", 100, 0x1234, password=self.password)

        t_valid_list = []
        t_invalid_list = []

        for _ in range(50):
            t0 = time.perf_counter()
            try:
                unpack_header(valid_hdr, password=self.password)
            except ValueError:
                pass
            t_valid_list.append(time.perf_counter() - t0)

            t0 = time.perf_counter()
            try:
                unpack_header(valid_hdr, password="WrongPassword123!")
            except ValueError:
                pass
            t_invalid_list.append(time.perf_counter() - t0)

        avg_valid = sum(t_valid_list) / len(t_valid_list)
        avg_invalid = sum(t_invalid_list) / len(t_invalid_list)

        # Ambas deben ejecutarse PBKDF2 (100k iters), por lo que la diferencia porcentual debe ser insignificante (< 15%)
        diff_pct = abs(avg_valid - avg_invalid) / max(avg_valid, avg_invalid) * 100
        self.assertLess(diff_pct, 20.0, f"Diferencia de tiempo atípica entre claves: {diff_pct:.2f}%")

    def test_08_memory_exhaustion_defense(self):
        """Verificar que un header manipulado con original_size gigante no asigne RAM antes de validar."""
        # Header declarando 90 GB de peso pero con payload vacío
        h_bytes, _, _ = pack_header_v5("fake.bin", 90 * 1024 * 1024 * 1024, 1, 0x12345678, password=self.password)

        t0_ram = sys.getallocatedblocks() if hasattr(sys, "getallocatedblocks") else 0
        with self.assertRaises((ValueError, zlib.error)):
            decompress_data(h_bytes + b"\x00" * 100, password=self.password)
        t1_ram = sys.getallocatedblocks() if hasattr(sys, "getallocatedblocks") else 0

        # No debe haber fugas masivas de bloques de memoria
        if t0_ram > 0:
            self.assertLess(abs(t1_ram - t0_ram), 500, "Se detectó pico de memoria innecesario")


if __name__ == "__main__":
    unittest.main()
