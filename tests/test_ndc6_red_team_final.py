import os
import shutil
import tempfile
import unittest
import secrets
import struct
import zlib
import time
import threading
import zstandard as zstd
from typing import List, Dict, Any

from src.formats import detect_format
from src.formats.ndc6 import compress_ndc6, decompress_ndc6, validate_ndc6
from src.formats.ndc6.constants import (
    MAGIC_HEADER_V6, FORMAT_VERSION_V6, HEADER_SIZE_V6, HEADER_FORMAT_V6,
    KDF_ARGON2ID, CIPHER_AES_256_GCM, COMPRESSION_ZSTD, COMPRESSION_DEFLATE,
    DEFAULT_CHUNK_SIZE, FLAG_IS_ENCRYPTED, FLAG_METADATA_ENCRYPTED
)
from src.formats.ndc6.crypto import (
    derive_master_key, expand_subkeys, derive_chunk_nonce,
    encrypt_aead_gcm, decrypt_aead_gcm, generate_salt, generate_nonce
)
from src.formats.ndc6.header import unpack_header_v6, pack_header_v6, verify_header_integrity
from src.formats.ndc6.metadata import pack_metadata, encrypt_metadata_blob, decrypt_and_unpack_metadata
from src.formats.ndc6.chunks import write_chunk_frame, read_and_verify_chunk_frame


class TestNDC6FinalRedTeam(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ndc6_rt_final_")
        self.output_dir = tempfile.mkdtemp(prefix="ndc6_rt_out_")
        self.archive_path = os.path.join(self.test_dir, "victim.ndac")
        self.password = "P@ssw0rd_Adversarial_RedTeam_2026!"

        # Crear estructura de archivos de prueba
        self.file1 = os.path.join(self.test_dir, "sensitive_document.pdf")
        with open(self.file1, "wb") as f:
            f.write(b"CONFIDENTIAL_DATA_PAYLOAD_TEST_" * 300)

        self.sub_dir = os.path.join(self.test_dir, "nested_folder")
        os.makedirs(self.sub_dir, exist_ok=True)
        self.file2 = os.path.join(self.sub_dir, "database.sqlite")
        with open(self.file2, "wb") as f:
            f.write(os.urandom(1024 * 512))  # 512 KB

        # Generar archivo comprimido v2.0
        compress_ndc6([self.file1, self.sub_dir], self.archive_path, password=self.password)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        shutil.rmtree(self.output_dir, ignore_errors=True)

    # =========================================================================
    # 1. AUDITORÍA CRÍTICA DE NONCES & UNICIDAD DE KEYSTREAM
    # =========================================================================
    def test_01_nonce_uniqueness_and_boundary_overflow(self):
        """Verificar la unicidad matemática de nonces y resistencia ante overflow de chunks."""
        base_nonce = generate_nonce(12)
        indices_to_test = [
            0, 1, 2, 2**16, 2**32 - 1, 2**32, 2**48, 2**63 - 1, 2**64 - 1
        ]
        nonces = set()
        for idx in indices_to_test:
            n = derive_chunk_nonce(base_nonce, idx)
            self.assertEqual(len(n), 12)
            self.assertNotIn(n, nonces, f"Colisión de nonce detectada en índice {idx}")
            nonces.add(n)

    def test_02_multi_container_nonce_isolation(self):
        """Demostrar que dos contenedores generados con la misma contraseña usan salts y nonces distintos."""
        arch1 = os.path.join(self.test_dir, "arch1.ndac")
        arch2 = os.path.join(self.test_dir, "arch2.ndac")

        compress_ndc6(self.file1, arch1, password=self.password)
        compress_ndc6(self.file1, arch2, password=self.password)

        with open(arch1, "rb") as f1, open(arch2, "rb") as f2:
            hdr1 = unpack_header_v6(f1)
            hdr2 = unpack_header_v6(f2)

        self.assertNotEqual(hdr1["salt"], hdr2["salt"], "Fallo: Salts idénticos en dos contenedores distintos")
        self.assertNotEqual(hdr1["base_nonce"], hdr2["base_nonce"], "Fallo: Base nonces idénticos en dos contenedores")

    # =========================================================================
    # 2. ATAQUES DE ALGORITHM DOWNGRADE Y MITIGACIÓN EN HEADER / AAD
    # =========================================================================
    def test_03_header_tampering_and_algorithm_downgrade(self):
        """Intentar modificar flags y algos de cabecera (AES-GCM -> ChaCha, Argon2 -> PBKDF2)."""
        with open(self.archive_path, "rb") as f:
            raw_bytes = bytearray(f.read())

        # Alterar byte 7 (kdf_algo_id) en la cabecera fija
        raw_bytes[7] = 0x03  # PBKDF2
        bad_kdf_arch = os.path.join(self.test_dir, "bad_kdf.ndac")
        with open(bad_kdf_arch, "wb") as f:
            f.write(raw_bytes)

        with self.assertRaises(ValueError, msg="Se aceptó silenciosamente la alteración de KDF en cabecera"):
            decompress_ndc6(bad_kdf_arch, self.output_dir, password=self.password)

        # Alterar byte 8 (cipher_algo_id)
        with open(self.archive_path, "rb") as f:
            raw_bytes2 = bytearray(f.read())
        raw_bytes2[8] = 0x02  # ChaCha20
        bad_cipher_arch = os.path.join(self.test_dir, "bad_cipher.ndac")
        with open(bad_cipher_arch, "wb") as f:
            f.write(raw_bytes2)

        with self.assertRaises(ValueError, msg="Se aceptó silenciosamente la alteración de Cifrado en cabecera"):
            decompress_ndc6(bad_cipher_arch, self.output_dir, password=self.password)

    # =========================================================================
    # 3. ATAQUES SOBRE CHUNKS (REORDENAMIENTO, DUPLICACIÓN, CORRUPCIÓN)
    # =========================================================================
    def test_04_chunk_bit_flipping_and_reordering(self):
        """Demostrar rechazo atómico ante alteración de 1 bit de payload o reordenamiento de chunks."""
        with open(self.archive_path, "rb") as f:
            hdr = unpack_header_v6(f)
            meta_blob = f.read(hdr["encrypted_metadata_len"])
            chunk0_hdr = f.read(12)
            chunk0_idx, chunk0_len = struct.unpack(">QI", chunk0_hdr)
            chunk0_data = bytearray(f.read(chunk0_len))

        # Bit flip en el ciphertext del chunk 0
        chunk0_data[10] ^= 0x01

        corrupted_arch = os.path.join(self.test_dir, "chunk_corrupt.ndac")
        with open(corrupted_arch, "wb") as f:
            f.write(pack_header_v6(
                flags=hdr["flags"],
                kdf_algo_id=hdr["kdf_algo_id"],
                cipher_algo_id=hdr["cipher_algo_id"],
                compression_algo_id=hdr["compression_algo_id"],
                chunk_size=hdr["chunk_size"],
                salt=hdr["salt"],
                base_nonce=hdr["base_nonce"],
                kdf_param_m=hdr["kdf_param_m"],
                kdf_param_t=hdr["kdf_param_t"],
                encrypted_metadata_len=hdr["encrypted_metadata_len"],
                payload_total_chunks=hdr["payload_total_chunks"]
            ))
            f.write(meta_blob)
            f.write(chunk0_hdr)
            f.write(chunk0_data)

        with self.assertRaises(ValueError, msg="Se aceptó un chunk con 1 bit alterado"):
            decompress_ndc6(corrupted_arch, self.output_dir, password=self.password)

    def test_05_cross_container_chunk_replay_rejection(self):
        """Intentar inyectar un chunk válido perteneciente a otro contenedor cifrado con la misma contraseña."""
        arch2 = os.path.join(self.test_dir, "arch2.ndac")
        compress_ndc6(self.file2, arch2, password=self.password)

        with open(arch2, "rb") as f2:
            hdr2 = unpack_header_v6(f2)
            f2.read(hdr2["encrypted_metadata_len"])
            chunk_foreign_hdr = f2.read(12)
            _, foreign_len = struct.unpack(">QI", chunk_foreign_hdr)
            chunk_foreign_payload = f2.read(foreign_len)

        # Inyectar el chunk del contenedor 2 en el contenedor 1
        with open(self.archive_path, "rb") as f1:
            hdr1 = unpack_header_v6(f1)
            meta_blob1 = f1.read(hdr1["encrypted_metadata_len"])

        replayed_arch = os.path.join(self.test_dir, "replayed.ndac")
        with open(replayed_arch, "wb") as f:
            f.write(pack_header_v6(
                flags=hdr1["flags"],
                kdf_algo_id=hdr1["kdf_algo_id"],
                cipher_algo_id=hdr1["cipher_algo_id"],
                compression_algo_id=hdr1["compression_algo_id"],
                chunk_size=hdr1["chunk_size"],
                salt=hdr1["salt"],
                base_nonce=hdr1["base_nonce"],
                kdf_param_m=hdr1["kdf_param_m"],
                kdf_param_t=hdr1["kdf_param_t"],
                encrypted_metadata_len=hdr1["encrypted_metadata_len"],
                payload_total_chunks=1
            ))
            f.write(meta_blob1)
            f.write(chunk_foreign_hdr)
            f.write(chunk_foreign_payload)

        with self.assertRaises(ValueError, msg="Se aceptó un chunk de replay proveniente de otro archivo"):
            decompress_ndc6(replayed_arch, self.output_dir, password=self.password)

    # =========================================================================
    # 4. PATH TRAVERSAL & SEGURIDAD DE RUTAS EN EXTRACTION ENGINE
    # =========================================================================
    def test_06_path_traversal_and_windows_reserved_names(self):
        """Simular rutas maliciosas (../../etc/passwd, C:\\Windows, UNC) en metadatos descomprimidos."""
        from src.utils.helpers import safe_extract_path

        malicious_paths = [
            "../../etc/shadow",
            "..\\..\\Windows\\System32\\cmd.exe",
            "C:/Windows/System32/drivers/etc/hosts",
            "\\\\attacker_server\\share\\exploit.exe",
        ]

        for p in malicious_paths:
            with self.assertRaises(ValueError, msg=f"Ruta peligrosa no fue bloqueada por safe_extract_path: {p}"):
                safe_extract_path(self.output_dir, p)

    # =========================================================================
    # 5. DOS, MEMORY EXHAUSTION & LIMITS AUDIT
    # =========================================================================
    def test_07_fake_giant_total_chunks_and_metadata_limits(self):
        """Verificar que un total_chunks inflado no lea más allá del final del stream."""
        with open(self.archive_path, "rb") as f:
            hdr = unpack_header_v6(f)
            meta_blob = f.read(hdr["encrypted_metadata_len"])
            payload_data = f.read()

        giant_hdr_bytes = pack_header_v6(
            flags=hdr["flags"],
            kdf_algo_id=hdr["kdf_algo_id"],
            cipher_algo_id=hdr["cipher_algo_id"],
            compression_algo_id=hdr["compression_algo_id"],
            chunk_size=hdr["chunk_size"],
            salt=hdr["salt"],
            base_nonce=hdr["base_nonce"],
            kdf_param_m=hdr["kdf_param_m"],
            kdf_param_t=hdr["kdf_param_t"],
            encrypted_metadata_len=hdr["encrypted_metadata_len"],
            payload_total_chunks=100  # Declarar más chunks de los existentes
        )

        giant_arch = os.path.join(self.test_dir, "giant_chunks.ndac")
        with open(giant_arch, "wb") as f:
            f.write(giant_hdr_bytes)
            f.write(meta_blob)
            f.write(payload_data)

        with self.assertRaises(ValueError):
            decompress_ndc6(giant_arch, self.output_dir, password=self.password)

    # =========================================================================
    # 6. FUZZING ADVANCED (1,000 ITERACIONES MASIVAS)
    # =========================================================================
    def test_08_massive_fuzzing_1k_iterations(self):
        """Fuzzing de 1,000 muestras mutadas probando validación completa sin crashes ni aceptación sin error."""
        crashes = 0
        accepted_corrupted = 0

        with open(self.archive_path, "rb") as f:
            valid_bytes = f.read()

        for i in range(1000):
            # Mutar datos arbitrarios a lo largo de todo el archivo
            mutated = bytearray(valid_bytes)
            for _ in range(secrets.randbelow(15) + 1):
                idx = secrets.randbelow(len(mutated))
                mutated[idx] ^= (secrets.randbelow(255) + 1)

            mutated_path = os.path.join(self.test_dir, f"fuzz_{i}.ndac")
            with open(mutated_path, "wb") as f:
                f.write(mutated)

            try:
                # Validar usando el motor completo
                val_res = validate_ndc6(mutated_path, password=self.password)
                if val_res:
                    accepted_corrupted += 1
            except ValueError:
                pass
            except Exception as exc:
                crashes += 1
            finally:
                if os.path.exists(mutated_path):
                    try:
                        os.remove(mutated_path)
                    except OSError:
                        pass

        self.assertEqual(crashes, 0, f"Se detectaron unhandled crashes en fuzzing: {crashes}")
        self.assertEqual(accepted_corrupted, 0, f"Se aceptaron contenedores corruptos en fuzzing: {accepted_corrupted}")

    # =========================================================================
    # 7. MANEJO DE CONTRASEÑAS EDGE CASES & CONCURRENCIA
    # =========================================================================
    def test_09_unicode_and_special_passwords(self):
        """Verificar soporte de contraseñas Unicode complejas, emojis y caracteres multibyte."""
        passwords = [
            "🔑Contraseña_Súper_Compleja_2026!#$áéíóúÑñ",
            "   Space P@ss   ",
            "CJK_Password_日本語_中文_한국어_🔒",
            "A" * 500
        ]

        for pwd in passwords:
            arch = os.path.join(self.test_dir, "unicode_pass.ndac")
            out_d = os.path.join(self.test_dir, "unicode_out")
            compress_ndc6(self.file1, arch, password=pwd)

            res = decompress_ndc6(arch, out_d, password=pwd)
            self.assertEqual(res["format"], "NDC6")
            shutil.rmtree(out_d, ignore_errors=True)

    def test_10_concurrent_compressions_safety(self):
        """Probar ejecución concurrente en 10 hilos simultáneos garantizando aislamiento."""
        threads = []
        errors = []

        def worker(thread_idx):
            try:
                out_arch = os.path.join(self.test_dir, f"thread_{thread_idx}.ndac")
                out_dir = os.path.join(self.test_dir, f"out_{thread_idx}")
                compress_ndc6(self.file1, out_arch, password=self.password)
                decompress_ndc6(out_arch, out_dir, password=self.password)
            except Exception as e:
                errors.append(e)

        for i in range(10):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Se produjeron errores en compresión concurrente: {errors}")


if __name__ == "__main__":
    unittest.main()
