import unittest
from src.formats.ndc6.crypto import (
    derive_master_key, expand_subkeys, derive_chunk_nonce,
    encrypt_aead_gcm, decrypt_aead_gcm, generate_salt, generate_nonce
)


class TestNDC6Crypto(unittest.TestCase):

    def test_01_argon2id_derivation(self):
        """Verificar la derivación de clave Argon2id."""
        salt = generate_salt(16)
        mk1 = derive_master_key("SecretPass123", salt)
        mk2 = derive_master_key("SecretPass123", salt)
        self.assertEqual(mk1, mk2)

        # Distinta contraseña -> Distinta Master Key
        mk3 = derive_master_key("SecretPass456", salt)
        self.assertNotEqual(mk1, mk3)

    def test_02_hkdf_subkey_expansion(self):
        """Verificar la expansión de subclaves independientes mediante HKDF-SHA256."""
        mk = derive_master_key("Pass", generate_salt(16))
        payload_key, meta_key = expand_subkeys(mk)
        self.assertEqual(len(payload_key), 32)
        self.assertEqual(len(meta_key), 32)
        self.assertNotEqual(payload_key, meta_key)

    def test_03_chunk_nonce_uniqueness(self):
        """Demostrar unicidad absoluta de nonces sobre 1,000 bloques consecutivos."""
        base_nonce = generate_nonce(12)
        seen_nonces = set()
        for idx in range(1000):
            n = derive_chunk_nonce(base_nonce, idx)
            self.assertEqual(len(n), 12)
            self.assertNotIn(n, seen_nonces)
            seen_nonces.add(n)

    def test_04_aead_gcm_tamper_rejection(self):
        """Verificar que cualquier alteración en el ciphertext o AAD rompa el Tag AEAD."""
        key = generate_salt(32)
        nonce = generate_nonce(12)
        aad = b"NDAC6-HeaderAAD"
        plaintext = b"Payload de prueba ultra confidencial"

        ciphertext_with_tag = encrypt_aead_gcm(plaintext, key, nonce, aad=aad)
        decrypted = decrypt_aead_gcm(ciphertext_with_tag, key, nonce, aad=aad)
        self.assertEqual(decrypted, plaintext)

        # Bit flip en ciphertext
        mod = bytearray(ciphertext_with_tag)
        mod[0] ^= 0xFF
        with self.assertRaises(ValueError):
            decrypt_aead_gcm(bytes(mod), key, nonce, aad=aad)

        # AAD alterado
        with self.assertRaises(ValueError):
            decrypt_aead_gcm(ciphertext_with_tag, key, nonce, aad=b"TamperedAAD")


if __name__ == "__main__":
    unittest.main()
