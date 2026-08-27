import secrets
from typing import Tuple, Optional

import argon2.low_level
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import (
    DEFAULT_ARGON2_MEMORY_KB, DEFAULT_ARGON2_TIME_COST, DEFAULT_ARGON2_PARALLELISM
)


def generate_salt(length: int = 16) -> bytes:
    """Genera un salt aleatorio criptográficamente seguro de N bytes."""
    return secrets.token_bytes(length)


def generate_nonce(length: int = 12) -> bytes:
    """Genera un base nonce aleatorio criptográficamente seguro de N bytes (96 bits)."""
    return secrets.token_bytes(length)


def derive_master_key(
    password: str,
    salt: bytes,
    memory_kb: int = DEFAULT_ARGON2_MEMORY_KB,
    time_cost: int = DEFAULT_ARGON2_TIME_COST,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM
) -> bytes:
    """Deriva una Master Key de 32 bytes utilizando Argon2id (memory-hard)."""
    if not password:
        raise ValueError("La contrasena no puede estar vacia.")
    
    return argon2.low_level.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kb,
        parallelism=parallelism,
        hash_len=32,
        type=argon2.low_level.Type.ID
    )


def expand_subkeys(master_key: bytes) -> Tuple[bytes, bytes]:
    """
    Expande la Master Key en subclaves independientes mediante HKDF-SHA256:
    - payload_key (32B): Clave para cifrado del payload
    - metadata_key (32B): Clave para cifrado de metadatos
    """
    hkdf_payload = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"NDAC6-AES256-GCM-PayloadKey"
    )
    payload_key = hkdf_payload.derive(master_key)

    hkdf_meta = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"NDAC6-AES256-GCM-MetadataKey"
    )
    metadata_key = hkdf_meta.derive(master_key)

    return payload_key, metadata_key


def derive_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """
    Deriva de forma determinista un nonce único de 96 bits para el chunk i:
    Chunk_Nonce[i] = base_nonce (12B) XOR Pad64To96(chunk_index).
    """
    if len(base_nonce) != 12:
        raise ValueError("El base nonce debe ser exactamente de 12 bytes (96 bits).")
    
    idx_bytes = chunk_index.to_bytes(8, "big").rjust(12, b"\x00")
    return bytes(b ^ p for b, p in zip(base_nonce, idx_bytes))


def encrypt_aead_gcm(
    plaintext: bytes,
    key: bytes,
    nonce: bytes,
    aad: Optional[bytes] = None
) -> bytes:
    """
    Cifra los datos en plaintext usando AES-256-GCM con autenticación AEAD y AAD opcional.
    Retorna bytes contiguos: ciphertext (N bytes) + tag (16 bytes).
    """
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, aad)


def decrypt_aead_gcm(
    ciphertext_with_tag: bytes,
    key: bytes,
    nonce: bytes,
    aad: Optional[bytes] = None
) -> bytes:
    """
    Descifra y valida la autenticidad AEAD de los datos usando AES-256-GCM.
    Arroja ValueError si la clave es incorrecta o si los datos fueron alterados.
    """
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
    except Exception as exc:
        raise ValueError("Contrasena incorrecta o archivo alterado / corrupto.") from exc
