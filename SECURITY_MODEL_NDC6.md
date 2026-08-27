# MODELO DE SEGURIDAD CRIPTOGRÁFICA — NDC6 (NDAC v2.0)

**Versión de Documento**: 1.0-DRAFT  
**Estado**: DESIGN SPECIFICATION  

---

## 1. Objetivos de Seguridad

El modelo de seguridad de NDC6 se fundamenta en cinco pilares criptográficos:

1. **Confidencialidad Total**: Los datos del usuario y toda la metadata asociada (nombres de archivo, rutas, marcas de tiempo, tamaños) están cifrados con AES-256 en modo GCM.
2. **Autenticidad e Integridad Garantizadas (AEAD)**: Todo el contenedor está protegido por firmas AEAD de 128 bits (16 bytes). Cualquier alteración en un solo bit de cabecera, metadatos o payload cifrado provoca el rechazo inmediato del archivo.
3. **Resistencia a Ataques Offline (Argon2id)**: La derivación de claves utiliza Argon2id con parámetros memory-hard (64 MB RAM + 3 iteraciones), imponiendo una barrera de costo computacional gigantesca ante intentos de fuerza bruta con GPU o clústeres ASIC.
4. **Prevención Absoluta de Reutilización de Keystream**: Generación de nonces de 96 bits únicos garantizados mediante XOR determinista del `base_nonce` aleatorio con el índice de bloque de 64 bits.
5. **Mitigación de Canal Lateral y Timing Attacks**: Todas las comprobaciones de tags y firmas utilizan comparación en tiempo constante (`hmac.compare_digest` / verificaciones AEAD nativas de hardware).

---

## 2. Jerarquía y Expansión de Claves (HKDF Key Tree)

```text
                     [ Contraseña del Usuario (str UTF-8) ]
                                      │
                                      ▼
                        [ Argon2id (Salt 16B, m=64MB, t=3) ]
                                      │
                                      ▼
                           [ Master Key (256 bits) ]
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
[ HKDF-Expand(b"NDAC6-PayloadKey") ]        [ HKDF-Expand(b"NDAC6-MetadataKey") ]
               │                                             │
               ▼                                             ▼
  [ Payload Encryption Key (256B) ]             [ Metadata Encryption Key (256B) ]
```

### Reglas de Separación de Claves:
- La `Master Key` nunca se utiliza directamente para cifrar datos ni metadatos.
- Se derivan subclaves independientes para el payload y para la metadata mediante **HKDF-SHA256**.
- Si un atacante intentara cruzar bloques entre metadata y payload, los tags AEAD fallarán debido a las claves distintas.

---

## 3. Construcción del Nonce de Bloque y Prevención de Colisión

### Definición del Nonce:
- `base_nonce`: 12 bytes (96 bits) generados por el CSPRNG del sistema operativo (`secrets.token_bytes(12)`).
- `chunk_index`: Entero sin signo de 64 bits ($0 \le i < 2^{64}-1$).

### Generación:
```python
chunk_nonce_bytes = bytes(
    b ^ p for b, p in zip(base_nonce, chunk_index.to_bytes(8, 'big').rjust(12, b'\x00'))
)
```

### Propiedad de Unicidad:
Dado que $i$ incrementa monótonamente por cada marco de 1 MB, se garantiza matemáticamente que dentro del mismo archivo **ningún bloque reutilizará jamás el mismo nonce**. Puesto que cada archivo tiene un `base_nonce` y un `salt` independientes, tampoco existirán colisiones entre archivos distintos.

---

## 4. Datos Asociados Autenticados (AAD — Associated Authenticated Data)

Para evitar ataques de substitución de cabecera o alteración de parámetros de descompresión, la cabecera fija de NDC6 se pasa como AAD a la llamada de descifrado AEAD:

### Componentes del AAD de Cabecera:
```python
header_aad = struct.pack(
    ">4sBBHHBBI",
    b"NDC6",
    version,             # 6
    flags,
    kdf_algo_id,         # Argon2id
    cipher_algo_id,      # AES-256-GCM
    compression_algo_id, # Zstandard
    chunk_size,          # 1 MB
    payload_total_chunks
)
```

### Protección Concedida por el AAD:
Si un atacante intenta:
- Cambiar el identificador de compresión (ej. Zstandard -> DEFLATE) para provocar un DoS.
- Modificar el tamaño de chunk.
- Modificar la versión o flags.

La verificación AEAD del marco **fallará antes de descifrar un solo byte**.

---

## 5. Resistencia ante Respuestas de Error (Oracle Distinguishing)

NDC6 adopta la política de **Manejo Opaque de Errores Criptográficos**:
- Ante cualquier fallo de autenticación AEAD en cabecera, metadatos o chunks, el motor reportará una excepción genérica unificada:
  `ValueError("El archivo esta corrupto, fue alterado o la contrasena es incorrecta.")`
- Esto evita ataques de oráculo de padding o distinción de errores entre clave incorrecta y corrupción de payload.
