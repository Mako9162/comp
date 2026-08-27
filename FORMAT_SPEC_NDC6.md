# ESPECIFICACIÓN TÉCNICA FORMAL DEL FORMATO BINARIO NDC6 (NDAC v2.0)

**Versión de Especificación**: 6.0-DRAFT  
**Estado**: PROPOSED / DESIGN REVIEW  
**Firma Mágica**: `b"NDC6"` (`0x4E 0x44 0x43 0x36`)  

---

## 1. Visión General y Objetivos de Diseño

NDC6 es la especificación de contenedor de próxima generación para **NDAC v2.0**. Diseñada para resolver de forma definitiva las limitaciones de los formatos anteriores (NDC3/NDC4/NDC5), introduciendo cifrado autenticado de estándar militar (**AEAD**), autenticación total de metadatos, independencia de algoritmo, compresión ultra-rápida (**Zstandard**), streaming acotado por bloques con nonces explícitos y protección estricta anti-manipulación.

### Principios Cero-Confianza (Zero-Trust Binary Architecture):
1. **Cifrado Autenticado de Extremo a Extremo (AEAD)**: Todo el contenido y metadatos están cifrados o firmados mediante AES-256-GCM.
2. **Cero Fuga de Metadatos en Claro**: A diferencia de NDC4, los nombres de archivos, rutas relativas, tamaños y marcas de tiempo están cifrados dentro del bloque de metadatos autenticados.
3. **Nonces Explícitos Garantizados**: Nonce base aleatorio de 96 bits combinado con un contador de bloque de 64 bits para prevenir cualquier colisión de keystream.
4. **Streaming por Bloques Independientes**: El archivo se divide en marcos (Chunks) de 1 MB cada uno con su propio Tag de autenticación de 16 bytes.
5. **Detección Inmediata de Reordenamiento o Truncamiento**: La secuencia de marcos está amarrada al índice de bloque y al tag final del contenedor.

---

## 2. Identificadores de Algoritmos y Extensibilidad

NDC6 incluye campos de identificadores binarios para permitir la evolución de algoritmos sin romper el formato:

### KDF Algorithm Identifiers (`kdf_algo_id` — 1 byte)
- `0x01`: **Argon2id** (Predeterminado para NDAC 2.0 — Resistencia GPU/ASIC)
- `0x02`: **scrypt** (Alternativa memory-hard)
- `0x03`: **PBKDF2-HMAC-SHA256** (100,000+ iteraciones — Compatibilidad ligera)

### AEAD Cipher Identifiers (`cipher_algo_id` — 1 byte)
- `0x01`: **AES-256-GCM** (Predeterminado — Aceleración por hardware AES-NI)
- `0x02`: **ChaCha20-Poly1305** (Alternativa para procesadores sin AES-NI)

### Compression Identifiers (`compression_algo_id` — 1 byte)
- `0x00`: **COMPRESSION_NONE** (Sin compresión / Almacenamiento directo)
- `0x01`: **DEFLATE (zlib)** (Nivel 1 al 9)
- `0x02`: **Zstandard (zstd)** (Predeterminado — Alta velocidad y tasa de reducción)

---

## 3. Estructura Binaria de la Cabecera NDC6

Todas las lecturas y escrituras de cabeceras están ordenadas en **Big-Endian** (`>`).

### 3.1 Cabecera Fija del Contenedor (`HEADER_FORMAT_V6` — 80 bytes fijos + AAD)

```text
+-------------------------------------------------------------------------+
| Magic (4B) | Ver (1B) | Flags (2B) | KDF ID (1B) | Cipher ID (1B)      |
+-------------------------------------------------------------------------+
| Comp ID (1B)| Chunk Size (4B) | Salt (16B) | Base Nonce (12B)           |
+-------------------------------------------------------------------------+
| KDF Param1 (4B) | KDF Param2 (4B) | Header AAD Len (2B)                 |
+-------------------------------------------------------------------------+
| Encrypted Metadata Len (4B) | Payload Total Chunks (8B)                 |
+-------------------------------------------------------------------------+
| Header AEAD Tag (16B)                                                   |
+-------------------------------------------------------------------------+
| [Header AAD Bytes (Variable)]                                           |
+-------------------------------------------------------------------------+
| [Encrypted Metadata Frame (Variable)]                                   |
+-------------------------------------------------------------------------+
```

| Offset (Bytes) | Tamaño | Tipo Struct | Campo | Descripción |
| :---: | :---: | :---: | :--- | :--- |
| `0` | 4 | `4s` | `magic` | Secuencia estricta `b"NDC6"` |
| `4` | 1 | `B` | `version` | Entero de versión `6` |
| `5` | 2 | `H` | `flags` | Máscara de bits (Bit 0: Cifrado con clave, Bit 1: Metadatos cifrados, Bits 2-15: Reservados) |
| `7` | 1 | `B` | `kdf_algo_id` | Identificador de KDF (`0x01` = Argon2id) |
| `8` | 1 | `B` | `cipher_algo_id` | Identificador de Cifrado (`0x01` = AES-256-GCM) |
| `9` | 1 | `B` | `compression_algo_id` | Identificador de Compresión (`0x02` = Zstandard) |
| `10` | 4 | `I` | `chunk_size` | Tamaño de bloque de streaming (predeterminado 1,048,576 B = 1 MB) |
| `14` | 16 | `16s` | `salt` | Salt aleatorio derivado con `secrets.token_bytes(16)` |
| `30` | 12 | `12s` | `base_nonce` | Nonce aleatorio inicial de 96 bits (`secrets.token_bytes(12)`) |
| `42` | 4 | `I` | `kdf_param_m` | Parámetro de memoria KDF (ej. 65536 KB para Argon2id) |
| `46` | 4 | `I` | `kdf_param_t` | Parámetro de tiempo / iteraciones KDF (ej. 3 iteraciones) |
| `50` | 2 | `H` | `header_aad_len` | Longitud en bytes del bloque AAD de cabecera visible |
| `52` | 4 | `I` | `encrypted_metadata_len` | Longitud del bloque de metadatos cifrados |
| `56` | 8 | `Q` | `payload_total_chunks` | Cantidad total de marcos de datos en el payload |
| `64` | 16 | `16s` | `header_aead_tag` | Tag de autenticación AES-GCM del encabezado |
| `80` | `N` | `bytes` | `header_aad_bytes` | Datos asociados autenticados visibles |

---

## 4. Esquema de Cifrado y Derivación de Claves (HKDF)

### 4.1 Derivación Principal (Argon2id)
```python
master_key = Argon2id(
    password=password.encode('utf-8'),
    salt=salt,
    time_cost=kdf_param_t,     # 3 iteraciones
    memory_cost=kdf_param_m,   # 64 MB
    parallelism=4,
    hash_len=32
)
```

### 4.2 Expansión de Subclaves (HKDF-SHA256)
Para evitar la reutilización de claves en distintos contextos, se utiliza **HKDF-Expand**:
- `enc_key = HKDF-Expand(master_key, info=b"NDAC6-AES256-GCM-PayloadKey", L=32)`
- `meta_key = HKDF-Expand(master_key, info=b"NDAC6-AES256-GCM-MetadataKey", L=32)`

### 4.3 Generación Determinista de Nonce por Bloque (Chunk Nonce)
Para el marco/chunk con índice $i$ ($0 \le i < \text{total\_chunks}$):
$$\text{Chunk\_Nonce}[i] = \text{base\_nonce}_{12B} \oplus \text{Pad64To96}(i_{64bit})$$
Garantiza matemáticamente que el nonce de 96 bits **jamás se repita** para ningún bloque del mismo contenedor.

---

## 5. Estructura del Bloque de Metadatos Cifrados (Encrypted Metadata Frame)

Los metadatos del contenido del paquete (nombres de archivos, estructura de carpetas, fechas `mtime`, permisos y CRC32 individuales) están empaquetados en formato **Zstandard / DEFLATE** y cifrados con `meta_key` usando AES-256-GCM.

### Estructura Interna Descomprimida de Metadatos:
- `root_name` (`UTF-8 String`): Nombre de la carpeta raíz o paquete
- `total_original_size` (`uint64`): Tamaño acumulado descompuesto
- `total_files_count` (`uint32`): Cantidad de archivos y directorios
- `entries_list` (`Secuencia de Entradas`):
  - `entry_type` (`1B`): `1` = Archivo, `2` = Carpeta
  - `path_len` (`2B`): Longitud de la ruta relativa UTF-8
  - `file_size` (`8B`): Tamaño del archivo descompuesto
  - `mtime` (`8B`): Fecha Unix de modificación
  - `crc32` (`4B`): Checksum CRC32 individual
  - `rel_path` (`N bytes`): Ruta relativa UTF-8 (ej: `src/core/engine.py`)

---

## 6. Formato de Marcos de Streaming (Chunk Frame Layout — `1 MB`)

Cada bloque de payload en streaming contiene su propio encabezado de sincronización y Tag AEAD independiente:

```text
+-----------------------------------------------------------------------+
| Chunk Index (8B) | Chunk Payload Len (4B) | Ciphertext (N Bytes)     |
+-----------------------------------------------------------------------+
| Chunk AEAD Tag (16B)                                                  |
+-----------------------------------------------------------------------+
```

### Proceso de Verificación durante la Descompresión:
1. El motor lee `Chunk Index` ($i$) y `Chunk Payload Len` ($L$).
2. Deriva el `Chunk_Nonce` correspondientes ($i$).
3. Descifra y autentica los $L$ bytes de `Ciphertext` usando AES-256-GCM con el `Chunk AEAD Tag` de 16 bytes.
4. Si el Tag es inválido, el proceso **se detiene de inmediato** sin escribir el bloque a disco.
5. Pasa el bloque descifrado al descompresor progresivo (Zstandard/DEFLATE).

---

## 7. Límites Definidos del Formato NDC6

- **Tamaño Máximo Total de Contenedor**: $100\text{ TB}$ ($10^{14}\text{ bytes}$).
- **Cantidad Máxima de Archivos/Carpetas**: $10,000,000\text{ elementos}$.
- **Profundidad Máxima de Subdirectorios**: $100\text{ niveles}$.
- **Longitud Máxima de Ruta Relativa**: $4,096\text{ bytes UTF-8}$.
- **Tamaño Predeterminado de Bloque (Chunk)**: $1,048,576\text{ bytes}$ ($1\text{ MB}$).
