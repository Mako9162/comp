# Especificación Técnica del Formato de Archivos NDAC (NDC3 / NDC4 / NDC5)

Este documento detalla la estructura binaria, cabeceras, criptografía y disposición de datos del formato de compresión `.ndac`.

---

## 1. Visión General del Formato

NDAC utiliza un contenedor de compresión basado en el algoritmo **DEFLATE (zlib)** con empaquetado personalizado y capas opcionales de cifrado autenticado de alta seguridad (**PBKDF2-HMAC-SHA256**).

| Versión | Magic Bytes | Soporte de Cifrado | Múltiples Archivos / Carpetas |
| :---: | :---: | :---: | :---: |
| **NDC3** | `NDC3` (`0x4E 0x44 0x43 0x33`) | No | No (Solo 1 archivo) |
| **NDC4** | `NDC4` (`0x4E 0x44 0x43 0x34`) | Sí (PBKDF2 + Keystream XOR) | No (Solo 1 archivo) |
| **NDC5** | `NDC5` (`0x4E 0x44 0x43 0x35`) | Sí (PBKDF2 + Keystream XOR) | **Sí** (Carpetas y Múltiples Archivos) |

---

## 2. Estructura Binaria de Cabeceras

Todas las cabeceras están empaquetadas en orden de bytes **Big-Endian** (`>`).

### 2.1 Cabecera NDC3 (`>4sBQIH`) — 19 bytes fijos + Nombre UTF-8
- `magic` (`4 bytes`): Secuencia literal `b"NDC3"`
- `version` (`1 byte uint8`): Valor entero `3`
- `original_size` (`8 bytes uint64 Q`): Tamaño descompuesto en bytes
- `crc32_checksum` (`4 bytes uint32 I`): Checksum CRC32 sin signo de los datos descompuestos
- `filename_len` (`2 bytes uint16 H`): Longitud en bytes del nombre del archivo en UTF-8
- `filename_bytes` (`N bytes`): Nombre de archivo codificado en UTF-8

### 2.2 Cabecera NDC4 (`>4sBB16sQIH32s`) — 68 bytes fijos + Nombre UTF-8
- `magic` (`4 bytes`): Secuencia literal `b"NDC4"`
- `version` (`1 byte uint8`): Valor entero `4`
- `is_encrypted` (`1 byte uint8`): `1` si incluye cifrado por clave; `0` en caso contrario
- `salt` (`16 bytes`): Salt criptográfico aleatorio derivado con `secrets.token_bytes(16)`
- `original_size` (`8 bytes uint64 Q`): Tamaño descompuesto en bytes
- `crc32_checksum` (`4 bytes uint32 I`): Checksum CRC32 sin signo del archivo descompuesto
- `filename_len` (`2 bytes uint16 H`): Longitud en bytes del nombre de archivo en UTF-8
- `hmac_tag` (`32 bytes`): Firma de autenticación HMAC-SHA256
- `filename_bytes` (`N bytes`): Nombre del archivo codificado en UTF-8

### 2.3 Cabecera NDC5 (`>4sBB16sQIIH32s`) — 72 bytes fijos + Nombre Raíz UTF-8
- `magic` (`4 bytes`): Secuencia literal `b"NDC5"`
- `version` (`1 byte uint8`): Valor entero `5`
- `is_encrypted` (`1 byte uint8`): `1` si está protegido con clave; `0` sin clave
- `salt` (`16 bytes`): Salt criptográfico aleatorio
- `total_original_size` (`8 bytes uint64 Q`): Suma acumulada de todos los elementos descompuestos
- `total_files_count` (`4 bytes uint32 I`): Cantidad total de archivos y carpetas contenidos
- `crc32_checksum` (`4 bytes uint32 I`): Checksum CRC32 global del flujo del contenedor descompuesto
- `root_name_len` (`2 bytes uint16 H`): Longitud del nombre del contenedor raíz en UTF-8
- `hmac_tag` (`32 bytes`): Firma HMAC-SHA256 de autenticación de cabecera
- `root_name_bytes` (`N bytes`): Nombre de carpeta o paquete en UTF-8

---

## 3. Disposición del Payload del Contenedor NDC5 (`>BHQQI`)

Dentro del flujo comprimido DEFLATE de un archivo **NDC5**, se almacena una secuencia contigua de Entradas de Paquete (**NDAC Package Entry**):

### Estructura de Encabezado de Entrada (23 bytes fijos + Ruta UTF-8)
- `entry_type` (`1 byte uint8`): `0x01` = Archivo, `0x02` = Directorio
- `path_len` (`2 bytes uint16 H`): Longitud de la ruta relativa UTF-8
- `file_size` (`8 bytes uint64 Q`): Tamaño descompuesto (0 para directorios)
- `mtime` (`8 bytes uint64 Q`): Marca de tiempo Unix de modificación (`mtime`)
- `crc32` (`4 bytes uint32 I`): CRC32 individual del archivo descompuesto
- `path_bytes` (`N bytes`): Ruta relativa codificada en UTF-8 con separador `/`
- `file_bytes` (`file_size bytes`): Bytes de contenido contiguo (solo si `entry_type == 0x01`)

---

## 4. Esquema Criptográfico

### 4.1 Derivación de Claves (PBKDF2)
Cuando un archivo está protegido con contraseña:
1. `enc_key, mac_key = PBKDF2-HMAC-SHA256(password, salt, iterations=100000, dklen=64)`
   - `enc_key` = primeros 32 bytes (usados para cifrado keystream XOR)
   - `mac_key` = siguientes 32 bytes (usados para HMAC)

### 4.2 Verificación de Autenticidad (HMAC Tag)
`hmac_tag = HMAC-SHA256(mac_key, salt + str(original_size) + str(crc32))`
La verificación se realiza mediante `hmac.compare_digest()` en tiempo constante antes de procesar el flujo comprimido.

### 4.3 Cifrado por Bloques (Keystream XOR Determinista)
El flujo de datos se procesa en bloques mediante XOR con subclaves derivadas:
`block_key = HMAC(key, blk_idx) + HMAC(key, blk_idx + 0x80000000)`
Garantiza cifrado/descifrado transparente por bloques en un solo pase de I/O.
