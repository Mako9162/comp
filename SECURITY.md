# Política de Seguridad — NDAC v2.0.0

## Alcance y Protección

El programa soporta compresión sin pérdida, archivado multielemento (carpetas y múltiples archivos) y cifrado autenticado de extremo a extremo para archivos `.ndac` bajo la especificación **NDC6** (así como compatibilidad de lectura para **NDC5**, **NDC4** y **NDC3**):

1. **Cifrado AEAD AES-256-GCM y Derivación Argon2id (Formato NDC6)**:
   - Protección por contraseña con derivación de claves memory-hard mediante **Argon2id** (`m=64 MB`, `t=3`, `p=4`, Salt aleatorio de 16 bytes).
   - Separación estricta de subclaves con **HKDF-SHA256** (`Payload Key` y `Metadata Key`).
   - Cifrado Autenticado AEAD con Tag de 128 bits (16 bytes) por cada bloque de 1 MB.
   - Nonces deterministas de 96 bits amarrados al índice de bloque $\text{Chunk\_Nonce}[i] = \text{base\_nonce}_{12B} \oplus \text{Pad64To96}(i_{64bit})$.
   - Cifrado completo de metadatos (nombres de archivo, rutas relativas, fechas de modificación `mtime` y tamaños) con Zstandard + AES-256-GCM.
   - Autenticación de cabecera fija mediante Datos Asociados Autenticados (**AAD**).

2. **Protección Anti Path-Traversal**:
   - Sanitización estricta de rutas con `safe_extract_path()`.
   - Bloqueo de escrituras fuera del directorio de destino (`../../`, `C:\`, `/var/`, secuencias de escape y nombres reservados en Windows como `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
   - Límite máximo de profundidad de subcarpetas anidadas (`MAX_PATH_DEPTH = 50`).

3. **Protección Anti Compression-Bomb / Zip-Bomb**:
   - Verificación de consistencia entre el tamaño total declarado en metadatos y la suma de elementos descompuestos.
   - Control de ratio de expansión anómalo y límite máximo en la cantidad de elementos contenidos (`MAX_TOTAL_FILES = 100,000`).

4. **Validación de Integridad CRC32 & AEAD Tags**:
   - Verificación estricta de firmas AEAD por bloque y verificación de suma de comprobación **CRC32** individual por archivo en streaming progresivo.

---

## Limitaciones Conocidas / Known Limitations

### NDC4 Header Filename Metadata Unauthenticated (Legacy NDC4)
El metadatos del nombre de archivo en la cabecera del formato NDC4 no está incluido en el cálculo del digest del HMAC original.

Esta limitación se conserva únicamente por motivos de compatibilidad retroactiva con contenedores antiguos generados con NDAC v1.0.0/v1.5.0.

**En NDC6 esta limitación está 100% RESUELTA**: toda la metadata (incluyendo nombres de archivos y carpetas) está totalmente cifrada y autenticada con AES-256-GCM.

---

## Reportar Problemas de Seguridad

Si descubres una vulnerabilidad o problema de seguridad, contacta de forma privada al mantenedor del repositorio adjuntando un caso de reproducción mínimo.
