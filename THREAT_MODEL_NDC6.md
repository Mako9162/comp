# MODELO DE AMENAZAS Y MITIGACIÓN DE VULNERABILIDADES — NDC6 (NDAC v2.0)

**Versión de Documento**: 1.0-DRAFT  
**Estado**: DESIGN SPECIFICATION  

---

## 1. Matriz de Amenazas y Mitigaciones en NDC6

| Amenaza / Vector de Ataque | Impacto en NDC5 / NDC4 | Mitigación Arquitectónica en NDC6 |
| :--- | :--- | :--- |
| **Header Tampering (Alteración de metadatos)** | En NDC4 el nombre no está firmado por HMAC. | **AEAD AAD + Cifrado Total**: El nombre y la metadata están cifrados y firmados con AES-GCM. |
| **Bit Flipping / Ciphertext Tampering** | Capturado por ZLIB / CRC32. | **Firma AEAD Tag 16B por Chunk**: Rechazo inmediato por hardware antes de descifrar. |
| **Reorganización / Eliminación de Chunks** | Dificil de detectar antes del CRC final. | **Índice de Chunk en Nonce + Total Chunks en AAD**: Cualquier falta o desorden rompe el tag AEAD. |
| **Path Traversal Vía Symlink / Junction** | Requiere validación `safe_extract_path()`. | **Rutas Cifradas + Normalización Canónica Realpath**: Imposibilidad de inyectar symlinks en metadata. |
| **Zip-Bomb / Expansion DoS** | Control de límites en Python. | **Header Pre-declare AAD Verification**: Verificación de ratio antes de iniciar descompresión. |
| **Ataque de Fuerza Bruta / GPU Mining** | PBKDF2 (100k iters) moderado. | **Argon2id (64 MB RAM)**: Costo computacional prohibitivo para minería distribuida en GPU/ASIC. |
| **Degradación de Algoritmo (Downgrade)** | Bloqueado por Magic Bytes. | **Header AAD Signature**: Los IDs de algoritmo forman parte de la firma AAD no modificable. |

---

## 2. Comparación de Capacidades: NDC5 vs NDC6

| Característica | Formato NDC5 (Estable v1.5.0) | Formato NDC6 (Propuesto v2.0) |
| :--- | :---: | :---: |
| **Cifrado Principal** | Keystream XOR sobre PRF-HMAC (Propietario) | **AES-256-GCM / ChaCha20-Poly1305 (Estándar AEAD)** |
| **Derivación de Clave (KDF)** | PBKDF2-HMAC-SHA256 (100,000 iteraciones) | **Argon2id (Memory-Hard 64 MB RAM)** |
| **Expansión de Claves** | Clave única dividida por índice | **HKDF-SHA256 (Claves independientes)** |
| **Autenticación de Nombres** | En payload cifrado | **Cifrado + Autenticado AEAD** |
| **Algoritmo de Compresión** | DEFLATE (zlib) | **Zstandard (zstd) + DEFLATE** |
| **Verificación por Bloque (Streaming)** | Búfer continuo de 1 MB | **Marco AEAD de 1 MB independiente con Tag 16B** |
| **Velocidad de Compresión/Desc.** | Normal | **3x a 5x más rápida con Zstandard y AES-NI** |
| **Extracción Parcial Futura** | Requiere leer stream completo | **Soportada mediante Índice de Chunks** |

---

## 3. Decisiones Abiertas de Diseño (Open Design Decisions)

### DECISION-01: Extracción Parcial y Acceso Aleatorio (Random Access Index)
- **Opciones**:
  - *Opción A*: Incluir una tabla de índice de entradas cifrada al final del contenedor NDC6.
  - *Opción B*: Mantener una estructura de streaming puramente secuencial.
- **Ventajas Opción A**: Permite explorar el contenido del contenedor y extraer un solo archivo de 1 MB en un paquete de 50 GB sin leer los 49.9 GB anteriores.
- **Recomendación**: **Opción A**. Incluir la tabla de índice cifrada en la cabecera/footer de NDC6.

### DECISION-02: Dependencia Criptográfica Externa
- **Opciones**:
  - *Opción A*: Utilizar la librería estándar de Python `cryptography` (compilada en C, alta velocidad AES-NI).
  - *Opción B*: Implementación en Python puro.
- **Ventajas Opción A**: Velocidad multimegabyte por segundo y cumplimiento FIPS.
- **Recomendación**: **Opción A**. `cryptography` se empaquetará dentro de `CompresorArchivos.exe` vía PyInstaller sin impacto para el usuario.

---

## 4. Estrategia de Migración y Coexistencia (NDAC 2.0)

```text
NDAC v2.0 App Engine
│
├── Lector / Extractor Multiformato (Transparente)
│   ├── Formato NDC3 (Legacy Read-Only)
│   ├── Formato NDC4 (Legacy Read-Only)
│   ├── Formato NDC5 (Stable Read-Only)
│   └── Formato NDC6 (Modern Default Read/Write)
│
└── Generador Predeterminado: Formato NDC6
```

- **Compatibilidad Total**: NDAC 2.0 podrá leer y descompresionar sin problemas cualquier archivo histórico `.ndac` (NDC3, NDC4, NDC5 o NDC6).
- **Generación Nueva**: Todas las operaciones de compresión en NDAC 2.0 generarán por defecto el formato moderno **NDC6**.
