# MANIFEST DE PUBLICACIÓN — NDAC v2.0.0

**Producto**: NDAC — Compresor y Protector de Archivos Ultra  
**Versión**: `2.0.0` (Release Final)  
**Fecha de Emisión**: 2026-08-27  
**Licencia**: MIT License  
**Formato Predeterminado de Compresión**: **NDC6** (Modo AEAD AES-256-GCM + Argon2id)  
**Formatos Legacy Soportados en Lectura**: `NDC3`, `NDC4`, `NDC5`  

---

## 1. ARTEFACTO EJECUTABLE Y CHECKSUM

| Propiedad | Valor |
| :--- | :--- |
| **Nombre de Archivo** | `CompresorArchivos.exe` |
| **Ubicación** | `dist/CompresorArchivos.exe` |
| **Tamaño Binario** | `41,818,688 bytes` (39.88 MB) |
| **Hash SHA-256** | `AECF5748053ECF3E0D1DE98E3F12E39F15896216D71E74DCC7E7B6FF96B47208` |
| **Firma Checksum File** | `SHA256SUMS.txt` |

---

## 2. ESPECIFICACIÓN TÉCNICA Y DEPENDENCIAS INCLUIDAS

- **Cifrado Principal**: AES-256-GCM AEAD (Tag de 128 bits por bloque de 1 MB + Autenticación AAD de cabecera).
- **Derivación de Clave (KDF)**: Argon2id (`memory_cost = 64 MB`, `time_cost = 3`, `parallelism = 4`).
- **Expansión de Subclaves**: HKDF-SHA256 (`Payload Key` y `Metadata Key` aislados).
- **Motor de Compresión**: Zstandard (`zstd` nivel 3) en streaming progresivo de $O(1)$ RAM.
- **Entorno de Compilación**: Python 3.13.5 (64-bit), PyInstaller 6.22.2, PyQt6 6.8.1, `cryptography` 44.0.1, `argon2-cffi` 23.1.0, `zstandard` 0.23.0.
- **Arquitectura de S.O.**: Windows 10 / Windows 11 (x64) Standalone Executable.

---

## 3. ESTADO DE SEGURIDAD Y AUDITORÍAS

- **Auditoría Ofensiva NDC6 (Red Team V3)**: **PASSED** (`RELEASE READY`).
- **Verificación End-to-End Byte-by-Byte**: **PASSED** (`ORIGINAL == EXTRACTED`).
- **Fuzzing Masivo (10,000 iteraciones en vivo)**: **0 crashes / 0 falsos positivos**.
- **Path Traversal & Zip-Bomb Protections**: Verified & Enabled.
- **Limitaciones Conocidas**: `VULN-V2-01` documentada únicamente en formato legacy NDC4 (`NDC6_KNOWN_LIMITATIONS.md`).
