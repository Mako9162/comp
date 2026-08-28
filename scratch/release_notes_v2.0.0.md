## NDAC v2.0.0 — Stable Release

NDAC v2.0.0 es la nueva versión estable que introduce el formato de contenedor cifrado y autenticado de nueva generación **NDC6**.

### 🚀 Principales Novedades

- **Nuevo Formato de Contenedor NDC6**:
  - Cifrado Autenticado de Extremo a Extremo con **AES-256-GCM** y firma AEAD Tag de 128 bits (16B) por bloque de 1 MB.
  - Derivación de claves memory-hard con **Argon2id** (64 MB RAM, 3 iteraciones) e infraestructura **HKDF-SHA256** para separación estricta de subclaves (`Payload Key` y `Metadata Key`).
  - Nonces deterministas de 96 bits amarrados al índice de bloque $\text{Chunk\_Nonce}[i] = \text{base\_nonce}_{12B} \oplus \text{Pad64To96}(i_{64bit})$.
  - Cifrado y ocultación total de metadatos (nombres de archivo, rutas relativas, marcas de tiempo y tamaños).
  - Autenticación de cabecera fija mediante Datos Asociados Autenticados (**AAD**).
  - Integración del motor de compresión ultra-rápido **Zstandard (zstd)** en streaming de memoria acotada $O(1)$.
- **Compatibilidad Retroactiva Intacta**:
  - Soporte de lectura y descompresión transparente para archivos generados en formatos anteriores (**NDC3**, **NDC4** y **NDC5**).
- **Ejecutable Standalone para Windows**:
  - Distribución en un único binario ejecutable portable (`CompresorArchivos.exe`) que no requiere Python ni dependencias externas instaladas.

---

### 🛡️ Notas de Seguridad

- NDC6 incorpora autenticación criptográfica AEAD del contenido y metadatos.
- La limitación histórica `VULN-V2-01` corresponde únicamente al formato legacy NDC4 y **no afecta al nuevo formato NDC6**.

---

### 🔍 Verificación de Integridad del Ejecutable

Los usuarios pueden verificar la integridad del ejecutable distribuido utilizando la firma SHA-256 incluida en `SHA256SUMS.txt`:

```text
AECF5748053ECF3E0D1DE98E3F12E39F15896216D71E74DCC7E7B6FF96B47208  CompresorArchivos.exe
```
