# Registro de Cambios (CHANGELOG) — NDAC

Todos los cambios notables en este proyecto están documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-08-27

### 🚀 Novedades y Arquitectura NDC6
- **Formato Criptográfico Moderno NDC6 (AEAD)**:
  - Cifrado Autenticado de Extremo a Extremo con **AES-256-GCM** y firma AEAD Tag de 128 bits (16B) por cada bloque de 1 MB.
  - Derivación de claves memory-hard con **Argon2id** (64 MB RAM, 3 iteraciones) e infraestructura **HKDF-SHA256** para separación de subclaves (`Payload Key` y `Metadata Key`).
  - Nonces deterministas de 96 bits amarrados al índice de bloque $\text{Chunk\_Nonce}[i] = \text{base\_nonce}_{12B} \oplus \text{Pad64To96}(i_{64bit})$.
  - Cifrado y ocultación total de metadatos (nombres de archivo, rutas relativas, marcas de tiempo y tamaños).
  - Autenticación de cabecera fija mediante Datos Asociados Autenticados (**AAD**).
  - Integración del motor de compresión de ultra-alta velocidad **Zstandard (zstd)**.
  - Arquitectura modular aislada en `src/formats/ndc6/`.
- **Despachador Multiformato Transparente**:
  - Función `detect_format()` que identifica automáticamente contenedores NDC3, NDC4, NDC5 y NDC6.
- **Suite de Pruebas NDC6 y Red Team**:
  - Nuevas suites `tests/test_ndc6.py`, `tests/test_ndc6_crypto.py` y `tests/test_red_team_ndc6.py`.

---

## [1.5.0] - 2026-08-27

### 🚀 Novedades y Características Principales
- **Soporte Multielemento y Carpetas (NDC5)**:
  - Formato binario **NDC5** que permite comprimir directorios completos con subcarpetas, archivos y carpetas vacías conservando fechas de modificación (`mtime`).
- **Interfaz Gráfica Profesional (PyQt6)**:
  - Zona de arrastrar y soltar (Drag & Drop) para múltiples archivos y carpetas simultáneos.
  - Tabla interactiva de selección de elementos con botones para agregar, eliminar y limpiar lista.
  - Medidor dinámico de fortaleza de contraseña en tiempo real.
  - Barra de progreso detallada con cálculo de velocidad (MB/s) y tiempo estimado restante (ETA).
  - Diálogos de **Propiedades**, **Validación de Archivo** (sin extraer a disco) y **Configuración**.
- **Interfaz de Línea de Comandos (CLI)**:
  - Subcomandos de terminal `ndac compress`, `extract`, `validate`, `info`.
  - Opción silenciosa `--quiet` / `-q` para automatización y scripts.
  - Códigos de salida estándar (0 = Éxito, 1 = Error General, 2 = Archivo Inválido, 3 = Contraseña Incorrecta, 4 = Cancelado, 5 = Error I/O).
- **Integración con Explorador de Windows**:
  - Asociación de la extensión de archivo `.ndac`.
  - Comandos en el menú contextual del Explorador de Windows: `Comprimir con NDAC`, `Comprimir carpeta con NDAC` y `Extraer con NDAC`.
- **Internacionalización (i18n)**:
  - Sistema centralizado de traducción en **Español** e **Inglés** con cambio de idioma en caliente.

### 🔒 Seguridad y Rendimiento
- **Procesamiento Streaming en Bloques de 1 MB**: Huella de memoria RAM acotada O(1) (~5 MB) sin importar el tamaño total de los archivos.
- **Protección Anti Path-Traversal**: Normalización y verificación estricta `safe_extract_path()` contra inyecciones `../../` o rutas absolutas.
- **Protección Anti Zip-Bomb**: Límites automáticos de profundidades (máx. 50), recuento de archivos (máx. 100,000) y comprobación de ratios de expansión.
- **Verificación HMAC en Tiempo Constante**: Comparación con `hmac.compare_digest()` para mitigar ataques de temporización.

### 🔄 Compatibilidad
- Mantiene compatibilidad total de lectura y descompresión para archivos generados en versiones anteriores (**NDC3** y **NDC4**).

---

## [1.0.0] - 2026-01-15
- Versión inicial con soporte para compresión de archivo único en formato NDC4 y cifrado PBKDF2.
