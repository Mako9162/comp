# NDAC — Compresor y Protector de Archivos Ultra 🚀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Repository](https://img.shields.io/badge/GitHub-Mako9162%2Fcomp-blue.svg)](https://github.com/Mako9162/comp.git)
[![Version](https://img.shields.io/badge/Version-1.5.0-success.svg)](#)

**NDAC (File Compressor Ultra / NDC5)** es una herramienta profesional de compresión, protección e inspección de archivos y directorios para Windows. Diseñada bajo la filosofía:

> **"Simple para el usuario, potente por dentro."**

Procesamiento 100% local sin conexión a internet, soporte para carpetas completas y múltiples archivos, cifrado militar PBKDF2-HMAC-SHA256, interfaz gráfica moderna de arrastrar y soltar, y CLI completa para automatización.

---

## ✨ Características Principales

- 📦 **Compresión de Carpetas y Múltiples Archivos (Formato NDC5)**: Convierte estructuras complejas con subdirectorios, archivos y carpetas vacías en un único paquete `.ndac`, preservando nombres, jerarquías y fechas de modificación (`mtime`).
- 🔒 **Protección con Contraseña y Cifrado Autenticado**: PBKDF2-HMAC-SHA256 (100,000 iteraciones + Salt aleatorio de 16 bytes + Keystream XOR determinista posicional + HMAC-SHA256 de autenticación en tiempo constante).
- ⚡ **Rendimiento Bounded-RAM Streaming (1 MB Chunk I/O)**: Procesamiento progresivo en bloques de 1 MB. Garantiza un consumo de memoria constante O(1) (~5 MB RAM) sin importar si el archivo pesa 10 MB o 10 GB.
- 🎨 **Interfaz Moderna Drag & Drop (Cyber Dark Glass)**: Zona intuitiva para arrastrar múltiples archivos/carpetas, tabla interactiva de selección, medidor de fortaleza de contraseña en tiempo real y estadísticas en vivo (Velocidad, ETA, Tamaños).
- 💻 **CLI Profesional para Automatización**: Invocación por línea de comandos (`ndac compress`, `extract`, `validate`, `info`) con modo silencioso `--quiet` y códigos de salida estándar (0 a 5) para scripts, backups y tareas programadas.
- 🛡️ **Seguridad Avanzada Anti-Hackers**:
  - **Anti Path-Traversal**: Normalización y validación estricta de rutas con `safe_extract_path()`, bloqueando escrituras maliciosas fuera del directorio de destino (`../../`, rutas absolutas o letras de unidad).
  - **Anti Zip-Bomb / Compression-Bomb**: Límites automáticos de profundidades (máx. 50), límite de archivos (máx. 100,000) y comprobación de ratios de expansión anómalos.
- 🌐 **Internacionalización (i18n)**: Sistema centralizado de traducción en **Español** e **Inglés**, con selector de idioma en caliente desde Opciones.
- 🪟 **Integración Profunda con Windows**: Asociación automática de extensión `.ndac` y opciones en el menú contextual del Explorador de Windows (`Comprimir con NDAC`, `Comprimir carpeta con NDAC`, `Extraer con NDAC`).
- 🔄 **Compatibilidad Retroactiva Intacta**: Descomprime e inspecciona sin problemas archivos de versiones previas (**NDC3** y **NDC4**).

---

## 📐 Especificación Técnica del Formato Binario

NDAC soporta tres versiones de formato binario con detección automática transparente:

### 1. Formato NDC3 (Versión 3 — Archivo Único sin Cifrado)
- **Cabecera Binaria (`>4sBQIH` — 19 bytes)**:
  - `magic` (4 bytes): `b"NDC3"`
  - `version` (1 byte): `3`
  - `original_size` (8 bytes Q): Tamaño descompuesto en bytes
  - `crc32_checksum` (4 bytes I): Checksum CRC32 del contenido original
  - `filename_len` (2 bytes H): Longitud del nombre del archivo en UTF-8
  - `filename_bytes`: Nombre del archivo codificado en UTF-8
- **Payload**: Datos comprimidos con `zlib` (DEFLATE).

### 2. Formato NDC4 (Versión 4 — Archivo Único con Cifrado Opcional)
- **Cabecera Binaria (`>4sBB16sQIH32s` — 68 bytes)**:
  - `magic` (4 bytes): `b"NDC4"`
  - `version` (1 byte): `4`
  - `is_encrypted` (1 byte): `1` si incluye cifrado con clave, `0` sin clave
  - `salt` (16 bytes): Salt aleatorio criptográfico (`secrets.token_bytes(16)`)
  - `original_size` (8 bytes Q): Tamaño descompuesto en bytes
  - `crc32_checksum` (4 bytes I): Checksum CRC32 del contenido original
  - `filename_len` (2 bytes H): Longitud del nombre del archivo en UTF-8
  - `hmac_tag` (32 bytes): Tag HMAC-SHA256 para validación de clave e integridad
  - `filename_bytes`: Nombre del archivo codificado en UTF-8
- **Payload**: Datos comprimidos con `zlib` (DEFLATE), cifrados progresivamente mediante Keystream XOR determinista por bloque HMAC.

### 3. Formato NDC5 (Versión 5 — Múltiples Archivos y Carpetas)
- **Cabecera Binaria (`>4sBB16sQIIH32s` — 72 bytes)**:
  - `magic` (4 bytes): `b"NDC5"`
  - `version` (1 byte): `5`
  - `is_encrypted` (1 byte): `1` si está protegido con clave, `0` si no
  - `salt` (16 bytes): Salt criptográfico
  - `total_original_size` (8 bytes Q): Tamaño acumulado descompuesto
  - `total_files_count` (4 bytes I): Cantidad total de archivos y directorios contenidos
  - `crc32_checksum` (4 bytes I): Checksum CRC32 global del flujo del contenedor
  - `root_name_len` (2 bytes H): Longitud del nombre del contenedor raíz
  - `hmac_tag` (32 bytes): Tag HMAC-SHA256
  - `root_name_bytes`: Nombre de carpeta o paquete raíz en UTF-8
- **Estructura Interna del Payload DEFLATE**:
  Secuencia contigua de Entradas de Contenedor (**NDAC Package Entries**):
  - `entry_type` (1 byte B): `1` = Archivo, `2` = Directorio
  - `path_len` (2 bytes H): Longitud de la ruta relativa UTF-8 (ej: `sub/modulo.py`)
  - `file_size` (8 bytes Q): Tamaño del archivo (0 si es directorio)
  - `mtime` (8 bytes Q): Marca de tiempo Unix de modificación
  - `crc32` (4 bytes I): CRC32 individual del archivo
  - `path_bytes`: Ruta relativa UTF-8 (con separadores `/`)
  - `file_bytes`: `file_size` bytes de datos contiguos (si es archivo)

---

## 💻 Uso de la Línea de Comandos (CLI)

NDAC incluye una potente CLI para automatización y scripts:

### Comprimir archivos o carpetas
```bash
# Comprimir un archivo o carpeta
ndac compress Proyecto/

# Comprimir especificando archivo de salida y perfil de compresión máxima
ndac compress Proyecto/ -o respaldo.ndac -l 9

# Comprimir con protección por contraseña
ndac compress Proyecto/ -o respaldo.ndac -p MiClaveSegura

# Modo silencioso para scripts (sin logs en consola)
ndac compress Proyecto/ --quiet
```

### Descomprimir paquetes
```bash
# Descomprimir un paquete en el directorio actual
ndac extract respaldo.ndac

# Descomprimir en un directorio específico
ndac extract respaldo.ndac -o ./destino

# Descomprimir paquete protegido
ndac extract respaldo.ndac -p MiClaveSegura --quiet
```

### Validar archivo sin extraer
```bash
ndac validate respaldo.ndac -p MiClaveSegura
```

### Mostrar propiedades y metadatos
```bash
ndac info respaldo.ndac
```

### Códigos de Salida Estándar (Exit Codes)
| Código | Significado |
| :---: | :--- |
| **0** | Operación exitosa |
| **1** | Error general o inesperado |
| **2** | Archivo inválido, corrupto o no encontrado |
| **3** | Contraseña incorrecta o no provista |
| **4** | Operación cancelada por el usuario |
| **5** | Error de entrada/salida (I/O) o permisos |

---

## 📥 Instalación y Desarrollo

### Requisitos
- Windows 10/11
- Python 3.10 o superior

### Entorno de Desarrollo
```powershell
# Clonar repositorio
git clone https.github.com/Mako9162/comp.git
cd comp

# Crear entorno virtual e instalar dependencias
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# Iniciar aplicación gráfica
.\.venv\Scripts\python.exe main.py
```

### Generación del Ejecutable Portable e Instalador

Para generar la versión portable ejecutable `dist\CompresorArchivos.exe` e instalador de Windows:

```powershell
# Generar ejecutable portable
.\build_windows.ps1

# Generar ejecutable e instalador Inno Setup
.\build_windows.ps1 -Installer
```

---

## 🧪 Pruebas Automatizadas

El proyecto cuenta con una suite completa de 20 pruebas unitarias, de CLI, rendimiento y seguridad:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
