# NDAC — Compresor y Protector de Archivos Ultra 🚀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Repository](https://img.shields.io/badge/GitHub-Mako9162%2Fcomp-blue.svg)](https://github.com/Mako9162/comp.git)
[![Version](https://img.shields.io/badge/Version-2.0.0-success.svg)](#)

**NDAC (File Compressor Ultra / NDC6)** es una herramienta profesional de compresión, protección e inspección de archivos y directorios para Windows. Diseñada bajo la filosofía:

> **"Simple para el usuario, potente por dentro."**

Procesamiento 100% local sin conexión a internet, soporte para carpetas completas y múltiples archivos, cifrado militar AEAD **AES-256-GCM**, derivación de claves memory-hard **Argon2id**, compresión ultra-rápida **Zstandard (zstd)**, interfaz gráfica moderna de arrastrar y soltar, y CLI completa para automatización.

---

## ✨ Características Principales

- 📦 **Compresión de Carpetas y Múltiples Archivos (Formato NDC6)**: Convierte estructuras complejas con subdirectorios, archivos y carpetas vacías en un único paquete `.ndac`, preservando nombres, jerarquías y fechas de modificación (`mtime`).
- 🔒 **Protección con Contraseña y Cifrado Autenticado AEAD (AES-256-GCM)**: Cifrado por bloques de 1 MB autenticados con Tag AEAD de 16B y Derivación Argon2id (64 MB RAM, 3 iteraciones) + HKDF-SHA256 para separación de subclaves.
- ⚡ **Compresión Ultra-Rápida Zstandard & Streaming**: Motor de compresión Zstandard (`zstd`) integrado que reduce de 3x a 5x los tiempos de procesamiento con consumo constante $O(1)$ de memoria RAM ($\sim 5$ MB).
- 🎨 **Interfaz Moderna Drag & Drop (Cyber Dark Glass)**: Zona intuitiva para arrastrar múltiples archivos/carpetas, tabla interactiva de selección, medidor de fortaleza de contraseña en tiempo real y estadísticas en vivo (Velocidad, ETA, Tamaños).
- 💻 **CLI Profesional para Automatización**: Invocación por línea de comandos (`ndac compress`, `extract`, `validate`, `info`) con modo silencioso `--quiet` y códigos de salida estándar (0 a 5) para scripts, backups y tareas programadas.
- 🛡️ **Seguridad Avanzada Anti-Hackers**:
  - **Anti Path-Traversal**: Normalización y validación estricta de rutas con `safe_extract_path()`, bloqueando escrituras maliciosas fuera del directorio de destino (`../../`, rutas absolutas o letras de unidad).
  - **Anti Zip-Bomb / Compression-Bomb**: Límites automáticos de profundidades (máx. 50), límite de archivos (máx. 100,000) y comprobación de ratios de expansión anómalos.
- 🌐 **Internacionalización (i18n)**: Sistema centralizado de traducción en **Español** e **Inglés**, con selector de idioma en caliente desde Opciones.
- 🪟 **Integración Profunda con Windows**: Asociación automática de extensión `.ndac` y opciones en el menú contextual del Explorador de Windows (`Comprimir con NDAC`, `Comprimir carpeta con NDAC`, `Extraer con NDAC`).
- 🔄 **Compatibilidad Retroactiva Intacta**: Descomprime e inspecciona sin problemas archivos de versiones previas (**NDC3**, **NDC4** y **NDC5**).

---

## 🛠️ Instalación y Uso

### Ejecutable Standalone (Windows)
Descarga `CompresorArchivos.exe` desde la sección de releases y ejecútalo directamente (sin requerir instalación de Python).

### Desde Línea de Comandos (CLI)
```bash
# Comprimir archivos/carpetas
ndac compress archivo1.txt carpeta/ -o paquete.ndac -p "MiContrasena"

# Extraer contenido
ndac extract paquete.ndac -o ./destino -p "MiContrasena"

# Validar integridad sin extraer a disco
ndac validate paquete.ndac -p "MiContrasena"
```
