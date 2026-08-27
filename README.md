# Compresor de Archivos Ultra (NDC4) 🚀

Aplicación de escritorio moderna y ultrarrápida para Windows que comprime, restaura y protege tus archivos sin pérdida. Procesamiento 100% local en tu equipo, con opción de cifrado de alta seguridad.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Repository](https://img.shields.io/badge/GitHub-Mako9162%2Fcomp-blue.svg)](https://github.com/Mako9162/comp.git)

---

## ✨ Características Principales

- 🔒 **Protección con Contraseña (NDC4)**: Cifrado autenticado de alta seguridad usando **PBKDF2-HMAC-SHA256** (100,000 iteraciones + Salt de 16 bytes). Sin la clave correcta, la descompresión se rechaza de inmediato.
- ⚡ **Compresión Streaming de 1 Solo Pase (1-Pass I/O)**: Optimización I/O que reduce a la mitad el tiempo de procesamiento en disco.
- 🎨 **Interfaz Ultra-Moderna (Cyber Dark Glass)**: Diseño visual limpio en PyQt6 con tarjetas de estadísticas en tiempo real, campo de contraseña con botón alternador (👁️), cancelación en vivo y consola de logs.
- 🛡️ **Seguridad Antihackers**: Sanitización de nombres de archivo contra ataques de *Path Traversal* (`../`) y validación estricta de formato y CRC32.
- 📂 **Compatibilidad de Formatos**: Genera archivos `.ndac` en formato **NDC4** y mantiene compatibilidad total de lectura para restaurar versiones anteriores (**NDC3**).

---

## 📥 Guía de Descarga e Instalación

### Para Usuarios de Windows (Descarga Directa)

1. Ve a la sección de **[Releases de GitHub](https://github.com/Mako9162/comp/releases)**.
2. Descarga el ejecutable `CompresorArchivos.exe` (Portátil) o el instalador `CompresorArchivos-Setup.exe`.
3. Ejecuta la aplicación y ¡listo! No requiere configuración previa.

---

## 📖 Modo de Uso

1. **Arrastra y suelta** cualquier archivo en la ventana principal o usa el botón **Examinar archivo**.
2. **Para comprimir**:
   - (Opcional) Introduce una contraseña si deseas proteger el archivo con cifrado.
   - Haz clic en **🚀 Iniciar proceso**. Se creará un archivo `.ndac` junto al original.
3. **Para descomprimir**:
   - Selecciona el archivo `.ndac`. Si está protegido con contraseña, la app te la solicitará automáticamente.
   - El archivo se restaurará conservando su contenido e integridad originales.

---

## 🔒 Seguridad y Privacidad

- Todos los archivos permanecen estrictamente en tu ordenador; **nada se sube a internet**.
- Para más información sobre los mecanismos de seguridad, consulta [SECURITY.md](SECURITY.md).

---

## 💻 Desarrollo y Compilación

Requisitos: Windows, Python 3.11 o superior.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

### Generar Ejecutable con Ícono `.exe`:

```powershell
.\build_windows.ps1
```

El ejecutable listo para distribución con ícono personalizado se generará en `dist\CompresorArchivos.exe`.

