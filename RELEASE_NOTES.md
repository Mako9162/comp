# NDAC v1.5.0 — Propuesta de Notas de Lanzamiento

Nos complace anunciar la publicación oficial de **NDAC v1.5.0 (Compresor y Protector de Archivos Ultra / NDC5)**, una herramienta profesional de compresión y protección de datos para Windows.

---

## 🚀 Novedades (Added)

- **Formato NDC5**: Compresión de directorios completos con subcarpetas, carpetas vacías y preservación de fechas de modificación (`mtime`).
- **Interfaz Gráfica Cyber Dark Glass**: Arrastrar y soltar (Drag & Drop) múltiple, tabla interactiva de selección, medidor de fortaleza de contraseña y métricas en tiempo real (Velocidad MB/s, ETA, Tamaños).
- **Línea de Comandos (CLI)**: Subcomandos `ndac compress`, `extract`, `validate`, `info`, `--quiet` y códigos de salida estándar (0 al 5) para scripts y automatización.
- **Integración con Explorador de Windows**: Asociación automática de extensión `.ndac` y comandos de menú contextual (`Comprimir con NDAC`, `Comprimir carpeta con NDAC`, `Extraer con NDAC`).
- **Internacionalización (i18n)**: Soporte centralizado en Español (`es`) e Inglés (`en`).

---

## 🔒 Seguridad (Security)

- **Protección por Contraseña**: PBKDF2-HMAC-SHA256 con 100,000 iteraciones y salt aleatorio criptográfico de 16 bytes.
- **Verificación HMAC en Tiempo Constante**: Uso estricto de `hmac.compare_digest()` para prevenir timing attacks.
- **Protección Anti Path-Traversal**: Normalización y bloqueo de escrituras maliciosas con `safe_extract_path()`.
- **Protección Anti Zip-Bomb**: Control de ratio de expansión y límites automáticos de recuento de elementos (máx. 100,000) y profundidades (máx. 50).
- **Validación Red Team**: Auditado exhaustivamente con 31 pruebas ofensivas de seguridad.

---

## ⚠️ Limitaciones Conocidas (Known Limitations)

- **Metadata de Nombre en Cabecera NDC4**: En el formato NDC4, el nombre del archivo expuesto en la cabecera fija no está incluido en el cálculo del digest HMAC. Un atacante con acceso binario al paquete puede alterar el nombre del archivo sin invalidar el HMAC. **Esta limitación no permite descifrar el contenido ni alterar el payload protegido**, y se conserva por motivos de compatibilidad retroactiva. Se solucionará en la versión futura **NDC6**.

---

## 📦 Artefactos de Distribución (Release Assets)

| Archivo | Descripción | Tamaño | SHA256 Checksum |
| :--- | :--- | :---: | :--- |
| **`CompresorArchivos.exe`** | Ejecutable Portable Standalone (Windows 10/11) | 35.6 MB | `EDF20ED7E4650D16B116DF22EEC0054A6B55C28ABDBFF843B694131016783A16` |
| **`CompresorArchivos-Setup.exe`** | Instalador de Windows (Inno Setup) | ~36 MB | *Generado con script ISS* |
| **`SHA256SUMS.txt`** | Firmas SHA256 verificables | < 1 KB | `EDF20ED7...` |
