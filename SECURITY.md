# Política de Seguridad — NDAC v1.5.0

## Alcance y Protección

El programa soporta compresión sin pérdida, archivado multielemento (carpetas y múltiples archivos) y cifrado opcional de alta seguridad para archivos `.ndac` bajo las especificaciones **NDC4** y **NDC5**:

1. **Cifrado de Datos y Autenticación Criptográfica**:
   - Protección por contraseña con derivación de claves mediante **PBKDF2-HMAC-SHA256** (100,000 iteraciones + Salt criptográfico aleatorio de 16 bytes por paquete `secrets.token_bytes(16)`).
   - Firma de autenticación **HMAC-SHA256** de 32 bytes en la cabecera del contenedor.
   - Verificación de la firma HMAC en **tiempo constante** con `hmac.compare_digest()` para prevenir ataques de temporización (timing attacks).
   - Reclusión e interrupción inmediata si la clave es incorrecta o el archivo ha sido alterado, sin realizar escrituras intermedias a disco.

2. **Protección Anti Path-Traversal**:
   - Sanitización estricta de rutas con `safe_extract_path()`.
   - Bloqueo de escrituras fuera del directorio de destino (`../../`, `C:\`, `/var/`, secuencias de escape y nombres reservados en Windows como `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
   - Límite máximo de profundidad de subcarpetas anidadas (`MAX_PATH_DEPTH = 50`).

3. **Protección Anti Compression-Bomb / Zip-Bomb**:
   - Verificación de consistencia entre el tamaño total declarado en cabecera y la suma de elementos descompuestos.
   - Control de ratio de expansión anómalo y límite máximo en la cantidad de elementos contenidos (`MAX_TOTAL_FILES = 100,000`).

4. **Validación de Integridad CRC32**:
   - Verificación de suma de comprobacion **CRC32** individual por archivo y global del contenedor en streaming progresivo.

---

## Reportar Problemas de Seguridad

Si descubres una vulnerabilidad o problema de seguridad, no publiques detalles exploitables en los issues públicos de GitHub. Contacta de forma privada al mantenedor del repositorio adjuntando un caso de reproducción mínimo.
