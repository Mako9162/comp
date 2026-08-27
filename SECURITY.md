# Política de Seguridad — NDAC v1.5.0

## Alcance y Protección

El programa soporta compresión sin pérdida, archivado multielemento (carpetas y múltiples archivos) y cifrado opcional para archivos `.ndac` bajo las especificaciones **NDC4** y **NDC5**:

1. **Cifrado de Datos y Autenticación Criptográfica**:
   - Protección por contraseña con derivación de claves mediante **PBKDF2-HMAC-SHA256** (100,000 iteraciones + Salt criptográfico aleatorio de 16 bytes por paquete `secrets.token_bytes(16)`).
   - Firma de autenticación **HMAC-SHA256** de 32 bytes en la cabecera del contenedor.
   - Verificación de la firma HMAC en **tiempo constante** con `hmac.compare_digest()` para prevenir ataques de temporización (timing attacks).
   - Interrupción inmediata si la clave es incorrecta o el archivo ha sido alterado, sin realizar escrituras intermedias a disco.

2. **Protección Anti Path-Traversal**:
   - Sanitización estricta de rutas con `safe_extract_path()`.
   - Bloqueo de escrituras fuera del directorio de destino (`../../`, `C:\`, `/var/`, secuencias de escape y nombres reservados en Windows como `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
   - Límite máximo de profundidad de subcarpetas anidadas (`MAX_PATH_DEPTH = 50`).

3. **Protección Anti Compression-Bomb / Zip-Bomb**:
   - Verificación de consistencia entre el tamaño total declarado en cabecera y la suma de elementos descompuestos.
   - Control de ratio de expansión anómalo y límite máximo en la cantidad de elementos contenidos (`MAX_TOTAL_FILES = 100,000`).

4. **Validación de Integridad CRC32**:
   - Verificación de suma de comprobación **CRC32** individual por archivo y global del contenedor en streaming progresivo.

---

## Limitaciones Conocidas / Known Limitations

### NDC4 Header Filename Metadata Unauthenticated
El metadato del nombre de archivo (`filename_bytes`) en la cabecera del formato NDC4 no está incluido en el cálculo del digest del HMAC actual.

Un atacante que posea acceso de modificación binaria al contenedor puede cambiar el nombre del archivo almacenado en la cabecera NDC4 sin conocer la contraseña.

**Esta limitación NO permite:**
- Descifrar el contenido del archivo.
- Modificar los datos del payload descompuesto.
- Recuperar la contraseña o claves derivadas.
- Escapar del directorio de extracción (Path Traversal).
- Modificar los nombres ni la estructura interna de contenedores multielemento **NDC5** (donde todos los nombres viven dentro del payload cifrado autenticado).

Esta limitación se conserva por motivos de compatibilidad retroactiva con versiones anteriores de NDC4 y está planificada para su resolución en un formato de contenedor autenticado futuro (**NDC6**).

---

## Reportar Problemas de Seguridad

Si descubres una vulnerabilidad o problema de seguridad, no publiques detalles explotables en los issues públicos de GitHub. Contacta de forma privada al mantenedor del repositorio adjuntando un caso de reproducción mínimo.
