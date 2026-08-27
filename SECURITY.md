# Politica de Seguridad

## Alcance y Proteccion

El programa soporta compresion sin perdida y cifrado opcional de alta seguridad para archivos `.ndac` bajo el estandar **NDC4**:

1. **Cifrado de Datos y Autenticacion**:
   - Cuando se asigna una contrasena, el archivo se protege mediante **PBKDF2-HMAC-SHA256** con **100,000 iteraciones** y un **Salt aleatorio de 16 bytes** por archivo.
   - Incluye una firma de autenticacion **HMAC-SHA256** de 32 bytes en la cabecera. Si la contrasena introducida es incorrecta o los datos fueron alterados, la descompresion se cancela de forma inmediata sin modificar ningun archivo en el disco.
2. **Proteccion contra Path Traversal**:
   - Los nombres de archivo almacenados en la cabecera son sanitizados automaticamente al descomprimir para evitar que se escriban fuera de la carpeta de destino.
3. **Validacion de Integridad**:
   - Todos los archivos verifican la suma de comprobacion **CRC32** e imponen un limite de seguridad en el tamano declarado antes de completar la restauracion.

## Buenas Practicas de Seguridad

- **Fortaleza de la contrasena**: Utiliza contrasenas fuertes y unicas para proteger archivos confidenciales. Sin la clave correcta, el descifrado es matematicamente inviable.
- **Archivos de fuentes no confiables**: Al restaurar archivos `.ndac` descargados de internet, asegurate de verificar su origen antes de abrirlos.

## Reportar Problemas

Si descubres un problema de seguridad o vulnerabilidad, no publiques detalles explotables en los issues publicos de GitHub. Contacta de forma privada al mantenedor del repositorio incluyendo una reproduccion minima.

