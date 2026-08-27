# Politica de seguridad

## Alcance

El programa valida la cabecera, el tamano esperado y el CRC32 antes de publicar un archivo restaurado. Procesa los archivos por bloques y limita la descompresion al tamano declarado para reducir el riesgo de archivos maliciosos.

## Limitaciones importantes

- El formato `.ndac` **no cifra** los archivos y no requiere contrasena. No lo uses para proteger informacion confidencial.
- CRC32 detecta errores accidentales, pero no es una firma criptografica ni protege contra manipulacion intencionada.
- No abras archivos `.ndac` de origen no confiable si contienen datos que no deseas restaurar en tu equipo.

## Reportar problemas

No publiques vulnerabilidades con detalles explotables en los issues publicos. Contacta al mantenedor del repositorio de forma privada e incluye una reproduccion minima.
