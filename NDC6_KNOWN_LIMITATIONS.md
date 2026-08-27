# LIMITACIONES CONOCIDAS — NDAC v2.0.0 (NDC6)

Este documento registra formalmente las limitaciones arquitectónicas y comportamientos esperados en NDAC v2.0.0.

---

## 1. LIMITACIÓN CONOCIDA VULN-V2-01 (FORMATO NDC4 LEGACY)

- **Componente**: `src/engine/compressor.py` / Formato binario NDC4.
- **Descripción**: En archivos NDC4 antiguos (generados con NDAC v1.0.0 / v1.5.0), el campo `filename` de la cabecera fija de 64 bytes no está incluido en el cálculo del HMAC SHA-256 de autenticación.
- **Impacto**: Un atacante sin la contraseña puede modificar los bytes del nombre de archivo en la cabecera de un archivo `.ndac` en formato NDC4 sin invalidar la autenticación HMAC.
- **Estado en NDC6**: **RESUELTO**. En el nuevo formato **NDC6**, toda la metadata (incluyendo nombres de archivo, rutas relativas y estructuras de directorio) se comprime y se cifra con AES-256-GCM y `Metadata Key`, además de autenticarse el AAD de cabecera.

---

## 2. FORMATOS CONGELADOS E INMUTABLES (NDC3, NDC4, NDC5)

- **Componente**: `src/engine/` y `src/formats/legacy.py`.
- **Descripción**: Los formatos binarios NDC3, NDC4 y NDC5 han alcanzado el estado de congelamiento binario (Feature Freeze).
- **Consecuencia**: No se aplicarán cambios de formato ni modificaciones estructurales sobre contenedores legados para preservar la compatibilidad total de descompresión hacia atrás.
