import sys
import os
sys.path.insert(0, os.path.abspath("."))
import shutil
import tempfile
import hashlib
from src.formats.ndc6 import compress_ndc6, decompress_ndc6, validate_ndc6
from src.formats import detect_format

def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def run_e2e_test():
    base_dir = tempfile.mkdtemp(prefix="ndac_e2e_rc_")
    out_dir = tempfile.mkdtemp(prefix="ndac_e2e_out_")
    archive = os.path.join(base_dir, "rc_test.ndac")
    password = "RC_V2_0_0_Strict_Password!🔒"

    print("=== NDAC v2.0.0 END-TO-END VERIFICATION ===")

    # 1. Crear estructura rica de prueba
    f_small = os.path.join(base_dir, "small.txt")
    with open(f_small, "wb") as f:
        f.write(b"Small text file content\n")

    f_large = os.path.join(base_dir, "large_5mb.bin")
    with open(f_large, "wb") as f:
        f.write(os.urandom(1024 * 1024 * 5))

    f_empty = os.path.join(base_dir, "empty_file.dat")
    open(f_empty, "wb").close()

    f_space = os.path.join(base_dir, "file with spaces in name.csv")
    with open(f_space, "wb") as f:
        f.write(b"id,name,value\n1,test,100\n")

    f_unicode = os.path.join(base_dir, "documento_español_日本語_🔑.json")
    with open(f_unicode, "wb") as f:
        f.write('{"key": "value_unicode_áéíóú"}'.encode("utf-8"))

    subfolder = os.path.join(base_dir, "nested_dir")
    os.makedirs(subfolder, exist_ok=True)
    f_sub = os.path.join(subfolder, "deep_file.log")
    with open(f_sub, "wb") as f:
        f.write(b"Deep nested log data\n" * 500)

    sources = [f_small, f_large, f_empty, f_space, f_unicode, subfolder]

    # Map de digests originales
    orig_digests = {}
    for src in [f_small, f_large, f_empty, f_space, f_unicode, f_sub]:
        rel = os.path.relpath(src, base_dir)
        orig_digests[rel] = file_sha256(src)

    print(f"[1] Compresion de {len(sources)} elementos hacia '{os.path.basename(archive)}'...")
    comp_res = compress_ndc6(sources, archive, password=password)
    print(f"    Formato: {comp_res['format']} | Compresion Ratio: {comp_res['compression_ratio']:.1f}%")

    print("[2] Deteccion de formato del contenedor binario...")
    detected_fmt = detect_format(archive)
    print(f"    Formato detectado ID: {detected_fmt}")
    assert detected_fmt in (6, "NDC6"), f"Error: Formato esperado NDC6/6, detectado {detected_fmt}"

    print("[3] Validando integridad AEAD de contenedor sin escribir a disco...")
    val_ok = validate_ndc6(archive, password=password)
    assert val_ok is True, "Error: validate_ndc6 retorno False"
    print("    Validacion de firmas AEAD: OK")

    print("[4] Descompresion y restauracion en disco...")
    decomp_res = decompress_ndc6(archive, out_dir, password=password)
    print(f"    Elementos restaurados: {decomp_res['files_extracted']}")

    print("[5] Verificacion SHA-256 byte a byte...")
    all_matched = True
    for rel_p, orig_hash in orig_digests.items():
        rest_path = os.path.join(out_dir, rel_p)
        safe_rel_display = rel_p.encode('ascii', 'replace').decode('ascii')
        if not os.path.exists(rest_path):
            print(f"    [FAIL] Archivo restaurado faltante: {safe_rel_display}")
            all_matched = False
            continue
        rest_hash = file_sha256(rest_path)
        if orig_hash == rest_hash:
            print(f"    [OK] MATCH: {safe_rel_display} ({orig_hash[:12]}...)")
        else:
            print(f"    [FAIL] MISMATCH: {safe_rel_display} (orig {orig_hash[:12]}... != rest {rest_hash[:12]}...)")
            all_matched = False

    shutil.rmtree(base_dir, ignore_errors=True)
    shutil.rmtree(out_dir, ignore_errors=True)

    if all_matched:
        print("\n>>> E2E RESULT: ORIGINAL == EXTRACTED (BYTE-BY-BYTE MATCH SUCCESSFUL) <<<")
    else:
        print("\n>>> E2E RESULT: FAILED <<<")

if __name__ == "__main__":
    run_e2e_test()
