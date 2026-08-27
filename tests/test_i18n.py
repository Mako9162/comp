import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.utils.i18n import TRANSLATIONS, tr


class TestI18n(unittest.TestCase):
    def test_translations_keys_parity(self):
        es_keys = set(TRANSLATIONS["es"].keys())
        en_keys = set(TRANSLATIONS["en"].keys())

        missing_in_en = es_keys - en_keys
        missing_in_es = en_keys - es_keys

        self.assertEqual(len(missing_in_en), 0, f"Claves faltantes en ingles (en): {missing_in_en}")
        self.assertEqual(len(missing_in_es), 0, f"Claves faltantes en espanol (es): {missing_in_es}")

    def test_tr_function_fallbacks(self):
        self.assertEqual(tr("btn_validate", "es"), "🔍 Validar")
        self.assertEqual(tr("btn_validate", "en"), "🔍 Validate")

        # Clave inexistente retorna la misma clave
        self.assertEqual(tr("non_existent_key", "es"), "non_existent_key")

        # Idioma no soportado utiliza español como fallback
        self.assertEqual(tr("btn_validate", "fr"), "🔍 Validar")


if __name__ == "__main__":
    unittest.main()
