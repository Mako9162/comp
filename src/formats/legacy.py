from typing import Optional, Callable, Dict, Any
from ..engine.compressor import decompress as decompress_legacy, validate_archive as validate_legacy

def decompress_ndc_legacy(
    input_path: str,
    output_path: str,
    password: Optional[str] = None,
    progress_callback: Optional[Callable[[int, str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Adaptador transparente hacia el motor legacy NDC3/NDC4/NDC5."""
    return decompress_legacy(
        input_path,
        output_path,
        password=password,
        progress_callback=progress_callback,
        cancel_callback=cancel_callback,
    )
