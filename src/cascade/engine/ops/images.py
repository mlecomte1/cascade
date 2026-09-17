from __future__ import annotations

import io
from typing import Any

from cascade.engine.errors import DecodeError
from cascade.engine.limits import MAX_IMAGE_EDGE, MAX_IMAGE_PIXELS, MAX_MANUAL_BYTES
from cascade.engine.registry import Operation, has_op, register
from cascade.engine.types import ParamSpec

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None  # type: ignore[misc, assignment]
else:
    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

_ALLOWED_FORMATS = frozenset({"PNG", "JPEG", "WEBP", "BMP", "GIF"})


def _open_rgb(data: bytes) -> Any:
    if Image is None:
        raise DecodeError("Pillow n'est pas installé.", "Pillow is not installed.")
    try:
        image = Image.open(io.BytesIO(data))
        if image.format not in _ALLOWED_FORMATS:
            raise DecodeError(
                "Format d'image refusé (PNG/JPEG/WebP/BMP/GIF).",
                "Image format rejected (PNG/JPEG/WebP/BMP/GIF).",
            )
        width, height = image.size
        if width <= 0 or height <= 0:
            raise DecodeError("Image aux dimensions invalides.", "Image has invalid dimensions.")
        if width > MAX_IMAGE_EDGE or height > MAX_IMAGE_EDGE:
            raise DecodeError(
                f"Image trop large ({width}×{height}, max {MAX_IMAGE_EDGE} px).",
                f"Image too large ({width}×{height}, max {MAX_IMAGE_EDGE} px).",
            )
        if width * height > MAX_IMAGE_PIXELS:
            raise DecodeError(
                "Trop de pixels (plafond 4096×4096).",
                "Too many pixels (4096×4096 cap).",
            )
        image.load()
        return image.convert("RGB")
    except DecodeError:
        raise
    except Image.DecompressionBombError as exc:
        raise DecodeError("Image refusée (bombe de décompression).", "Image rejected (decompression bomb).") from exc
    except Exception as exc:
        raise DecodeError("Image illisible (PNG/JPEG/WebP/BMP).", "Unreadable image (PNG/JPEG/WebP/BMP).") from exc


def lsb_extract(data: bytes, params: dict[str, Any]) -> bytes:
    image = _open_rgb(data)
    channels = str(params.get("channels", "RGB"))
    stop_nul = bool(params.get("stop_nul", True))
    pixels = image.load()
    width, height = image.size
    out = bytearray()
    acc = 0
    nbits = 0

    def push(bit: int) -> bool:
        nonlocal acc, nbits
        acc = (acc << 1) | (bit & 1)
        nbits += 1
        if nbits < 8:
            return False
        out.append(acc)
        acc = 0
        nbits = 0
        if len(out) > MAX_MANUAL_BYTES:
            raise DecodeError("Extraction LSB trop volumineuse.", "LSB extract too large.")
        return stop_nul and out[-1] == 0

    for y in range(height):
        for x in range(width):
            red, green, blue = pixels[x, y][:3]
            if "R" in channels and push(red & 1):
                return bytes(out[:-1])
            if "G" in channels and push(green & 1):
                return bytes(out[:-1])
            if "B" in channels and push(blue & 1):
                return bytes(out[:-1])
    return bytes(out)


def from_qr(data: bytes, _params: dict[str, Any]) -> bytes:
    image = _open_rgb(data)
    try:
        import numpy as np
        import cv2
    except ImportError as exc:
        raise DecodeError(
            "opencv-python-headless n'est pas installé (lecture QR).",
            "opencv-python-headless is not installed (QR reading).",
        ) from exc
    array = np.array(image)
    detector = cv2.QRCodeDetector()
    payload, _points, _ = detector.detectAndDecode(array)
    if not payload:
        gray = cv2.cvtColor(array, cv2.COLOR_RGB2GRAY)
        payload, _points, _ = detector.detectAndDecode(gray)
    if not payload:
        raise DecodeError("Aucun QR code détecté.", "No QR code detected.")
    raw = payload.encode("utf-8")
    if len(raw) > MAX_MANUAL_BYTES:
        raise DecodeError("QR trop volumineux.", "QR payload too large.")
    return raw


def register_image_ops() -> None:
    if has_op("lsb_extract"):
        return
    register(
        Operation(
            id="lsb_extract",
            family="image",
            label_fr="Stégano LSB (extraction)",
            label_en="LSB stego (extract)",
            description_fr="Lit les bits de poids faible R/G/B. Ouvrir un fichier image, ne pas exécuter de payload.",
            description_en="Read least-significant R/G/B bits. Open an image file; do not execute payloads.",
            handler=lsb_extract,
            params=(
                ParamSpec(
                    "channels",
                    "choice",
                    "RGB",
                    "Canaux",
                    "Channels",
                    choices=("RGB", "R", "G", "B"),
                ),
                ParamSpec("stop_nul", "bool", True, "Arrêter au premier 0x00", "Stop at first 0x00"),
            ),
        )
    )
    register(
        Operation(
            id="from_qr",
            family="image",
            label_fr="QR code (lecture)",
            label_en="QR code (read)",
            description_fr="Lit un QR depuis un fichier image (PNG/JPEG).",
            description_en="Read a QR code from an image file (PNG/JPEG).",
            handler=from_qr,
        )
    )
