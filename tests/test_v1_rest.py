from __future__ import annotations

import io

import pytest

from cascade.engine.ops.ciphers import xor_brute2, xor_bytes, xor_wordlist
from cascade.engine.ops.ctf import js_beautify
from cascade.engine.ops.images import lsb_extract
from cascade.engine.ops.modern import aes_run, rc4_run


def _aes_params(decrypt: bool) -> dict:
    return {
        "key": "YELLOW SUBMARINE",
        "key_format": "text",
        "bits": "128",
        "mode": "ECB",
        "iv": "",
        "iv_in_ciphertext": False,
        "decrypt": decrypt,
    }


def test_aes_ecb_roundtrip() -> None:
    pytest.importorskip("Crypto")
    plain = b"cascade-offline-aes"
    cipher = aes_run(plain, _aes_params(False))
    assert aes_run(cipher, _aes_params(True)) == plain


def test_rc4_roundtrip() -> None:
    pytest.importorskip("Crypto")
    plain = b"stream-cipher-payload"
    xored = rc4_run(plain, {"key": "secret", "key_format": "text"})
    assert rc4_run(xored, {"key": "secret", "key_format": "text"}) == plain


def test_xor_wordlist_finds_builtin() -> None:
    xored = xor_bytes(b"hello-cascade", {"key": "flag", "key_format": "text"})
    report = xor_wordlist(xored, {"extra_keys": "", "top": 12}).decode()
    assert "flag" in report


def test_xor_brute2_finds_short_key() -> None:
    xored = xor_bytes(b"Hello World from Cascade!!", {"key": "ab", "key_format": "text"})
    report = xor_brute2(xored, {"top": 8}).decode()
    assert "6162" in report.lower() or "ab" in report.lower()


def test_js_beautify_indents() -> None:
    out = js_beautify(b"function x(){return 1;}", {}).decode()
    assert "{" in out
    assert "\n" in out
    assert "return 1;" in out


def test_lsb_extract_roundtrip() -> None:
    pytest.importorskip("PIL")
    from PIL import Image

    message = b"hidden"
    bits: list[int] = []
    for byte in message + b"\x00":
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    width = 32
    height = 32
    image = Image.new("RGB", (width, height), (10, 20, 30))
    pixels = image.load()
    index = 0
    for y in range(height):
        for x in range(width):
            red, green, blue = pixels[x, y][:3]
            if index < len(bits):
                red = (red & 0xFE) | bits[index]
                index += 1
            if index < len(bits):
                green = (green & 0xFE) | bits[index]
                index += 1
            if index < len(bits):
                blue = (blue & 0xFE) | bits[index]
                index += 1
            pixels[x, y] = (red, green, blue)
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    assert lsb_extract(buf.getvalue(), {"channels": "RGB", "stop_nul": True}) == message


def test_qr_rejects_blank_image() -> None:
    pytest.importorskip("cv2")
    pytest.importorskip("PIL")
    from PIL import Image

    from cascade.engine.errors import DecodeError
    from cascade.engine.ops.images import from_qr

    buf = io.BytesIO()
    Image.new("RGB", (48, 48), (255, 255, 255)).save(buf, format="PNG")
    with pytest.raises(DecodeError):
        from_qr(buf.getvalue(), {})
