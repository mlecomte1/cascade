from __future__ import annotations

import io
import zlib

import pytest

from cascade.engine.errors import DecodeError
from cascade.engine.hexdump import to_hexdump
from cascade.engine.keys import parse_iv, parse_key
from cascade.engine.limits import MAX_IMAGE_EDGE
from cascade.engine.ops.ctf import from_jwt
from cascade.engine.ops.encodings import from_zlib, to_zlib
from cascade.engine.ops.modern import aes_run


def test_zlib_roundtrip_small() -> None:
    raw = b"cascade-zlib-ok"
    assert from_zlib(to_zlib(raw, {}), {}) == raw


def test_zlib_respects_max_bytes() -> None:
    payload = b"A" * 50_000
    compressed = zlib.compress(payload)
    with pytest.raises(DecodeError, match="trop volumineuse|too large"):
        from_zlib(compressed, {"max_bytes": 1024})


def test_aes_rejects_wrong_key_length() -> None:
    pytest.importorskip("Crypto")
    with pytest.raises(DecodeError, match="octets|bytes"):
        aes_run(
            b"x" * 16,
            {
                "key": "short",
                "key_format": "text",
                "bits": "128",
                "mode": "ECB",
                "decrypt": True,
            },
        )


def test_aes_cbc_requires_iv() -> None:
    pytest.importorskip("Crypto")
    params = {
        "key": "YELLOW SUBMARINE",
        "key_format": "text",
        "bits": "128",
        "mode": "CBC",
        "iv": "",
        "iv_in_ciphertext": False,
        "decrypt": False,
    }
    with pytest.raises(DecodeError, match="IV"):
        aes_run(b"hello cascade!!", params)


def test_aes_cbc_roundtrip_with_iv() -> None:
    pytest.importorskip("Crypto")
    params = {
        "key": "YELLOW SUBMARINE",
        "key_format": "text",
        "bits": "128",
        "mode": "CBC",
        "iv": "000102030405060708090a0b0c0d0e0f",
        "iv_in_ciphertext": False,
        "decrypt": False,
    }
    plain = b"hello cascade aes"
    cipher = aes_run(plain, params)
    opened = dict(params)
    opened["decrypt"] = True
    assert aes_run(cipher, opened) == plain


def test_aes_rejects_bad_padding() -> None:
    pytest.importorskip("Crypto")
    params = {
        "key": "YELLOW SUBMARINE",
        "key_format": "text",
        "bits": "128",
        "mode": "ECB",
        "decrypt": False,
    }
    cipher = aes_run(b"padding-check-ok", params)
    broken = cipher[:-1] + bytes([cipher[-1] ^ 0x7F])
    opened = dict(params)
    opened["decrypt"] = True
    with pytest.raises(DecodeError, match="Padding|padding"):
        aes_run(broken, opened)


def test_parse_iv_no_implicit_zeros() -> None:
    with pytest.raises(DecodeError, match="IV"):
        parse_iv({"iv": ""}, block=16)


def test_parse_key_rejects_odd_hex() -> None:
    with pytest.raises(DecodeError, match="impaire|odd"):
        parse_key({"key": "abc", "key_format": "hex"})


def test_parse_iv_rejects_odd_hex() -> None:
    with pytest.raises(DecodeError, match="impaire|odd"):
        parse_iv({"iv": "00112233445566778899aabbccddeef"}, block=16)


def test_jwt_warning_unverified() -> None:
    token = b"eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
    out = from_jwt(token, {})
    assert b'"verified": false' in out
    assert b"NON v" in out or b"NOT verified" in out or b"non v" in out.lower()


def test_hexdump_truncates() -> None:
    text = to_hexdump(b"\x00" * 80, limit=16)
    assert "truncated" in text
    assert text.count("\n") <= 3


def test_image_rejects_unknown_format() -> None:
    pytest.importorskip("PIL")
    from PIL import Image

    from cascade.engine.ops.images import lsb_extract

    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (1, 2, 3)).save(buf, format="TIFF")
    with pytest.raises(DecodeError, match="Format|format"):
        lsb_extract(buf.getvalue(), {"channels": "RGB", "stop_nul": True})


def test_image_rejects_oversize_edge() -> None:
    pytest.importorskip("PIL")
    from PIL import Image

    from cascade.engine.ops.images import lsb_extract

    buf = io.BytesIO()
    Image.new("RGB", (MAX_IMAGE_EDGE + 1, 8), (1, 2, 3)).save(buf, format="PNG")
    with pytest.raises(DecodeError, match="trop large|too large"):
        lsb_extract(buf.getvalue(), {"channels": "RGB", "stop_nul": True})
