from __future__ import annotations

from cascade.engine.errors import DecodeError

_HEX = set("0123456789abcdefABCDEF")


def parse_key(params: dict, *, required: bool = True) -> bytes:
    raw = str(params.get("key", ""))
    if not raw:
        if required:
            raise DecodeError("Clé vide.", "Empty key.")
        return b""
    if params.get("key_format", "text") == "hex":
        hexed = "".join(ch for ch in raw if ch in _HEX)
        if len(hexed) % 2:
            raise DecodeError(
                "Clé hex de longueur impaire.",
                "Odd-length hex key.",
            )
        try:
            return bytes.fromhex(hexed)
        except ValueError as exc:
            raise DecodeError("Clé hex invalide.", "Invalid hex key.") from exc
    return raw.encode("utf-8")


def parse_iv(params: dict, *, block: int) -> bytes:
    raw = str(params.get("iv", "")).strip()
    if not raw:
        raise DecodeError(
            "IV CBC obligatoire (hex). Pas de zéros implicites.",
            "CBC IV is required (hex). No implicit zeros.",
        )
    hexed = "".join(ch for ch in raw if ch in _HEX)
    if len(hexed) % 2:
        raise DecodeError("IV hex de longueur impaire.", "Odd-length hex IV.")
    try:
        iv = bytes.fromhex(hexed)
    except ValueError as exc:
        raise DecodeError("IV hex invalide.", "Invalid hex IV.") from exc
    if len(iv) != block:
        raise DecodeError(
            f"IV : {len(iv)} octets, attendu {block}.",
            f"IV is {len(iv)} bytes, expected {block}.",
        )
    return iv
