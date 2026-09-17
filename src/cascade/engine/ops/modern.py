from __future__ import annotations

from typing import Any

from cascade.engine.errors import DecodeError
from cascade.engine.keys import parse_iv, parse_key
from cascade.engine.registry import Operation, has_op, register
from cascade.engine.types import ParamSpec

try:
    from Crypto.Cipher import AES, ARC4, DES, DES3
    from Crypto.Util.Padding import pad, unpad
except ImportError:  # pragma: no cover
    AES = ARC4 = DES = DES3 = pad = unpad = None  # type: ignore[misc, assignment]


def _need_crypto() -> None:
    if AES is None:
        raise DecodeError(
            "pycryptodome n'est pas installé (AES/DES/RC4).",
            "pycryptodome is not installed (AES/DES/RC4).",
        )


def _require_key(raw: bytes, size: int) -> bytes:
    if len(raw) != size:
        raise DecodeError(
            f"Clé : {len(raw)} octets, attendu {size} (texte ou hex exact, sans hash).",
            f"Key is {len(raw)} bytes, expected {size} (exact text or hex, no hashing).",
        )
    return raw


def _pkcs7_unpad(data: bytes, block: int) -> bytes:
    if unpad is None:
        raise DecodeError("pycryptodome n'est pas installé.", "pycryptodome is not installed.")
    try:
        return unpad(data, block)
    except ValueError as exc:
        raise DecodeError(
            "Padding PKCS7 invalide (mauvaise clé, IV ou ciphertext).",
            "Invalid PKCS7 padding (wrong key, IV, or ciphertext).",
        ) from exc


def _split_iv(data: bytes, block: int, params: dict[str, Any]) -> tuple[bytes, bytes]:
    if params.get("iv_in_ciphertext"):
        if len(data) < block:
            raise DecodeError("Chiffrement trop court pour contenir l'IV.", "Ciphertext too short to hold IV.")
        return data[:block], data[block:]
    return parse_iv(params, block=block), data


def aes_run(data: bytes, params: dict[str, Any]) -> bytes:
    _need_crypto()
    bits = int(str(params.get("bits", 128)))
    if bits not in (128, 192, 256):
        bits = 128
    size = {128: 16, 192: 24, 256: 32}[bits]
    key = _require_key(parse_key(params), size)
    mode_name = str(params.get("mode", "CBC"))
    decrypt = bool(params.get("decrypt", True))
    block = AES.block_size
    if mode_name == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        if decrypt:
            return _pkcs7_unpad(cipher.decrypt(data), block)
        return cipher.encrypt(pad(data, block))
    iv, body = _split_iv(data, block, params) if decrypt else (parse_iv(params, block=block), data)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    if decrypt:
        return _pkcs7_unpad(cipher.decrypt(body), block)
    return cipher.encrypt(pad(body, block))


def des_run(data: bytes, params: dict[str, Any]) -> bytes:
    _need_crypto()
    key = _require_key(parse_key(params), 8)
    decrypt = bool(params.get("decrypt", True))
    mode_name = str(params.get("mode", "CBC"))
    block = DES.block_size
    if mode_name == "ECB":
        cipher = DES.new(key, DES.MODE_ECB)
        if decrypt:
            return _pkcs7_unpad(cipher.decrypt(data), block)
        return cipher.encrypt(pad(data, block))
    iv, body = _split_iv(data, block, params) if decrypt else (parse_iv(params, block=block), data)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    if decrypt:
        return _pkcs7_unpad(cipher.decrypt(body), block)
    return cipher.encrypt(pad(body, block))


def des3_run(data: bytes, params: dict[str, Any]) -> bytes:
    _need_crypto()
    raw = parse_key(params)
    if len(raw) == 16:
        key = raw
    else:
        key = _require_key(raw, 24)
    decrypt = bool(params.get("decrypt", True))
    mode_name = str(params.get("mode", "CBC"))
    block = DES3.block_size
    if mode_name == "ECB":
        cipher = DES3.new(key, DES3.MODE_ECB)
        if decrypt:
            return _pkcs7_unpad(cipher.decrypt(data), block)
        return cipher.encrypt(pad(data, block))
    iv, body = _split_iv(data, block, params) if decrypt else (parse_iv(params, block=block), data)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    if decrypt:
        return _pkcs7_unpad(cipher.decrypt(body), block)
    return cipher.encrypt(pad(body, block))


def rc4_run(data: bytes, params: dict[str, Any]) -> bytes:
    _need_crypto()
    key = parse_key(params)
    if not (1 <= len(key) <= 256):
        raise DecodeError("Clé RC4 : 1 à 256 octets.", "RC4 key must be 1–256 bytes.")
    return ARC4.new(key).encrypt(data)


_KEY = ParamSpec("key", "text", "", "Clé / mot de passe", "Key / password")
_FMT = ParamSpec("key_format", "choice", "text", "Format de clé", "Key format", choices=("text", "hex"))
_MODE = ParamSpec("mode", "choice", "CBC", "Mode", "Mode", choices=("CBC", "ECB"))
_IV = ParamSpec("iv", "text", "", "IV (hex, obligatoire en CBC)", "IV (hex, required for CBC)")
_IV_IN = ParamSpec("iv_in_ciphertext", "bool", False, "IV = 1er bloc du ciphertext", "IV is first ciphertext block")
_DEC = ParamSpec("decrypt", "bool", True, "Déchiffrer", "Decrypt")


def register_modern_ops() -> None:
    if has_op("aes"):
        return
    register(
        Operation(
            id="aes",
            family="cipher",
            label_fr="AES",
            label_en="AES",
            description_fr="AES-128/192/256 ECB/CBC. Clé de longueur exacte. IV hex obligatoire en CBC. Pas de bruteforce.",
            description_en="AES-128/192/256 ECB/CBC. Exact-length key. Hex IV required for CBC. No bruteforce.",
            handler=aes_run,
            params=(
                _KEY,
                _FMT,
                ParamSpec("bits", "choice", "128", "Taille de clé", "Key size", choices=("128", "192", "256")),
                _MODE,
                _IV,
                _IV_IN,
                _DEC,
            ),
        )
    )
    register(
        Operation(
            id="des",
            family="cipher",
            label_fr="DES",
            label_en="DES",
            description_fr="DES ECB/CBC, clé 8 octets exacte. IV hex obligatoire en CBC.",
            description_en="DES ECB/CBC, exact 8-byte key. Hex IV required for CBC.",
            handler=des_run,
            params=(_KEY, _FMT, _MODE, _IV, _IV_IN, _DEC),
        )
    )
    register(
        Operation(
            id="des3",
            family="cipher",
            label_fr="3DES",
            label_en="3DES",
            description_fr="Triple DES ECB/CBC, clé 16 ou 24 octets. IV hex obligatoire en CBC.",
            description_en="Triple DES ECB/CBC, 16- or 24-byte key. Hex IV required for CBC.",
            handler=des3_run,
            params=(_KEY, _FMT, _MODE, _IV, _IV_IN, _DEC),
        )
    )
    register(
        Operation(
            id="rc4",
            family="cipher",
            label_fr="RC4",
            label_en="RC4",
            description_fr="RC4 / ARC4 avec clé fournie (stream, réversible).",
            description_en="RC4 / ARC4 with a provided key (stream, reversible).",
            handler=rc4_run,
            params=(_KEY, _FMT),
            inverse_id="rc4",
        )
    )
