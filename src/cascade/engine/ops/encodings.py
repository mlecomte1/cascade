from __future__ import annotations

import base64
import binascii
import re
from typing import Any
from urllib.parse import quote, unquote_to_bytes

from cascade.engine.errors import DecodeError
from cascade.engine.registry import Operation, register
from cascade.engine.types import ParamSpec

_WHITESPACE = re.compile(br"\s+")
_HEX_NOISE = re.compile(br"[^0-9A-Fa-f]")
_OX_PREFIX = re.compile(br"(?i)0x")
_OX_BYTE = re.compile(br"(?i)(?:0x|\\x)([0-9A-Fa-f]{2})")
_BINARY_BITS = re.compile(br"[^01]")

B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {char: index for index, char in enumerate(B58_ALPHABET)}

MORSE_TABLE = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    ".": ".-.-.-",
    ",": "--..--",
    "?": "..--..",
    "'": ".----.",
    "!": "-.-.--",
    "/": "-..-.",
    "(": "-.--.",
    ")": "-.--.-",
    "&": ".-...",
    ":": "---...",
    ";": "-.-.-.",
    "=": "-...-",
    "+": ".-.-.",
    "-": "-....-",
    "_": "..--.-",
    '"': ".-..-.",
    "$": "...-..-",
    "@": ".--.-.",
    " ": "/",
}
MORSE_REVERSE = {code: char for char, code in MORSE_TABLE.items() if char != " "}


def _as_ascii(data: bytes) -> str:
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DecodeError(
            "Cette opération attend du texte ASCII.",
            "This operation expects ASCII text.",
        ) from exc


def _strip_ws(data: bytes) -> bytes:
    return _WHITESPACE.sub(b"", data)


def from_base64(data: bytes, params: dict[str, Any]) -> bytes:
    raw = _strip_ws(data)
    if params.get("url_safe"):
        raw = raw.replace(b"-", b"+").replace(b"_", b"/")
    pad = (-len(raw)) % 4
    raw += b"=" * pad
    try:
        return base64.b64decode(raw, validate=bool(params.get("validate", False)))
    except binascii.Error as exc:
        raise DecodeError("Base64 invalide.", "Invalid Base64.") from exc


def to_base64(data: bytes, params: dict[str, Any]) -> bytes:
    encoded = base64.b64encode(data)
    if params.get("url_safe"):
        encoded = encoded.replace(b"+", b"-").replace(b"/", b"_")
        if not params.get("padding", True):
            encoded = encoded.rstrip(b"=")
    elif not params.get("padding", True):
        encoded = encoded.rstrip(b"=")
    return encoded


def from_base32(data: bytes, _params: dict[str, Any]) -> bytes:
    raw = _strip_ws(data).upper()
    pad = (-len(raw)) % 8
    raw += b"=" * pad
    try:
        return base64.b32decode(raw, casefold=True)
    except binascii.Error as exc:
        raise DecodeError("Base32 invalide.", "Invalid Base32.") from exc


def to_base32(data: bytes, _params: dict[str, Any]) -> bytes:
    return base64.b32encode(data)


def from_base32hex(data: bytes, _params: dict[str, Any]) -> bytes:
    raw = _strip_ws(data).upper()
    pad = (-len(raw)) % 8
    raw += b"=" * pad
    try:
        return base64.b32hexdecode(raw, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError("Base32hex invalide.", "Invalid Base32hex.") from exc


def to_base32hex(data: bytes, _params: dict[str, Any]) -> bytes:
    return base64.b32hexencode(data)


def from_base85(data: bytes, params: dict[str, Any]) -> bytes:
    raw = _strip_ws(data)
    variant = params.get("variant", "ascii85")
    try:
        if variant == "rfc1924":
            return base64.b85decode(raw)
        return base64.a85decode(raw, adobe=params.get("adobe", False), ignorechars=b" \t\n\r")
    except (ValueError, binascii.Error) as exc:
        raise DecodeError("Base85 invalide.", "Invalid Base85.") from exc


def to_base85(data: bytes, params: dict[str, Any]) -> bytes:
    variant = params.get("variant", "ascii85")
    if variant == "rfc1924":
        return base64.b85encode(data)
    return base64.a85encode(data, adobe=params.get("adobe", False))


def _b58encode(data: bytes) -> bytes:
    if not data:
        return b""
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    value = int.from_bytes(data, "big")
    out = bytearray()
    while value > 0:
        value, rem = divmod(value, 58)
        out.append(B58_ALPHABET[rem])
    out.extend(b"1" * pad)
    out.reverse()
    return bytes(out) if out else b"1" * pad


def _b58decode(data: bytes) -> bytes:
    raw = _strip_ws(data)
    if not raw:
        return b""
    pad = 0
    for byte in raw:
        if byte == 49:  # '1'
            pad += 1
        else:
            break
    value = 0
    for byte in raw:
        try:
            value = value * 58 + _B58_INDEX[byte]
        except KeyError as exc:
            raise DecodeError("Base58 invalide.", "Invalid Base58.") from exc
    if value == 0:
        body = b""
    else:
        length = (value.bit_length() + 7) // 8
        body = value.to_bytes(length, "big")
    return b"\x00" * pad + body


def from_base58(data: bytes, _params: dict[str, Any]) -> bytes:
    return _b58decode(data)


def to_base58(data: bytes, _params: dict[str, Any]) -> bytes:
    return _b58encode(data)


def from_hex(data: bytes, _params: dict[str, Any]) -> bytes:
    blob = data.replace(b"\xc2\xa0", b" ").replace(b"\t", b" ")
    pairs = _OX_BYTE.findall(blob)
    leftover = _HEX_NOISE.sub(b"", _OX_BYTE.sub(b"", blob))
    if len(pairs) >= 2 and not leftover:
        return bytes(int(part, 16) for part in pairs)
    raw = _OX_PREFIX.sub(b"", blob.strip())
    raw = raw.replace(b"\\x", b"")
    raw = _HEX_NOISE.sub(b"", raw)
    if len(raw) % 2:
        raw = b"0" + raw
    try:
        return binascii.unhexlify(raw)
    except binascii.Error as exc:
        raise DecodeError("Hexadécimal invalide.", "Invalid hexadecimal.") from exc


def to_hex(data: bytes, params: dict[str, Any]) -> bytes:
    sep = params.get("separator", "none")
    hexed = binascii.hexlify(data).upper()
    if sep == "space":
        hexed = b" ".join(hexed[i : i + 2] for i in range(0, len(hexed), 2))
    elif sep == "colon":
        hexed = b":".join(hexed[i : i + 2] for i in range(0, len(hexed), 2))
    if params.get("prefix"):
        hexed = b"0x" + hexed
    return hexed


def from_decimal(data: bytes, _params: dict[str, Any]) -> bytes:
    parts = data.strip().replace(b",", b" ").split()
    if not parts:
        raise DecodeError("Décimal vide.", "Empty decimal.")
    out = bytearray()
    for part in parts:
        try:
            value = int(part)
        except ValueError as exc:
            raise DecodeError("Octets décimaux invalides.", "Invalid decimal bytes.") from exc
        if not 0 <= value <= 255:
            raise DecodeError("Octet décimal hors 0–255.", "Decimal byte out of 0–255.")
        out.append(value)
    return bytes(out)


def to_decimal(data: bytes, _params: dict[str, Any]) -> bytes:
    return b" ".join(str(byte).encode("ascii") for byte in data)


def from_zlib(data: bytes, params: dict[str, Any]) -> bytes:
    import zlib

    from cascade.engine.limits import MAX_MANUAL_BYTES

    cap = int(params.get("max_bytes") or MAX_MANUAL_BYTES)
    cap = max(1, min(cap, MAX_MANUAL_BYTES))
    last: Exception | None = None
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 16):
        try:
            decoder = zlib.decompressobj(wbits)
            out = decoder.decompress(data, cap)
            if not decoder.eof:
                raise DecodeError(
                    f"Décompression trop volumineuse (plafond {cap} octets).",
                    f"Decompression too large ({cap} byte cap).",
                )
            return out
        except DecodeError:
            raise
        except zlib.error as exc:
            last = exc
    raise DecodeError("Zlib/gzip invalide.", "Invalid zlib/gzip.") from last


def to_zlib(data: bytes, _params: dict[str, Any]) -> bytes:
    import zlib

    return zlib.compress(data)


def url_decode(data: bytes, _params: dict[str, Any]) -> bytes:
    return unquote_to_bytes(data.decode("ascii", errors="latin-1"))


def url_encode(data: bytes, params: dict[str, Any]) -> bytes:
    safe = params.get("safe", "")
    return quote(data, safe=safe).encode("ascii")


def from_binary(data: bytes, _params: dict[str, Any]) -> bytes:
    bits = _BINARY_BITS.sub(b"", _strip_ws(data))
    if not bits:
        return b""
    pad = (-len(bits)) % 8
    bits = (b"0" * pad) + bits
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def to_binary(data: bytes, params: dict[str, Any]) -> bytes:
    grouped = bool(params.get("grouped", True))
    chunks = [f"{byte:08b}" for byte in data]
    joined = " ".join(chunks) if grouped else "".join(chunks)
    return joined.encode("ascii")


def _rot_bytes(data: bytes, shift: int) -> bytes:
    shift %= 26
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        if 65 <= byte <= 90:
            out[i] = 65 + (byte - 65 + shift) % 26
        elif 97 <= byte <= 122:
            out[i] = 97 + (byte - 97 + shift) % 26
        else:
            out[i] = byte
    return bytes(out)


def rot13(data: bytes, _params: dict[str, Any]) -> bytes:
    return _rot_bytes(data, 13)


def rot_n(data: bytes, params: dict[str, Any]) -> bytes:
    return _rot_bytes(data, int(params.get("n", 13)))


def from_morse(data: bytes, _params: dict[str, Any]) -> bytes:
    text = _as_ascii(data).strip().replace("|", "/")
    if not text:
        return b""
    words: list[str] = []
    for word in re.split(r"(?:\s*/\s*|\s{3,})", text):
        letters: list[str] = []
        for token in word.split():
            if not token:
                continue
            letter = MORSE_REVERSE.get(token)
            if letter is None:
                raise DecodeError(
                    f"Symbole Morse inconnu : {token}",
                    f"Unknown Morse token: {token}",
                )
            letters.append(letter)
        words.append("".join(letters))
    return " ".join(words).encode("ascii")


def to_morse(data: bytes, _params: dict[str, Any]) -> bytes:
    text = _as_ascii(data).upper()
    encoded: list[str] = []
    for char in text:
        if char == " ":
            encoded.append("/")
            continue
        code = MORSE_TABLE.get(char)
        if code is None:
            raise DecodeError(
                f"Caractère non Morse : {char!r}",
                f"Character has no Morse mapping: {char!r}",
            )
        encoded.append(code)
    return " ".join(encoded).encode("ascii")


def from_utf16le(data: bytes, _params: dict[str, Any]) -> bytes:
    if len(data) % 2:
        raise DecodeError("UTF-16 LE : longueur impaire.", "UTF-16 LE: odd length.")
    try:
        return data.decode("utf-16-le").encode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("UTF-16 LE invalide.", "Invalid UTF-16 LE.") from exc


def to_utf16le(data: bytes, _params: dict[str, Any]) -> bytes:
    return data.decode("utf-8", errors="surrogateescape").encode("utf-16-le")


def from_utf16be(data: bytes, _params: dict[str, Any]) -> bytes:
    if len(data) % 2:
        raise DecodeError("UTF-16 BE : longueur impaire.", "UTF-16 BE: odd length.")
    try:
        return data.decode("utf-16-be").encode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError("UTF-16 BE invalide.", "Invalid UTF-16 BE.") from exc


def to_utf16be(data: bytes, _params: dict[str, Any]) -> bytes:
    return data.decode("utf-8", errors="surrogateescape").encode("utf-16-be")


def from_latin1(data: bytes, _params: dict[str, Any]) -> bytes:
    return data.decode("latin-1").encode("utf-8")


def to_latin1(data: bytes, _params: dict[str, Any]) -> bytes:
    try:
        return data.decode("utf-8").encode("latin-1")
    except UnicodeError as exc:
        raise DecodeError(
            "Impossible d'encoder en Latin-1.",
            "Cannot encode as Latin-1.",
        ) from exc


def reverse_bytes(data: bytes, _params: dict[str, Any]) -> bytes:
    return data[::-1]


def atbash(data: bytes, _params: dict[str, Any]) -> bytes:
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        if 65 <= byte <= 90:
            out[i] = 90 - (byte - 65)
        elif 97 <= byte <= 122:
            out[i] = 122 - (byte - 97)
        else:
            out[i] = byte
    return bytes(out)


def rot47(data: bytes, _params: dict[str, Any]) -> bytes:
    """Rotate printable ASCII 33–126 by 47 (not a letter-only ROT13/ROT-N)."""
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        if 33 <= byte <= 126:
            out[i] = 33 + (byte - 33 + 47) % 94
        else:
            out[i] = byte
    return bytes(out)


def from_quoted_printable(data: bytes, _params: dict[str, Any]) -> bytes:
    import quopri

    try:
        return quopri.decodestring(data)
    except Exception as exc:
        raise DecodeError(
            "Quoted-Printable invalide.",
            "Invalid Quoted-Printable.",
        ) from exc


def from_html_entities(data: bytes, _params: dict[str, Any]) -> bytes:
    import html

    from cascade.engine.limits import MAX_MANUAL_BYTES

    text = data.decode("utf-8", errors="latin-1")
    out = html.unescape(text).encode("utf-8")
    if len(out) > MAX_MANUAL_BYTES:
        raise DecodeError(
            "Entités HTML : sortie trop volumineuse.",
            "HTML entities: output too large.",
        )
    return out


def from_unicode_escape(data: bytes, _params: dict[str, Any]) -> bytes:
    import codecs

    from cascade.engine.limits import MAX_MANUAL_BYTES

    text = data.decode("utf-8", errors="latin-1")
    try:
        out = codecs.decode(text, "unicode_escape").encode("utf-8", errors="replace")
    except Exception as exc:
        raise DecodeError(
            "Échappements Unicode invalides.",
            "Invalid Unicode escapes.",
        ) from exc
    if len(out) > MAX_MANUAL_BYTES:
        raise DecodeError(
            "Échappements Unicode : sortie trop volumineuse.",
            "Unicode escapes: output too large.",
        )
    return out


def _a2b_uu_line(line: bytes) -> bytes:
    line = line.rstrip(b"\r\n")
    if not line:
        return b""
    try:
        return binascii.a2b_uu(line)
    except binascii.Error:
        nbytes = (((line[0] - 32) & 63) * 4 + 2) // 3
        padded = line[: nbytes + 1].ljust(nbytes + 5)
        return binascii.a2b_uu(padded)


def from_uu(data: bytes, _params: dict[str, Any]) -> bytes:
    blob = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    stripped = blob.lstrip()
    if stripped.lower().startswith(b"begin-base64"):
        body: list[bytes] = []
        for line in stripped.split(b"\n")[1:]:
            marker = line.strip()
            if marker in {b"====", b"end"}:
                break
            if marker:
                body.append(marker)
        if not body:
            raise DecodeError("UUencode Base64 vide.", "Empty Base64 UUencode.")
        return from_base64(b"".join(body), {})
    lines = blob.split(b"\n")
    out = bytearray()
    started = False
    for line in lines:
        lowered = line.lower().lstrip()
        if lowered.startswith(b"begin ") or lowered.startswith(b"begin-base64"):
            started = True
            continue
        stripped_line = line.strip()
        if stripped_line.lower() in {b"end", b"===="}:
            break
        if not stripped_line or stripped_line in {b"`", b" "}:
            continue
        try:
            chunk = _a2b_uu_line(line)
        except (binascii.Error, ValueError, IndexError) as exc:
            if started:
                continue
            raise DecodeError("UUencode invalide.", "Invalid UUencode.") from exc
        started = True
        out.extend(chunk)
    if not out:
        raise DecodeError("UUencode vide.", "Empty UUencode.")
    return bytes(out)


def to_html_entities(data: bytes, _params: dict[str, Any]) -> bytes:
    import html

    text = data.decode("utf-8", errors="surrogateescape")
    return html.escape(text, quote=True).encode("utf-8")


def to_unicode_escape(data: bytes, _params: dict[str, Any]) -> bytes:
    text = data.decode("utf-8", errors="surrogateescape")
    return text.encode("unicode_escape")


def hash_md5(data: bytes, _params: dict[str, Any]) -> bytes:
    import hashlib

    return hashlib.md5(data).hexdigest().encode("ascii")


def hash_sha1(data: bytes, _params: dict[str, Any]) -> bytes:
    import hashlib

    return hashlib.sha1(data).hexdigest().encode("ascii")


def hash_sha256(data: bytes, _params: dict[str, Any]) -> bytes:
    import hashlib

    return hashlib.sha256(data).hexdigest().encode("ascii")


def hash_sha512(data: bytes, _params: dict[str, Any]) -> bytes:
    import hashlib

    return hashlib.sha512(data).hexdigest().encode("ascii")


def to_uu(data: bytes, _params: dict[str, Any]) -> bytes:
    lines = [b"begin 644 -"]
    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + 45]
        offset += 45
        encoded = binascii.b2a_uu(chunk)
        lines.append(encoded.rstrip(b"\n"))
    lines.append(b"`")
    lines.append(b"end")
    return b"\n".join(lines) + b"\n"


_BOOL = lambda key, default, fr, en: ParamSpec(key, "bool", default, fr, en)
_INT = lambda key, default, fr, en, lo, hi: ParamSpec(
    key, "int", default, fr, en, minimum=lo, maximum=hi
)
_CHOICE = lambda key, default, fr, en, choices: ParamSpec(
    key, "choice", default, fr, en, choices=choices
)


def register_encoding_ops() -> None:
    from cascade.engine.registry import has_op

    if has_op("reverse"):
        return

    register(
        Operation(
            id="from_base64",
            family="encoding",
            label_fr="Depuis Base64",
            label_en="From Base64",
            description_fr="Décode Base64 (padding optionnel, alphabet URL possible).",
            description_en="Decode Base64 (optional padding, URL alphabet supported).",
            handler=from_base64,
            params=(_BOOL("url_safe", False, "Alphabet URL", "URL alphabet"),),
            inverse_id="to_base64",
        )
    )
    register(
        Operation(
            id="to_base64",
            family="encoding",
            label_fr="Vers Base64",
            label_en="To Base64",
            description_fr="Encode en Base64.",
            description_en="Encode as Base64.",
            handler=to_base64,
            params=(
                _BOOL("url_safe", False, "Alphabet URL", "URL alphabet"),
                _BOOL("padding", True, "Padding =", "Padding ="),
            ),
            inverse_id="from_base64",
            encode=True,
        )
    )
    register(
        Operation(
            id="from_base32",
            family="encoding",
            label_fr="Depuis Base32",
            label_en="From Base32",
            description_fr="Décode Base32 RFC 4648.",
            description_en="Decode RFC 4648 Base32.",
            handler=from_base32,
            inverse_id="to_base32",
        )
    )
    register(
        Operation(
            id="to_base32",
            family="encoding",
            label_fr="Vers Base32",
            label_en="To Base32",
            description_fr="Encode en Base32.",
            description_en="Encode as Base32.",
            handler=to_base32,
            inverse_id="from_base32",
            encode=True,
        )
    )
    register(
        Operation(
            id="from_base32hex",
            family="encoding",
            label_fr="Depuis Base32hex",
            label_en="From Base32hex",
            description_fr="Décode Base32hex RFC 4648 (alphabet 0-9A-V).",
            description_en="Decode RFC 4648 Base32hex (alphabet 0-9A-V).",
            handler=from_base32hex,
            inverse_id="to_base32hex",
        )
    )
    register(
        Operation(
            id="to_base32hex",
            family="encoding",
            label_fr="Vers Base32hex",
            label_en="To Base32hex",
            description_fr="Encode en Base32hex (0-9A-V).",
            description_en="Encode as Base32hex (0-9A-V).",
            handler=to_base32hex,
            inverse_id="from_base32hex",
            encode=True,
        )
    )
    register(
        Operation(
            id="from_base58",
            family="encoding",
            label_fr="Depuis Base58",
            label_en="From Base58",
            description_fr="Décode Base58 (alphabet Bitcoin).",
            description_en="Decode Base58 (Bitcoin alphabet).",
            handler=from_base58,
            inverse_id="to_base58",
        )
    )
    register(
        Operation(
            id="to_base58",
            family="encoding",
            label_fr="Vers Base58",
            label_en="To Base58",
            description_fr="Encode en Base58 (alphabet Bitcoin).",
            description_en="Encode as Base58 (Bitcoin alphabet).",
            handler=to_base58,
            inverse_id="from_base58",
            encode=True,
        )
    )
    register(
        Operation(
            id="from_base85",
            family="encoding",
            label_fr="Depuis Base85",
            label_en="From Base85",
            description_fr="Décode ASCII85 ou Base85 RFC 1924.",
            description_en="Decode ASCII85 or RFC 1924 Base85.",
            handler=from_base85,
            params=(
                _CHOICE(
                    "variant",
                    "ascii85",
                    "Variante",
                    "Variant",
                    ("ascii85", "rfc1924"),
                ),
                _BOOL("adobe", False, "Délimiteurs Adobe <~ ~>", "Adobe <~ ~> delimiters"),
            ),
            inverse_id="to_base85",
        )
    )
    register(
        Operation(
            id="to_base85",
            family="encoding",
            label_fr="Vers Base85",
            label_en="To Base85",
            description_fr="Encode en ASCII85 ou Base85 RFC 1924.",
            description_en="Encode as ASCII85 or RFC 1924 Base85.",
            handler=to_base85,
            params=(
                _CHOICE(
                    "variant",
                    "ascii85",
                    "Variante",
                    "Variant",
                    ("ascii85", "rfc1924"),
                ),
                _BOOL("adobe", False, "Délimiteurs Adobe <~ ~>", "Adobe <~ ~> delimiters"),
            ),
            inverse_id="from_base85",
            encode=True,
        )
    )
    register(
        Operation(
            id="from_hex",
            family="encoding",
            label_fr="Depuis Hex",
            label_en="From Hex",
            description_fr="Décode hex (espaces, 0x, \\x ignorés).",
            description_en="Decode hex (spaces, 0x, \\x ignored).",
            handler=from_hex,
            inverse_id="to_hex",
        )
    )
    register(
        Operation(
            id="to_hex",
            family="encoding",
            label_fr="Vers Hex",
            label_en="To Hex",
            description_fr="Encode en hexadécimal.",
            description_en="Encode as hexadecimal.",
            handler=to_hex,
            params=(
                _CHOICE(
                    "separator",
                    "none",
                    "Séparateur",
                    "Separator",
                    ("none", "space", "colon"),
                ),
                _BOOL("prefix", False, "Préfixe 0x", "0x prefix"),
            ),
            inverse_id="from_hex",
            encode=True,
        )
    )
    register(
        Operation(
            id="from_decimal",
            family="encoding",
            label_fr="Depuis décimal",
            label_en="From decimal",
            description_fr="Interprète des octets écrits en décimal (68 101 108).",
            description_en="Parse bytes written as decimal (68 101 108).",
            handler=from_decimal,
            inverse_id="to_decimal",
        )
    )
    register(
        Operation(
            id="to_decimal",
            family="encoding",
            label_fr="Vers décimal",
            label_en="To decimal",
            description_fr="Affiche les octets en décimal séparés par des espaces.",
            description_en="Render bytes as space-separated decimals.",
            handler=to_decimal,
            inverse_id="from_decimal",
            encode=True,
        )
    )
    register(
        Operation(
            id="from_zlib",
            family="encoding",
            label_fr="Depuis zlib/gzip",
            label_en="From zlib/gzip",
            description_fr="Décompresse zlib, gzip ou deflate brut.",
            description_en="Decompress zlib, gzip, or raw deflate.",
            handler=from_zlib,
            inverse_id="to_zlib",
        )
    )
    register(
        Operation(
            id="to_zlib",
            family="encoding",
            label_fr="Vers zlib",
            label_en="To zlib",
            description_fr="Compresse avec zlib.",
            description_en="Compress with zlib.",
            handler=to_zlib,
            inverse_id="from_zlib",
            encode=True,
        )
    )
    register(
        Operation(
            id="url_decode",
            family="encoding",
            label_fr="Décodage URL",
            label_en="URL decode",
            description_fr="Décode percent-encoding.",
            description_en="Decode percent-encoding.",
            handler=url_decode,
            inverse_id="url_encode",
        )
    )
    register(
        Operation(
            id="url_encode",
            family="encoding",
            label_fr="Encodage URL",
            label_en="URL encode",
            description_fr="Encode en percent-encoding.",
            description_en="Percent-encode bytes.",
            handler=url_encode,
            inverse_id="url_decode",
            encode=True,
        )
    )
    register(
        Operation(
            id="from_binary",
            family="encoding",
            label_fr="Depuis binaire",
            label_en="From binary",
            description_fr="Interprète une chaîne 0/1 en octets.",
            description_en="Parse a 0/1 bit string into bytes.",
            handler=from_binary,
            inverse_id="to_binary",
        )
    )
    register(
        Operation(
            id="to_binary",
            family="encoding",
            label_fr="Vers binaire",
            label_en="To binary",
            description_fr="Affiche les octets en bits.",
            description_en="Render bytes as bits.",
            handler=to_binary,
            params=(_BOOL("grouped", True, "Grouper par octet", "Group by byte"),),
            inverse_id="from_binary",
            encode=True,
        )
    )
    register(
        Operation(
            id="rot13",
            family="encoding",
            label_fr="ROT13",
            label_en="ROT13",
            description_fr="Rotation de 13 lettres (A-Z).",
            description_en="Rotate letters by 13 (A-Z).",
            handler=rot13,
            inverse_id="rot13",
        )
    )
    register(
        Operation(
            id="rot_n",
            family="encoding",
            label_fr="ROT-N",
            label_en="ROT-N",
            description_fr="Rotation de N lettres.",
            description_en="Rotate letters by N.",
            handler=rot_n,
            params=(_INT("n", 13, "Décalage N", "Shift N", 0, 25),),
            inverse_id="rot_n",
        )
    )
    register(
        Operation(
            id="from_morse",
            family="encoding",
            label_fr="Depuis Morse",
            label_en="From Morse",
            description_fr="Décode le Morse international ( / = espace).",
            description_en="Decode international Morse ( / = space).",
            handler=from_morse,
            inverse_id="to_morse",
        )
    )
    register(
        Operation(
            id="to_morse",
            family="encoding",
            label_fr="Vers Morse",
            label_en="To Morse",
            description_fr="Encode en Morse international.",
            description_en="Encode as international Morse.",
            handler=to_morse,
            inverse_id="from_morse",
            encode=True,
        )
    )
    register(
        Operation(
            id="from_utf16le",
            family="encoding",
            label_fr="Depuis UTF-16 LE",
            label_en="From UTF-16 LE",
            description_fr="Interprète les octets comme UTF-16 little-endian → UTF-8.",
            description_en="Interpret bytes as UTF-16 LE → UTF-8.",
            handler=from_utf16le,
            inverse_id="to_utf16le",
        )
    )
    register(
        Operation(
            id="to_utf16le",
            family="encoding",
            label_fr="Vers UTF-16 LE",
            label_en="To UTF-16 LE",
            description_fr="Encode le texte UTF-8 en UTF-16 LE.",
            description_en="Encode UTF-8 text as UTF-16 LE.",
            handler=to_utf16le,
            inverse_id="from_utf16le",
            encode=True,
        )
    )
    register(
        Operation(
            id="from_utf16be",
            family="encoding",
            label_fr="Depuis UTF-16 BE",
            label_en="From UTF-16 BE",
            description_fr="Interprète les octets comme UTF-16 big-endian → UTF-8.",
            description_en="Interpret bytes as UTF-16 BE → UTF-8.",
            handler=from_utf16be,
            inverse_id="to_utf16be",
        )
    )
    register(
        Operation(
            id="to_utf16be",
            family="encoding",
            label_fr="Vers UTF-16 BE",
            label_en="To UTF-16 BE",
            description_fr="Encode le texte UTF-8 en UTF-16 BE.",
            description_en="Encode UTF-8 text as UTF-16 BE.",
            handler=to_utf16be,
            inverse_id="from_utf16be",
            encode=True,
        )
    )
    register(
        Operation(
            id="from_latin1",
            family="encoding",
            label_fr="Latin-1 → UTF-8",
            label_en="Latin-1 → UTF-8",
            description_fr="Réinterprète les octets Latin-1 en texte UTF-8.",
            description_en="Reinterpret Latin-1 bytes as UTF-8 text.",
            handler=from_latin1,
            inverse_id="to_latin1",
        )
    )
    register(
        Operation(
            id="to_latin1",
            family="encoding",
            label_fr="UTF-8 → Latin-1",
            label_en="UTF-8 → Latin-1",
            description_fr="Encode le texte UTF-8 en Latin-1.",
            description_en="Encode UTF-8 text as Latin-1.",
            handler=to_latin1,
            inverse_id="from_latin1",
            encode=True,
        )
    )
    register(
        Operation(
            id="reverse",
            family="encoding",
            label_fr="Inverser",
            label_en="Reverse",
            description_fr="Inverse les octets (texte à l’envers, classique CTF avant/après Base64).",
            description_en="Reverse bytes (upside-down text, classic before/after Base64).",
            handler=reverse_bytes,
            inverse_id="reverse",
        )
    )
    register(
        Operation(
            id="atbash",
            family="encoding",
            label_fr="Atbash",
            label_en="Atbash",
            description_fr="A↔Z, B↔Y… (auto-inverse).",
            description_en="A↔Z, B↔Y… (self-inverse).",
            handler=atbash,
            inverse_id="atbash",
        )
    )
    register(
        Operation(
            id="rot47",
            family="encoding",
            label_fr="ROT47",
            label_en="ROT47",
            description_fr="Décalage ASCII imprimable 33–126 de 47 (chiffres et symboles inclus, pas un ROT13).",
            description_en="Shift printable ASCII 33–126 by 47 (digits and symbols included, not ROT13).",
            handler=rot47,
            inverse_id="rot47",
        )
    )
    register(
        Operation(
            id="from_quoted_printable",
            family="encoding",
            label_fr="Quoted-Printable",
            label_en="Quoted-Printable",
            description_fr="Décode Quoted-Printable (=XX).",
            description_en="Decode Quoted-Printable (=XX).",
            handler=from_quoted_printable,
        )
    )
    register(
        Operation(
            id="from_html_entities",
            family="encoding",
            label_fr="Entités HTML",
            label_en="HTML entities",
            description_fr="Décode &amp; &#NN; &#xHH;.",
            description_en="Decode &amp; &#NN; &#xHH;.",
            handler=from_html_entities,
            inverse_id="to_html_entities",
        )
    )
    register(
        Operation(
            id="from_unicode_escape",
            family="encoding",
            label_fr="Échappements Unicode",
            label_en="Unicode escapes",
            description_fr="Décode \\uXXXX et \\xHH.",
            description_en="Decode \\uXXXX and \\xHH.",
            handler=from_unicode_escape,
            inverse_id="to_unicode_escape",
        )
    )
    register(
        Operation(
            id="from_uu",
            family="encoding",
            label_fr="Depuis UUencode",
            label_en="From UUencode",
            description_fr="Décode un bloc begin … end (ou le corps seul).",
            description_en="Decode a begin … end block (or the body alone).",
            handler=from_uu,
            inverse_id="to_uu",
        )
    )
    register(
        Operation(
            id="to_html_entities",
            family="encoding",
            label_fr="Vers entités HTML",
            label_en="To HTML entities",
            description_fr="Encode & < > \" ' en entités HTML.",
            description_en="Encode & < > \" ' as HTML entities.",
            handler=to_html_entities,
            inverse_id="from_html_entities",
            encode=True,
        )
    )
    register(
        Operation(
            id="to_unicode_escape",
            family="encoding",
            label_fr="Vers échappements Unicode",
            label_en="To Unicode escapes",
            description_fr="Encode en \\uXXXX / \\xHH.",
            description_en="Encode as \\uXXXX / \\xHH.",
            handler=to_unicode_escape,
            inverse_id="from_unicode_escape",
            encode=True,
        )
    )
    register(
        Operation(
            id="hash_md5",
            family="encoding",
            label_fr="Empreinte MD5",
            label_en="MD5 digest",
            description_fr="Empreinte MD5 hex (sens unique).",
            description_en="Hex MD5 digest (one-way).",
            handler=hash_md5,
            encode=True,
            one_way=True,
        )
    )
    register(
        Operation(
            id="hash_sha1",
            family="encoding",
            label_fr="Empreinte SHA-1",
            label_en="SHA-1 digest",
            description_fr="Empreinte SHA-1 hex (sens unique).",
            description_en="Hex SHA-1 digest (one-way).",
            handler=hash_sha1,
            encode=True,
            one_way=True,
        )
    )
    register(
        Operation(
            id="hash_sha256",
            family="encoding",
            label_fr="Empreinte SHA-256",
            label_en="SHA-256 digest",
            description_fr="Empreinte SHA-256 hex (sens unique).",
            description_en="Hex SHA-256 digest (one-way).",
            handler=hash_sha256,
            encode=True,
            one_way=True,
        )
    )
    register(
        Operation(
            id="hash_sha512",
            family="encoding",
            label_fr="Empreinte SHA-512",
            label_en="SHA-512 digest",
            description_fr="Empreinte SHA-512 hex (sens unique).",
            description_en="Hex SHA-512 digest (one-way).",
            handler=hash_sha512,
            encode=True,
            one_way=True,
        )
    )
    register(
        Operation(
            id="to_uu",
            family="encoding",
            label_fr="Vers UUencode",
            label_en="To UUencode",
            description_fr="Encode en UUencode.",
            description_en="Encode as UUencode.",
            handler=to_uu,
            inverse_id="from_uu",
            encode=True,
        )
    )
