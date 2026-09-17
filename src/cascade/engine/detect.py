from __future__ import annotations

import re

_B64 = re.compile(rb"^[A-Za-z0-9+/_-]+={0,2}$")
_HEX = re.compile(rb"^[0-9A-Fa-f]+$")
_BIN = re.compile(rb"^[01]+$")
_MORSE = re.compile(rb"^[.\-/\s]+$")
_PCT = re.compile(rb"%[0-9A-Fa-f]{2}")


def _compact(data: bytes) -> bytes:
    return b"".join(data.split())


_OX = re.compile(br"(?i)0x")
_OX_BYTE = re.compile(br"(?i)(?:0x|\\x)([0-9A-Fa-f]{2})")
_B32 = re.compile(rb"^[A-Z2-7]+={0,6}$", re.IGNORECASE)
_B32HEX = re.compile(rb"^[0-9A-V]+={0,6}$", re.IGNORECASE)


_B64_ALPHABET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")
_A85_BYTES = set(range(33, 118)) | {121, 122}  # !..u plus y/z
_B85_BYTES = set(
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
)
_QP = re.compile(rb"=(?:[0-9A-Fa-f]{2}|\r?\n)")
_HTML_ENT = re.compile(rb"&(?:#\d{1,7}|#x[0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]+);")
_UNI_ESC = re.compile(rb"\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}")


def looks_base64(data: bytes) -> bool:
    compact = _compact(data)
    n = len(compact)
    if n < 4 or n > 2_000_000:
        return False
    if not _B64.fullmatch(compact):
        return False
    pad = n - len(compact.rstrip(b"="))
    if pad > 2 or (pad and not compact.endswith(b"=" * pad)):
        return False
    if pad and n % 4:
        return False
    if not pad and n % 4 == 1:
        return False
    body = compact.rstrip(b"=")
    if _HEX.fullmatch(body) and len(body) % 2 == 0:
        return False
    has_symbol = any(byte in b"+/-_" for byte in compact)
    has_upper = any(65 <= byte <= 90 for byte in body)
    has_lower = any(97 <= byte <= 122 for byte in body)
    has_digit = any(48 <= byte <= 57 for byte in body)
    # RFC 4648 Base32 is A-Z/2-7 (optionally padded). Do not treat it as Base64.
    if _B32.fullmatch(compact) is not None and not (has_upper and has_lower):
        return False
    if has_symbol or pad:
        return True
    if has_upper and has_lower and has_digit:
        return True
    if has_upper and has_lower and n >= 12 and n % 4 == 0 and b" " not in data.strip():
        return True
    return n >= 16 and has_digit and (has_upper or has_lower)


def looks_base32(data: bytes) -> bool:
    compact = _compact(data)
    if len(compact) < 8 or len(compact) > 2_000_000:
        return False
    if _B32.fullmatch(compact) is None:
        return False
    body = compact.rstrip(b"=").upper()
    if len(body) < 8:
        return False
    has_digit = any(byte in b"234567" for byte in body)
    padded = compact.endswith(b"=")
    return has_digit or padded


def looks_base32hex(data: bytes) -> bool:
    compact = _compact(data)
    if len(compact) < 4 or len(compact) > 2_000_000:
        return False
    if _B32HEX.fullmatch(compact) is None:
        return False
    body = compact.rstrip(b"=").upper()
    if len(body) < 4:
        return False
    has_gv = any(71 <= byte <= 86 for byte in body)  # G–V, hors hex A–F
    has_0189 = any(byte in b"0189" for byte in body)
    if looks_hex(data) and not has_gv:
        return False
    return has_gv or has_0189


_LETTER_PUNCT = (
    ".,!?'-;:#%&@+/\\()[]{}\"«»“”‘’—–€$£"
)


def looks_letters(data: bytes) -> bool:
    sample = data.strip()
    if not (2 <= len(sample) <= 50_000):
        return False
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not any(ch.isalpha() for ch in text):
        return False
    useful = sum(ch.isalpha() or ch.isspace() or ch in _LETTER_PUNCT for ch in text)
    if useful / len(text) < 0.62:
        return False
    compact = not any(ch in sample for ch in b" \t\n\r")
    if compact and (
        looks_base64(data) or looks_base32(data) or looks_hex(data) or looks_base85(data)
    ):
        if not (
            b"?" in sample
            and b"=" in sample
            and len(sample) <= 80
            and sum(ch.isalpha() for ch in text) / len(text) >= 0.5
        ):
            return False
    return True


def looks_reversed_encoding(data: bytes) -> bool:
    stripped = data.strip()
    if len(stripped) < 4:
        return False
    rev = stripped[::-1]
    if looks_base64(stripped) and looks_base64(rev):
        return False
    if looks_hex(stripped) and looks_hex(rev):
        return False
    return looks_base64(rev) or looks_base32(rev) or looks_hex(rev) or looks_url(rev)


def looks_hex(data: bytes) -> bool:
    if looks_decimal_bytes(data) or looks_binary(data):
        return False
    ox_pairs = _OX_BYTE.findall(data)
    leftover = _compact(re.sub(br"[^0-9A-Fa-f]", b"", _OX_BYTE.sub(b"", data)))
    if len(ox_pairs) >= 2 and not leftover:
        return True
    cleaned = _OX.sub(b"", data).replace(b"\\x", b"").replace(b":", b"").replace(b",", b"")
    compact = _compact(cleaned)
    if len(compact) < 4 or len(compact) > 4_000_000:
        return False
    return len(compact) % 2 == 0 and _HEX.fullmatch(compact) is not None


_HASH_LEN = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}


def hash_digest_kind(data: bytes) -> str | None:
    compact = _compact(data.strip())
    name = _HASH_LEN.get(len(compact))
    if name is None or _HEX.fullmatch(compact) is None:
        return None
    raw = bytes.fromhex(compact.decode("ascii"))
    if looks_image(raw) or looks_zlib(raw) or looks_gzip(raw):
        return None
    if printable_score(raw) >= 0.72 or looks_letters(raw) or english_hint(raw) >= 0.55:
        return None
    if raw.count(0) / len(raw) > 0.25:
        return None
    return name


def looks_url(data: bytes) -> bool:
    if len(data) >= 2_000_000:
        return False
    hits = _PCT.findall(data)
    if not hits:
        return False
    lowered = data.lower()
    if b"%20" in lowered or b"%2f" in lowered or b"%3d" in lowered or b"%3a" in lowered:
        return True
    if b"://" in data or b"&" in data:
        return True
    return len(hits) >= 3


def looks_binary(data: bytes) -> bool:
    compact = _compact(data)
    return 8 <= len(compact) <= 2_000_000 and _BIN.fullmatch(compact) is not None


def looks_decimal_bytes(data: bytes) -> bool:
    parts = data.strip().replace(b",", b" ").split()
    if not (4 <= len(parts) <= 200_000):
        return False
    three_digit = 0
    for part in parts:
        if not part.isdigit():
            return False
        value = int(part)
        if value > 255:
            return False
        if len(part) >= 3:
            three_digit += 1
    return three_digit >= 2


def looks_morse(data: bytes) -> bool:
    sample = data.strip()
    if not (5 <= len(sample) <= 100_000):
        return False
    if _MORSE.fullmatch(sample) is None:
        return False
    return b"." in sample and b"-" in sample


def looks_utf16le(data: bytes) -> bool:
    if len(data) < 8 or len(data) % 2:
        return False
    sample = data[:4000]
    zeros = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
    return zeros / (len(sample) // 2) > 0.35


def looks_utf16be(data: bytes) -> bool:
    if len(data) < 8 or len(data) % 2:
        return False
    sample = data[:4000]
    zeros = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
    return zeros / (len(sample) // 2) > 0.35


def looks_jwt(data: bytes) -> bool:
    parts = data.strip().split(b".")
    if len(parts) not in (2, 3):
        return False
    return all(part and len(part) >= 4 for part in parts[:2])


def printable_score(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:8192]
    try:
        text = sample.decode("utf-8")
        utf8 = 1.0
    except UnicodeDecodeError:
        text = sample.decode("latin-1")
        utf8 = 0.0
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in text) / len(text)
    space_term = 0.0
    if len(text) >= 12:
        spaces = text.count(" ") / len(text)
        space_fit = 1.0 - min(abs(spaces - 0.16), 0.16) / 0.16
        space_term = 0.10 * space_fit
    return 0.50 * printable + 0.40 * utf8 + space_term


_COMMON = (
    b"the ",
    b"and ",
    b"flag",
    b"hello",
    b"world",
    b"http",
    b"ctf",
    b"{",
    b"user",
    b"pass",
    b"welcome",
    b" les ",
    b" des ",
    b" une ",
    b" est ",
    b" le ",
    b" de ",
    b" qui ",
    b" cette ",
    b" fois",
    b" pour ",
    b" avec ",
    b" dans ",
)


def english_hint(data: bytes) -> float:
    base = printable_score(data)
    sample = data[:8192]
    lowered = sample.lower()
    bonus = sum(0.04 for token in _COMMON if token in lowered)
    letters = [ch.lower() for ch in sample.decode("latin-1") if ch.isalpha()]
    if letters:
        vowels = sum(ch in "aeiouy" for ch in letters) / len(letters)
        vowel_fit = 1.0 - min(abs(vowels - 0.40), 0.40) / 0.40
        base += 0.12 * vowel_fit
    return min(base + min(bonus, 0.20), 1.25)


def _spaced_short_tokens(data: bytes) -> bool:
    parts = data.split()
    if len(parts) < 3:
        return False
    return sum(1 for part in parts if 2 <= len(part) <= 20) >= 3


def looks_base85(data: bytes) -> bool:
    sample = data.strip()
    compact = _compact(sample)
    if not (5 <= len(compact) <= 2_000_000):
        return False
    if sample.startswith(b"<~") or sample.endswith(b"~>"):
        return True
    # ROT47 / phrases keep spaces; ASCII85 is a compact blob or wrapped long lines.
    if _spaced_short_tokens(sample):
        return False
    # URLs. `/` is a valid ASCII85 digit — only reject path-like leftovers.
    if b"://" in sample:
        return False
    if b"." in compact and b"?" in compact:
        return False
    if b"/" in compact:
        weird = sum(1 for byte in compact if byte in b"!\"#$%&()*+,-;<=>?@[\\]^_`{|}~")
        letters = sum(1 for byte in compact if 65 <= byte <= 90 or 97 <= byte <= 122)
        if weird < 3 and letters / len(compact) >= 0.40:
            return False
    # flag{...} is plaintext, but `{` `}` are valid RFC1924 digits.
    brace = compact.find(b"{")
    if (
        compact.count(b"{") == 1
        and compact.endswith(b"}")
        and brace > 0
        and compact[:brace].isalpha()
        and len(compact) < 80
    ):
        return False
    if b" " in sample and len(sample) < 120:
        letters = sum(1 for byte in compact if 65 <= byte <= 90 or 97 <= byte <= 122)
        if b":" in sample or letters / len(compact) >= 0.45:
            return False
    if all(byte in _A85_BYTES for byte in compact):
        if any(byte not in _B64_ALPHABET for byte in compact):
            if sample.startswith(b"<") and b">" in compact and len(compact) < 20:
                return False
            return True
        has_upper = any(65 <= byte <= 90 for byte in compact)
        has_lower = any(97 <= byte <= 122 for byte in compact)
        has_digit = any(48 <= byte <= 57 for byte in compact)
        if 5 <= len(compact) <= 48 and has_upper and has_lower and has_digit:
            return True
    return all(byte in _B85_BYTES for byte in compact) and any(
        byte not in _B64_ALPHABET for byte in compact
    )


def looks_quoted_printable(data: bytes) -> bool:
    if not (8 <= len(data) <= 2_000_000):
        return False
    return len(_QP.findall(data)) >= 2


def looks_html_entities(data: bytes) -> bool:
    return bool(_HTML_ENT.search(data)) and len(data) < 2_000_000


def looks_unicode_escape(data: bytes) -> bool:
    return len(_UNI_ESC.findall(data)) >= 2 and len(data) < 2_000_000


def looks_uu_header(data: bytes) -> bool:
    sample = data.lstrip().lower()
    return sample.startswith(b"begin ") or sample.startswith(b"begin-base64")


def looks_uu(data: bytes) -> bool:
    sample = data.lstrip()
    if looks_uu_header(sample):
        return True
    lines = [
        line.rstrip(b"\r")
        for line in sample.splitlines()
        if line.strip() and line.strip().lower() != b"end"
    ]
    if not (1 <= len(lines) <= 8_000):
        return False

    def uu_line(line: bytes) -> bool:
        raw = line.rstrip()
        if not (2 <= len(raw) <= 80):
            return False
        if not (32 <= raw[0] <= 96 and all(32 <= byte <= 96 for byte in raw)):
            return False
        length_code = (raw[0] - 32) & 63
        if length_code > 45:
            return False
        expected_body = ((length_code + 2) // 3) * 4
        actual_body = len(raw) - 1
        if actual_body < expected_body:
            return False
        return actual_body <= max(expected_body + 16, 60)

    probe = lines[:12]
    hits = sum(1 for line in probe if uu_line(line))
    return hits >= min(2, len(probe)) and hits >= len(probe) * 0.6


def looks_js_atob(data: bytes) -> bool:
    return b"atob(" in data.lower()


def looks_powershell_encoded(data: bytes) -> bool:
    lowered = data.lower()
    return b"encodedcommand" in lowered or b" -enc " in lowered or b" -e " in lowered


def looks_zlib(data: bytes) -> bool:
    return len(data) >= 6 and data[0] == 0x78 and data[1] in {0x01, 0x5E, 0x9C, 0xDA}


def looks_gzip(data: bytes) -> bool:
    return len(data) >= 10 and data.startswith(b"\x1f\x8b")


def looks_image(data: bytes) -> bool:
    if len(data) < 12:
        return False
    if data.startswith(b"\x89PNG\r\n\x1a\n") or data.startswith(b"\xff\xd8\xff"):
        return True
    if data.startswith(b"GIF8") or data.startswith(b"BM"):
        return True
    return data.startswith(b"RIFF") and data[8:12] == b"WEBP"


def looks_like_layer(data: bytes) -> bool:
    """Same question for every layer: does this still look like something to peel?"""
    if not data or len(data) > 2_000_000:
        return False
    return (
        looks_base64(data)
        or looks_base32(data)
        or looks_base32hex(data)
        or looks_hex(data)
        or looks_url(data)
        or looks_binary(data)
        or looks_morse(data)
        or looks_jwt(data)
        or looks_utf16le(data)
        or looks_utf16be(data)
        or looks_reversed_encoding(data)
        or looks_base85(data)
        or looks_quoted_printable(data)
        or looks_html_entities(data)
        or looks_unicode_escape(data)
        or looks_uu(data)
        or looks_js_atob(data)
        or looks_powershell_encoded(data)
        or looks_zlib(data)
        or looks_gzip(data)
        or looks_decimal_bytes(data)
        or looks_image(data)
    )
