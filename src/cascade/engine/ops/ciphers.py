from __future__ import annotations

from typing import Any

from cascade.engine.detect import printable_score
from cascade.engine.errors import DecodeError
from cascade.engine.hexdump import decode_utf8_view
from cascade.engine.keys import parse_key
from cascade.engine.limits import MAX_BRUTE_SECONDS
from cascade.engine.ops.encodings import _rot_bytes
from cascade.engine.registry import Operation, has_op, register
from cascade.engine.types import ParamSpec
from cascade.engine.wordlist import BUILTIN_XOR_KEYS, parse_pasted_keys


def _key_bytes(params: dict[str, Any]) -> bytes:
    return parse_key(params)


def xor_bytes(data: bytes, params: dict[str, Any]) -> bytes:
    key = _key_bytes(params)
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def vigenere(data: bytes, params: dict[str, Any]) -> bytes:
    key = [b for b in str(params.get("key", "")).upper().encode("ascii", errors="ignore") if 65 <= b <= 90]
    if not key:
        raise DecodeError("Clé Vigenère vide (A-Z).", "Empty Vigenère key (A-Z).")
    decode = bool(params.get("decrypt", True))
    out = bytearray(len(data))
    ki = 0
    for i, byte in enumerate(data):
        if 65 <= byte <= 90:
            shift = key[ki % len(key)] - 65
            ki += 1
            delta = -shift if decode else shift
            out[i] = 65 + (byte - 65 + delta) % 26
        elif 97 <= byte <= 122:
            shift = key[ki % len(key)] - 65
            ki += 1
            delta = -shift if decode else shift
            out[i] = 97 + (byte - 97 + delta) % 26
        else:
            out[i] = byte
    return bytes(out)


def caesar_brute(data: bytes, _params: dict[str, Any]) -> bytes:
    ranked: list[tuple[float, int, bytes]] = []
    for n in range(26):
        out = _rot_bytes(data, n)
        ranked.append((printable_score(out), n, out))
    ranked.sort(key=lambda item: item[0], reverse=True)
    lines = ["# Caesar / ROT brute (26 shifts, best first)", ""]
    for score, n, out in ranked:
        preview, _ok = decode_utf8_view(out)
        flat = " ".join(preview.split())
        lines.append(f"n={n:02d}  score={score:.3f}  {flat[:200]}")
    return "\n".join(lines).encode("utf-8")


def xor_brute1(data: bytes, params: dict[str, Any]) -> bytes:
    sample = data[:4096] if data else data
    top_n = int(params.get("top", 12))
    ranked: list[tuple[float, int, bytes]] = []
    for key in range(256):
        out = bytes(byte ^ key for byte in sample)
        ranked.append((printable_score(out), key, out))
    ranked.sort(key=lambda item: item[0], reverse=True)
    lines = ["# XOR brute 1-byte (sample, best first)", ""]
    for score, key, out in ranked[:top_n]:
        preview, _ok = decode_utf8_view(out)
        flat = " ".join(preview.split())
        lines.append(f"key=0x{key:02X}  score={score:.3f}  {flat[:200]}")
    return "\n".join(lines).encode("utf-8")


def _xor_repeat(data: bytes, key: bytes) -> bytes:
    length = len(key)
    return bytes(data[i] ^ key[i % length] for i in range(len(data)))


def _report_xor(title: str, ranked: list[tuple[float, str, bytes]]) -> bytes:
    lines = [title, ""]
    for score, label, out in ranked:
        preview, _ok = decode_utf8_view(out)
        flat = " ".join(preview.split())
        lines.append(f"{label}  score={score:.3f}  {flat[:200]}")
    return "\n".join(lines).encode("utf-8")


def xor_brute2(data: bytes, params: dict[str, Any]) -> bytes:
    sample = data[:160] if data else data
    top_n = int(params.get("top", 10))
    best: list[tuple[float, str, bytes]] = []
    for key_int in range(65536):
        key = bytes((key_int >> 8, key_int & 0xFF))
        out = _xor_repeat(sample, key)
        score = printable_score(out)
        if len(best) < top_n:
            best.append((score, f"key=0x{key.hex().upper()}", out))
            best.sort(key=lambda item: item[0])
        elif score > best[0][0]:
            best[0] = (score, f"key=0x{key.hex().upper()}", out)
            best.sort(key=lambda item: item[0])
    best.sort(key=lambda item: item[0], reverse=True)
    return _report_xor("# XOR brute 2-byte (sample, best first)", best)


def xor_brute3(data: bytes, params: dict[str, Any]) -> bytes:
    import time

    sample = data[:48] if data else data
    top_n = int(params.get("top", 8))
    seconds = min(float(params.get("seconds", MAX_BRUTE_SECONDS)), MAX_BRUTE_SECONDS)
    deadline = time.monotonic() + max(1.0, seconds)
    best: list[tuple[float, str, bytes]] = []
    stopped_early = False
    sample_len = len(sample)
    for key_int in range(256 ** 3):
        if key_int & 0x3FFF == 0 and time.monotonic() > deadline:
            stopped_early = True
            break
        k0, k1, k2 = key_int >> 16, (key_int >> 8) & 0xFF, key_int & 0xFF
        out = bytes(sample[i] ^ (k0, k1, k2)[i % 3] for i in range(sample_len))
        good = 0
        for byte in out:
            if 32 <= byte < 127 or byte in (9, 10, 13):
                good += 1
        score = good / sample_len if sample_len else 0.0
        if len(best) < top_n:
            key = bytes((k0, k1, k2))
            best.append((score, f"key=0x{key.hex().upper()}", out))
            best.sort(key=lambda item: item[0])
        elif score > best[0][0]:
            key = bytes((k0, k1, k2))
            best[0] = (score, f"key=0x{key.hex().upper()}", out)
            best.sort(key=lambda item: item[0])
    best.sort(key=lambda item: item[0], reverse=True)
    title = "# XOR brute 3-byte (sample, best first)"
    if stopped_early:
        title += "\n# stopped by timeout — partial search"
    return _report_xor(title, best)


def xor_wordlist(data: bytes, params: dict[str, Any]) -> bytes:
    sample = data[:4096] if data else data
    top_n = int(params.get("top", 12))
    keys = list(BUILTIN_XOR_KEYS)
    keys.extend(parse_pasted_keys(str(params.get("extra_keys", ""))))
    unique: list[bytes] = []
    seen: set[bytes] = set()
    for key in keys:
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(key)
    ranked: list[tuple[float, str, bytes]] = []
    for key in unique:
        out = _xor_repeat(sample, key)
        try:
            label = key.decode("ascii")
            if not label.isprintable():
                label = "0x" + key.hex()
        except UnicodeDecodeError:
            label = "0x" + key.hex()
        ranked.append((printable_score(out), f"key={label!r}", out))
    ranked.sort(key=lambda item: item[0], reverse=True)
    return _report_xor("# XOR wordlist (built-in + pasted, best first)", ranked[:top_n])


def register_cipher_ops() -> None:
    if has_op("xor_wordlist"):
        return
    register(
        Operation(
            id="xor",
            family="cipher",
            label_fr="XOR",
            label_en="XOR",
            description_fr="XOR avec une clé texte ou hex (répétée).",
            description_en="XOR with a repeating text or hex key.",
            handler=xor_bytes,
            params=(
                ParamSpec("key", "text", "", "Clé", "Key"),
                ParamSpec(
                    "key_format",
                    "choice",
                    "text",
                    "Format de clé",
                    "Key format",
                    choices=("text", "hex"),
                ),
            ),
            inverse_id="xor",
        )
    )
    register(
        Operation(
            id="vigenere",
            family="cipher",
            label_fr="Vigenère",
            label_en="Vigenère",
            description_fr="Chiffre / déchiffre Vigenère (lettres A-Z).",
            description_en="Vigenère encrypt / decrypt (A-Z letters).",
            handler=vigenere,
            params=(
                ParamSpec("key", "text", "", "Clé", "Key"),
                ParamSpec("decrypt", "bool", True, "Déchiffrer", "Decrypt"),
            ),
        )
    )
    register(
        Operation(
            id="caesar_brute",
            family="cipher",
            label_fr="César bruteforce",
            label_en="Caesar brute",
            description_fr="Teste les 26 décalages et les classe par lisibilité.",
            description_en="Try all 26 shifts and rank by readability.",
            handler=caesar_brute,
        )
    )
    register(
        Operation(
            id="xor_brute1",
            family="cipher",
            label_fr="XOR bruteforce 1 octet",
            label_en="XOR brute 1-byte",
            description_fr="Teste les 256 clés d’un octet (échantillon) et classe le résultat.",
            description_en="Try all 256 one-byte keys (sample) and rank the result.",
            handler=xor_brute1,
            params=(ParamSpec("top", "int", 12, "Top N", "Top N", minimum=3, maximum=32),),
        )
    )
    register(
        Operation(
            id="xor_brute2",
            family="cipher",
            label_fr="XOR bruteforce 2 octets",
            label_en="XOR brute 2-byte",
            description_fr="Teste 65 536 clés de 2 octets (échantillon).",
            description_en="Try all 65,536 two-byte keys (sample).",
            handler=xor_brute2,
            params=(ParamSpec("top", "int", 10, "Top N", "Top N", minimum=3, maximum=32),),
        )
    )
    register(
        Operation(
            id="xor_brute3",
            family="cipher",
            label_fr="XOR bruteforce 3 octets",
            label_en="XOR brute 3-byte",
            description_fr="Recherche 3 octets bornée (3 s max, pas 4 octets : trop large).",
            description_en="Bounded 3-byte search (3 s max; no 4-byte space: too large).",
            handler=xor_brute3,
            params=(
                ParamSpec("top", "int", 8, "Top N", "Top N", minimum=3, maximum=20),
                ParamSpec("seconds", "int", 3, "Timeout (s)", "Timeout (s)", minimum=1, maximum=3),
            ),
        )
    )
    register(
        Operation(
            id="xor_wordlist",
            family="cipher",
            label_fr="XOR wordlist",
            label_en="XOR wordlist",
            description_fr="Essaie une liste courte intégrée plus les clés collées (une par ligne).",
            description_en="Try a short built-in list plus pasted keys (one per line).",
            handler=xor_wordlist,
            params=(
                ParamSpec("extra_keys", "text", "", "Clés collées", "Pasted keys"),
                ParamSpec("top", "int", 12, "Top N", "Top N", minimum=3, maximum=32),
            ),
        )
    )
