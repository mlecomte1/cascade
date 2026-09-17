from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import time
from typing import Any

from cascade.engine.detect import (
    english_hint,
    looks_base32,
    looks_base32hex,
    looks_base64,
    looks_base85,
    looks_binary,
    looks_decimal_bytes,
    looks_gzip,
    looks_hex,
    hash_digest_kind,
    looks_html_entities,
    looks_image,
    looks_js_atob,
    looks_jwt,
    looks_letters,
    looks_like_layer,
    looks_morse,
    looks_powershell_encoded,
    looks_quoted_printable,
    looks_reversed_encoding,
    looks_unicode_escape,
    looks_url,
    looks_utf16be,
    looks_utf16le,
    looks_uu,
    looks_uu_header,
    looks_zlib,
)
from cascade.engine.errors import DecodeError
from cascade.engine.hexdump import decode_utf8_view
from cascade.engine.limits import MAX_MAGIC_BYTES, MAX_MAGIC_DEPTH, MAX_MAGIC_OUTPUT
from cascade.engine.ops.ciphers import vigenere
from cascade.engine.ops.encodings import B58_ALPHABET, _rot_bytes, atbash, rot13, rot47
from cascade.engine.registry import get_op
from cascade.engine.types import Step

MAX_DECODE_BRANCHES = 12
MAX_PERMUTE_BRANCHES = 6
MAX_NODES = 140
TIME_BUDGET_SEC = 0.85
MIN_KEEP = 0.42
PERMUTE_GAIN = 0.02
_PLAIN_TOKENS = (
    b" est ",
    b" the ",
    b" les ",
    b" des ",
    b" une ",
    b" un ",
    b" and ",
    b" de ",
    b" du ",
    b" que ",
    b" qui ",
    b" plus ",
    b" puis ",
    b" avec ",
    b" dans ",
    b" pour ",
    b" autre ",
    b" from ",
    b" with ",
    b" this ",
    b" that ",
    b" for ",
    b" on ",
    b" par ",
    b" avant ",
    b" deux ",
    b" trois ",
    b" bien ",
    b" ici ",
    b" mais ",
    b" comme ",
    b" tout ",
    b" cette ",
    b" pas ",
    b" aussi ",
    b" sans ",
    b" sous ",
    b" entre ",
    b" encore ",
    b" alors ",
    b" not ",
    b" are ",
    b" you ",
    b" le ",
    b" la ",
    b" sur ",
    b" au ",
    b" en ",
    b" et ",
    b" il ",
    b" elle ",
    b" je ",
    b" tu ",
    b" nous ",
    b" vous ",
    b" son ",
    b" sa ",
    b" ses ",
    b" mon ",
    b" ma ",
    b" mes ",
    b" ce ",
    b" se ",
    b" ne ",
    b" lui ",
    b" by ",
    b" of ",
    b" to ",
    b" is ",
    b" it ",
)

DECODE_OPS: tuple[tuple[str, dict[str, Any]], ...] = (
    ("from_jwt", {}),
    ("js_atob_unwrap", {}),
    ("from_powershell_encoded", {}),
    ("from_base64", {"validate": True}),
    ("from_base64", {"url_safe": True, "validate": True}),
    ("from_base32hex", {}),
    ("from_base32", {}),
    ("from_hex", {}),
    ("from_decimal", {}),
    ("from_zlib", {"max_bytes": MAX_MAGIC_OUTPUT}),
    ("url_decode", {}),
    ("from_binary", {}),
    ("from_morse", {}),
    ("from_utf16le", {}),
    ("from_utf16be", {}),
    ("from_quoted_printable", {}),
    ("from_html_entities", {}),
    ("from_unicode_escape", {}),
    ("from_uu", {}),
    ("from_base58", {}),
    ("from_base85", {"variant": "ascii85", "adobe": True}),
    ("from_base85", {"variant": "ascii85", "adobe": False}),
    ("from_base85", {"variant": "rfc1924"}),
    ("from_qr", {}),
    ("lsb_extract", {"channels": "RGB", "stop_nul": True}),
)

PERMUTE_OPS: tuple[tuple[str, dict[str, Any]], ...] = (
    ("reverse", {}),
    ("rot47", {}),
    ("rot13", {}),
    ("atbash", {}),
)

DECODE_IDS = frozenset(op_id for op_id, _params in DECODE_OPS)
SELF_INVERSE = frozenset({"reverse", "rot13", "atbash", "rot47"})
HEAVY = frozenset({"from_base58", "from_base85"})
_ALWAYS_KEEP_DECODE = frozenset({"from_hex", "from_binary", "from_decimal", "from_zlib"})
_VIGENERE_AUTO_KEYS = (
    "CLE",
    "KEY",
    "FLAG",
    "SECRET",
    "PASS",
    "PASSWORD",
    "CTF",
    "CRYPTO",
    "HIDDEN",
    "LEMON",
    "CODE",
    "TEST",
    "CASCADE",
)


@dataclass
class MagicNode:
    step: Step | None
    data: bytes
    score: float
    preview: str
    path: tuple[Step, ...]
    children: list[MagicNode] = field(default_factory=list)


@dataclass
class _Budget:
    deadline: float
    nodes: int = 0

    def ok(self) -> bool:
        return self.nodes < MAX_NODES and time.monotonic() < self.deadline


def _preview(data: bytes) -> str:
    text, _ok = decode_utf8_view(data)
    flat = " ".join(text.split())
    return flat[:180]


def _applicable(op_id: str, data: bytes) -> bool:
    if op_id in HEAVY and len(data) > 2048:
        return False
    if op_id == "from_jwt":
        return looks_jwt(data)
    if op_id == "from_hex":
        return looks_hex(data)
    if op_id == "from_decimal":
        return looks_decimal_bytes(data)
    if op_id == "from_zlib":
        return looks_zlib(data) or looks_gzip(data)
    if op_id == "url_decode":
        return looks_url(data)
    if op_id == "from_binary":
        return looks_binary(data)
    if op_id == "from_morse":
        return looks_morse(data)
    if op_id == "from_utf16le":
        return looks_utf16le(data)
    if op_id == "from_utf16be":
        return looks_utf16be(data)
    if op_id == "from_base32":
        return looks_base32(data)
    if op_id == "from_base32hex":
        return looks_base32hex(data)
    if op_id.startswith("from_base64"):
        return looks_base64(data)
    if op_id == "from_quoted_printable":
        return looks_quoted_printable(data)
    if op_id == "from_html_entities":
        return looks_html_entities(data)
    if op_id == "from_unicode_escape":
        return looks_unicode_escape(data)
    if op_id == "from_uu":
        return looks_uu(data)
    if op_id == "js_atob_unwrap":
        return looks_js_atob(data)
    if op_id == "from_powershell_encoded":
        return looks_powershell_encoded(data)
    if op_id == "from_base58":
        compact = b"".join(data.split())
        if len(compact) < 8 or len(compact) > 2048:
            return False
        alphabet = set(B58_ALPHABET)
        return all(byte in alphabet for byte in compact)
    if op_id == "from_base85":
        return looks_base85(data)
    if op_id in {"from_qr", "lsb_extract"}:
        return looks_image(data)
    return True


def _utf8_ok(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _compact_encoding(data: bytes) -> bool:
    return (
        looks_hex(data)
        or looks_base64(data)
        or looks_base32(data)
        or looks_base32hex(data)
        or looks_base85(data)
        or looks_binary(data)
        or looks_decimal_bytes(data)
        or looks_uu(data)
        or looks_morse(data)
        or looks_jwt(data)
        or looks_image(data)
    )


def _layer_flags(data: bytes) -> frozenset[str]:
    flags: set[str] = set()
    if looks_hex(data):
        flags.add("hex")
    if looks_base64(data):
        flags.add("b64")
    if looks_base32(data):
        flags.add("b32")
    if looks_base32hex(data):
        flags.add("b32h")
    if looks_base85(data):
        flags.add("b85")
    if looks_binary(data):
        flags.add("bin")
    if looks_uu(data):
        flags.add("uu")
    return frozenset(flags)


def _unlocks_new_layer(data: bytes, output: bytes) -> bool:
    return bool(_layer_flags(output) - _layer_flags(data))


def _permute_reveals_plain(data: bytes, output: bytes) -> bool:
    """True when ROT/Atbash of an encoding peels to text (or hex) the raw blob does not."""
    probes: tuple[tuple[str, dict[str, object]], ...] = (
        ("from_base64", {"validate": True}),
        ("from_base64", {"url_safe": True, "validate": True}),
        ("from_base32", {}),
        ("from_base32hex", {}),
        ("from_hex", {}),
        ("from_base85", {"variant": "rfc1924"}),
        ("from_base85", {"variant": "ascii85", "adobe": False}),
    )
    for op_id, params in probes:
        peeled = _try_one(output, op_id, params)
        if not peeled:
            continue
        baseline = _try_one(data, op_id, params)
        peeled_plain = (looks_letters(peeled) and not looks_like_layer(peeled)) or _wordy(peeled)
        base_plain = bool(
            baseline
            and (
                (looks_letters(baseline) and not looks_like_layer(baseline))
                or _wordy(baseline)
            )
        )
        if peeled_plain and not base_plain:
            return True
        if looks_hex(peeled) and not (baseline and looks_hex(baseline)):
            return True
    return False


def _stagnant_layer(data: bytes, output: bytes) -> bool:
    """Reject peels that stay on the same ambiguous encoding (false Base85, etc.)."""
    if looks_hex(output) or looks_base64(output) or looks_base32(output) or looks_base32hex(output):
        return False
    if looks_letters(output) and not looks_like_layer(output):
        return False
    if looks_base85(data) and looks_base85(output) and not looks_letters(output):
        rotated = rot47(output, {})
        if looks_hex(rotated) or looks_base64(rotated) or looks_base32(rotated) or looks_base32hex(rotated):
            return False
        flipped = atbash(output, {})
        if looks_hex(flipped) or looks_base64(flipped) or looks_base32(flipped):
            return False
        return True
    if looks_image(data) and looks_image(output):
        return True
    return False


def _keep_decode(
    data: bytes,
    output: bytes,
    score: float,
    parent_score: float,
    op_id: str,
) -> bool:
    if (
        op_id == "url_decode"
        and _utf8_ok(data)
        and not _utf8_ok(output)
        and not looks_like_layer(output)
    ):
        return False
    if _stagnant_layer(data, output):
        return False
    if looks_like_layer(output) or looks_zlib(output) or looks_gzip(output):
        return True
    if looks_letters(output):
        return True
    if op_id == "from_base85":
        return False
    if op_id in _ALWAYS_KEEP_DECODE and output and output != data:
        return True
    if score >= MIN_KEEP and score >= parent_score:
        return True
    return 0 < len(output) < len(data) and score >= 0.28


def _symbol_heavy(data: bytes) -> bool:
    sample = data[:4000]
    if not sample:
        return False
    weird = 0
    for byte in sample:
        if byte < 32 or byte > 126 or byte in b"\\<>#$~&`|{}[]^*'\"@":
            weird += 1
    return weird >= 3 and weird / len(sample) >= 0.06


def _alpha_space_ratio(data: bytes) -> float:
    sample = data[:4000]
    if not sample:
        return 0.0
    useful = 0
    for byte in sample:
        if 65 <= byte <= 90 or 97 <= byte <= 122 or byte in (9, 10, 13, 32):
            useful += 1
    return useful / len(sample)


def _is_rot47_plain(data: bytes, output: bytes, score: float, parent_score: float) -> bool:
    """True when ROT47 decoded mixed ASCII, not when it mangled already-readable letters."""
    if not output or output == data or not looks_letters(output):
        return False
    if looks_like_layer(output):
        return False
    if _alpha_space_ratio(data) >= 0.78:
        return False
    rot13_out = rot13(data, {})
    rot13_score = english_hint(rot13_out)
    if looks_letters(rot13_out) and rot13_score >= score - 0.005 and _alpha_space_ratio(rot13_out) >= _alpha_space_ratio(output):
        return False
    if _function_hits(output) > _function_hits(data) or (_wordy(output) and not _wordy(data)):
        return score >= rot13_score - 0.02
    return score >= parent_score and score >= rot13_score + 0.008


def _keep_permute(
    data: bytes,
    parent_score: float,
    output: bytes,
    score: float,
    op_id: str,
) -> bool:
    already_plain = (
        looks_letters(data)
        and not looks_like_layer(data)
        and _function_hits(data) >= 2
    )
    if already_plain:
        if op_id == "rot13":
            nxt = atbash(output, {})
            if _function_hits(nxt) > _function_hits(data):
                return True
        if op_id == "atbash":
            nxt = rot13(output, {})
            if _function_hits(nxt) > _function_hits(data):
                return True
        if op_id == "reverse":
            nxt = rot13(output, {})
            if (
                _function_hits(output) > _function_hits(data)
                or _function_hits(nxt) > _function_hits(data)
                or _function_hits(atbash(nxt, {})) > _function_hits(data)
            ):
                return True
        if not (
            _function_hits(output) > _function_hits(data)
            and (_wordy(output) or _plain_hit(output))
        ):
            return False
    if op_id == "rot47":
        letter_rot = rot13(data, {})
        if (
            letter_rot != data
            and looks_letters(letter_rot)
            and english_hint(letter_rot) >= score - 0.005
            and _alpha_space_ratio(letter_rot) >= _alpha_space_ratio(output)
        ):
            return False
    if op_id == "rot47" and _is_rot47_plain(data, output, score, parent_score):
        return True
    if _wordy(output) and (not _wordy(data) or score >= parent_score):
        return True
    if score >= parent_score + PERMUTE_GAIN:
        encoding_noise = (
            op_id in {"rot13", "atbash", "rot47"}
            and _compact_encoding(data)
            and not _unlocks_new_layer(data, output)
            and not looks_letters(output)
            and not _permute_reveals_plain(data, output)
        )
        if not encoding_noise:
            return True
    if op_id in {"rot13", "atbash", "rot47"} and _unlocks_new_layer(data, output):
        return True
    if op_id in {"rot13", "atbash", "rot47"} and _permute_reveals_plain(data, output):
        return True
    if op_id in {"rot13", "atbash", "rot47"} and looks_base85(output) and not looks_base85(data) and (
        _compact_encoding(data)
        or not looks_letters(data)
        or _symbol_heavy(data)
        or _alpha_space_ratio(data) < 0.70
    ):
        return True
    if op_id in {"rot13", "atbash"} and b" " not in data.strip() and 8 <= len(data.strip()) <= 4096:
        for params in (
            {"variant": "rfc1924"},
            {"variant": "ascii85", "adobe": False},
            {"variant": "ascii85", "adobe": True},
        ):
            peeled = _try_one(output, "from_base85", params)
            if peeled and (looks_letters(peeled) or _wordy(peeled)):
                return True
    if op_id == "rot13":
        nxt = atbash(output, {})
        if _wordy(nxt) or (_plain_hit(nxt) and looks_letters(nxt)):
            return True
    if op_id == "atbash":
        nxt = rot13(output, {})
        if _wordy(nxt) or (_plain_hit(nxt) and looks_letters(nxt)):
            return True
    if op_id == "reverse":
        if looks_hex(data) and looks_hex(output):
            return False
        if looks_reversed_encoding(data) or _reversed_plaintext(data):
            return True
        if looks_like_layer(output) and not looks_like_layer(data):
            return True
        if looks_base64(data) and looks_base64(output):
            peeled = _try_one(output, "from_base64", {"validate": True})
            original = _try_one(data, "from_base64", {"validate": True})
            if peeled and (looks_letters(peeled) or looks_like_layer(peeled) or _wordy(peeled)):
                if original is None or not looks_letters(original) or _function_hits(peeled) > _function_hits(original):
                    return True
        if looks_base32(data) and looks_base32(output):
            peeled = _try_one(output, "from_base32", {})
            if peeled and (looks_letters(peeled) or looks_like_layer(peeled)):
                return True
        if score >= parent_score + PERMUTE_GAIN and not looks_base64(data) and not looks_hex(data):
            return True
        return False
    return looks_like_layer(output) and not looks_like_layer(data)


def _try_one(data: bytes, op_id: str, params: dict[str, Any]) -> bytes | None:
    try:
        output = get_op(op_id).run(data, params)
    except Exception:
        return None
    if output is None or len(output) > MAX_MAGIC_OUTPUT:
        return None
    return output


def _xor_plain_hit(data: bytes, output: bytes, score: float, parent_score: float) -> bool:
    if output == data or score < parent_score + 0.06:
        return False
    return looks_letters(output) and _plain_hit(output)


def _best_xor_byte(data: bytes, parent_score: float) -> tuple[Step, bytes, float] | None:
    best_key = 0
    best_out = b""
    best_score = parent_score
    for key in range(1, 256):
        out = bytes(byte ^ key for byte in data)
        score = english_hint(out)
        if score > best_score:
            best_score = score
            best_key = key
            best_out = out
    if not best_out or not _xor_plain_hit(data, best_out, best_score, parent_score):
        return None
    return (
        Step("xor", {"key": f"{best_key:02x}", "key_format": "hex"}),
        best_out,
        best_score,
    )


def _try_branch(data: bytes, last_op: str | None) -> list[tuple[Step, bytes, float]]:
    parent_score = english_hint(data)
    decodes: list[tuple[Step, bytes, float]] = []
    permutes: list[tuple[Step, bytes, float]] = []
    seen_out: set[bytes] = set()

    def consider(op_id: str, params: dict[str, Any], permute: bool) -> None:
        if last_op == op_id and op_id in SELF_INVERSE:
            return
        if not permute and not _applicable(op_id, data):
            return
        output = _try_one(data, op_id, params)
        if output is None or not output or output == data or output in seen_out:
            return
        score = english_hint(output)
        keep = (
            _keep_permute(data, parent_score, output, score, op_id)
            if permute
            else _keep_decode(data, output, score, parent_score, op_id)
        )
        if not keep:
            return
        seen_out.add(output)
        item = (Step(op_id, dict(params)), output, score)
        (permutes if permute else decodes).append(item)

    for op_id, params in DECODE_OPS:
        consider(op_id, params, permute=False)
    rot47_plain = False
    rot47_probe = _try_one(data, "rot47", {})
    if rot47_probe:
        rot47_plain = _is_rot47_plain(
            data, rot47_probe, english_hint(rot47_probe), parent_score
        )

    for op_id, params in PERMUTE_OPS:
        if looks_reversed_encoding(data) and op_id != "reverse":
            continue
        if rot47_plain and op_id in {"rot13", "atbash"}:
            probe = rot13(data, {}) if op_id == "rot13" else atbash(data, {})
            if not looks_like_layer(probe):
                continue
        if op_id == "rot47" and not rot47_plain:
            probe = rot47_probe
            unlocks = bool(
                probe
                and (
                    looks_hex(probe)
                    or looks_base32(probe)
                    or looks_base32hex(probe)
                )
            )
            letters_plain = bool(
                probe
                and looks_letters(probe)
                and not looks_like_layer(probe)
                and _alpha_space_ratio(probe) >= 0.70
            )
            if looks_hex(data) or looks_base64(data) or looks_base32(data) or looks_base32hex(data):
                if not unlocks:
                    continue
            if looks_base85(data) and not unlocks and not letters_plain:
                continue
            if looks_binary(data) or looks_decimal_bytes(data) or looks_uu_header(data):
                continue
        if op_id == "atbash" and (
            looks_hex(data)
            or looks_binary(data)
            or looks_decimal_bytes(data)
            or looks_uu_header(data)
        ):
            continue
        consider(op_id, params, permute=True)

    if (
        last_op != "rot_n"
        and not rot47_plain
        and not _compact_encoding(data)
        and looks_letters(data)
        and len(data) <= 8000
    ):
        parent_hits = _function_hits(data)

        def _rot_quality(buf: bytes) -> int:
            hits = _function_hits(buf)
            flipped = atbash(buf, {})
            rotated = rot13(buf, {})
            return max(hits, _function_hits(flipped), _function_hits(rotated), _function_hits(atbash(rotated, {})))

        parent_q = _rot_quality(data)
        best_n = 0
        best_out = b""
        best_score = parent_score
        best_q = parent_q
        for shift in range(1, 26):
            out = _rot_bytes(data, shift)
            if not out or out == data or out in seen_out:
                continue
            quality = _rot_quality(out)
            score = english_hint(out)
            if quality > best_q or (quality == best_q and score > best_score):
                best_q = quality
                best_score = score
                best_n = shift
                best_out = out
        if best_n and best_q >= 2 and best_q > parent_hits and (
            best_q >= parent_q + 1 or _function_hits(best_out) > parent_hits
        ):
            seen_out.add(best_out)
            permutes.append((Step("rot_n", {"n": best_n}), best_out, best_score))

    if (
        last_op != "vigenere"
        and looks_letters(data)
        and not looks_like_layer(data)
        and b" " in data
        and 12 <= len(data) <= 8000
    ):
        parent_hits = _function_hits(data)
        best_key = ""
        best_out = b""
        best_score = parent_score
        best_hits = parent_hits
        for key in _VIGENERE_AUTO_KEYS:
            out = vigenere(data, {"key": key, "decrypt": True})
            if not out or out == data or out in seen_out:
                continue
            score = english_hint(out)
            hits = _function_hits(out)
            if hits < 2 or hits < parent_hits + 2 or not (_wordy(out) or _plain_hit(out)):
                continue
            if hits > best_hits or (hits == best_hits and score > best_score):
                best_score = score
                best_key = key
                best_out = out
                best_hits = hits
        if best_key and best_hits >= parent_hits + 2:
            seen_out.add(best_out)
            permutes.append(
                (Step("vigenere", {"key": best_key, "decrypt": True}), best_out, best_score)
            )

    try_xor = last_op in {"from_hex", "from_binary", "from_decimal"}
    if try_xor and last_op != "xor" and 12 <= len(data) <= 8192:
        hit = _best_xor_byte(data, parent_score)
        if hit is not None and hit[1] not in seen_out:
            seen_out.add(hit[1])
            decodes.append(hit)

    decodes.sort(key=lambda item: item[2], reverse=True)
    permutes.sort(key=lambda item: item[2], reverse=True)
    compact_layer = _compact_encoding(data)
    layer_permutes = [
        item
        for item in permutes
        if item[0].op_id in {"atbash", "rot13", "reverse", "rot47"}
        and (
            looks_like_layer(item[1])
            and (
                _unlocks_new_layer(data, item[1])
                or _permute_reveals_plain(data, item[1])
            )
        )
    ]
    decoded_plain = any(
        looks_letters(item[1]) or _wordy(item[1])
        for item in decodes
        if item[0].op_id.startswith("from_")
    )
    if (
        layer_permutes
        and not decoded_plain
        and (
            looks_base64(data)
            or looks_base32(data)
            or looks_base32hex(data)
            or looks_base85(data)
        )
    ):
        rest = [item for item in permutes if item not in layer_permutes]
        return (
            layer_permutes[:MAX_PERMUTE_BRANCHES]
            + decodes[:MAX_DECODE_BRANCHES]
            + rest[:MAX_PERMUTE_BRANCHES]
        )
    # Spaced ROT/plaintext first: false Base85 otherwise eats the node budget.
    if b" " in data and not compact_layer:
        return permutes[:MAX_PERMUTE_BRANCHES] + decodes[:MAX_DECODE_BRANCHES]
    return decodes[:MAX_DECODE_BRANCHES] + permutes[:MAX_PERMUTE_BRANCHES]


def _permute_improves(data: bytes) -> bool:
    hits = _function_hits(data)
    parent = english_hint(data)
    rotated = rot13(data, {})
    if _function_hits(rotated) > hits or (
        looks_letters(rotated) and english_hint(rotated) >= parent + 0.03
    ):
        return True
    flipped = atbash(data, {})
    if _function_hits(flipped) > hits or (
        looks_letters(flipped) and english_hint(flipped) >= parent + 0.03
    ):
        return True
    combo = atbash(rotated, {})
    if _function_hits(combo) > hits or (
        looks_letters(combo) and english_hint(combo) >= parent + 0.03
    ):
        return True
    rev = data[::-1]
    if _function_hits(rev) > hits:
        return True
    rev_rot = rot13(rev, {})
    if _function_hits(rev_rot) > hits:
        return True
    if _function_hits(atbash(rev_rot, {})) > hits:
        return True
    if looks_letters(data) and hits < 2 and len(data) <= 8000:
        for shift in range(1, 26):
            out = _rot_bytes(data, shift)
            if _function_hits(out) > hits:
                return True
            if _function_hits(atbash(out, {})) > hits:
                return True
            if _function_hits(rot13(out, {})) > hits:
                return True
            if looks_letters(out) and english_hint(out) >= parent + 0.05:
                return True
    return False


def _should_peel(step: Step, output: bytes, path: tuple[Step, ...]) -> bool:
    if looks_like_layer(output):
        return True
    if step.op_id in {"from_hex", "from_binary", "from_decimal"}:
        return True
    if looks_reversed_encoding(output) or _reversed_plaintext(output):
        return True
    readable = looks_letters(output) and not looks_like_layer(output)
    if step.op_id == "rot47":
        return looks_like_layer(output)
    permute_count = sum(
        1 for item in path if item.op_id in SELF_INVERSE or item.op_id == "rot_n"
    )
    improves = _permute_improves(output)
    if readable and not improves:
        if _function_hits(output) >= 2:
            return False
        if _alpha_space_ratio(output) >= 0.75:
            return False
    if readable:
        return permute_count < 3
    if step.op_id in DECODE_IDS:
        return True
    if permute_count >= 2:
        return False
    return looks_letters(output) or looks_reversed_encoding(output)


def explore(data: bytes, *, depth: int = MAX_MAGIC_DEPTH) -> list[MagicNode]:
    if len(data) > MAX_MAGIC_BYTES:
        raise DecodeError(
            f"Trop volumineux pour le mode auto ({len(data)} octets).",
            f"Too large for auto mode ({len(data)} bytes).",
        )
    stripped = data.strip()
    digest = hash_digest_kind(stripped)
    if digest:
        preview = _preview(stripped)
        return [
            MagicNode(
                step=None,
                data=stripped,
                score=0.12,
                preview=preview,
                path=(),
            )
        ]
    budget = _Budget(deadline=time.monotonic() + TIME_BUDGET_SEC)
    nodes = _walk(
        stripped,
        remaining=depth,
        seen={sha256(stripped).digest()},
        path=(),
        last_op=None,
        budget=budget,
    )
    return _rank_tree(nodes)


def flatten_nodes(nodes: list[MagicNode]) -> list[MagicNode]:
    flat: list[MagicNode] = []
    for node in nodes:
        flat.append(node)
        flat.extend(flatten_nodes(node.children))
    return flat


def _branch_score(node: MagicNode) -> float:
    best = node.score
    for child in node.children:
        best = max(best, _branch_score(child))
    return best


def _rank_tree(nodes: list[MagicNode]) -> list[MagicNode]:
    for node in nodes:
        node.children = _rank_tree(node.children)
    return sorted(nodes, key=_branch_score, reverse=True)


def _reversed_plaintext(data: bytes) -> bool:
    if len(data) < 4:
        return False
    return english_hint(data[::-1]) >= english_hint(data) + 0.04


def _wordy(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    words: list[str] = []
    for word in text.split():
        letters = sum(ch.isalpha() for ch in word)
        if letters >= 3 and letters / max(len(word), 1) >= 0.7:
            words.append(word)
    useful = sum(
        ch.isalpha() or ch.isspace() or ch in ".,;:'-!?«»“”#%" for ch in text
    )
    if not text or useful / len(text) < 0.58:
        return False
    if len(words) >= 3:
        return True
    if len(words) >= 2 and len(text) <= 80 and _function_hits(data) > 0:
        return True
    return len(words) >= 1 and len(text) <= 28 and _function_hits(data) > 0


def _plain_hit(data: bytes) -> bool:
    return _function_hits(data) > 0


def _digit_heavy(data: bytes) -> bool:
    sample = data[:4000]
    if not sample:
        return False
    digits = sum(48 <= byte <= 57 for byte in sample)
    letters = sum(65 <= byte <= 90 or 97 <= byte <= 122 for byte in sample)
    if letters / len(sample) >= 0.45:
        return False
    return digits / len(sample) >= 0.15


def _function_hits(data: bytes) -> int:
    if _digit_heavy(data):
        return 0
    padded = (
        b" "
        + data.lower()
        .replace(b":", b" ")
        .replace(b",", b" ")
        .replace(b".", b" ")
        .replace(b"'", b" ")
        .replace(b"\xe2\x80\x99", b" ")
        + b" "
    )
    return sum(1 for token in _PLAIN_TOKENS if token in padded)


_NOISE_OPS = SELF_INVERSE | {"rot_n", "xor", "vigenere"}


def _noise_ops(path: tuple[Step, ...] | list[Step]) -> int:
    return sum(1 for step in path if step.op_id in _NOISE_OPS)


def _node_rank(node: MagicNode) -> tuple:
    text, utf8_ok = decode_utf8_view(node.data)
    printable = utf8_ok and all(ch.isprintable() or ch in "\n\r\t" for ch in text)
    still_encoded = looks_like_layer(node.data) and not looks_letters(node.data)
    reversed_text = _reversed_plaintext(node.data)
    hits = _function_hits(node.data)
    rot_noise = any(step.op_id == "rot_n" for step in node.path) and hits == 0
    has_decode = any(
        step.op_id in DECODE_IDS or step.op_id.startswith("from_") for step in node.path
    )
    return (
        printable,
        hits,
        hits > 0,
        _wordy(node.data),
        not still_encoded,
        not reversed_text,
        not rot_noise,
        not _digit_heavy(node.data),
        has_decode,
        -_noise_ops(node.path),
        _alpha_space_ratio(node.data),
        node.score,
        -len(node.path),
    )


def best_node(nodes: list[MagicNode]) -> MagicNode | None:
    flat = flatten_nodes(nodes)
    if not flat:
        return None
    return max(flat, key=_node_rank)


def confidence_pct(node: MagicNode) -> int:
    (
        printable,
        hits,
        plain,
        wordy,
        decoded_layer,
        not_reversed,
        not_rot_noise,
        not_digits,
        has_decode,
        neg_noise,
        _alpha,
        raw_score,
        _depth,
    ) = _node_rank(node)
    pct = int(round(min(1.0, max(0.0, float(raw_score) / 1.25)) * 40))
    pct += min(24, int(hits) * 8)
    if printable:
        pct += 12
    if wordy:
        pct += 12
    if plain:
        pct += 8
    if decoded_layer:
        pct += 6
    if has_decode:
        pct += 8
    if not not_digits:
        pct -= 14
    pct += max(-12, int(neg_noise) * 4)
    if not not_reversed:
        pct -= 16
    if not not_rot_noise:
        pct -= 20
    return max(8, min(98, pct))


def top_nodes(nodes: list[MagicNode], limit: int = 3) -> list[MagicNode]:
    ranked = sorted(flatten_nodes(nodes), key=_node_rank, reverse=True)
    picked: list[MagicNode] = []
    seen: set[bytes] = set()
    for node in ranked:
        if node.data in seen:
            continue
        seen.add(node.data)
        picked.append(node)
        if len(picked) >= limit:
            break
    return picked


def format_path(path: tuple[Step, ...] | list[Step], lang: str) -> str:
    labels: list[str] = []
    for step in path:
        op = get_op(step.op_id)
        labels.append(op.label(lang))
    return " → ".join(labels)


def _walk(
    data: bytes,
    *,
    remaining: int,
    seen: set[bytes],
    path: tuple[Step, ...],
    last_op: str | None,
    budget: _Budget,
) -> list[MagicNode]:
    nodes: list[MagicNode] = []
    if not budget.ok():
        return nodes
    for step, output, score in _try_branch(data, last_op):
        if not budget.ok():
            break
        digest = sha256(output).digest()
        if digest in seen:
            continue
        budget.nodes += 1
        child_seen = set(seen)
        child_seen.add(digest)
        new_path = path + (step,)
        node = MagicNode(
            step=step,
            data=output,
            score=score,
            preview=_preview(output),
            path=new_path,
        )
        next_remaining = remaining - 1
        if remaining > 1 and _should_peel(step, output, new_path):
            node.children = _walk(
                output,
                remaining=next_remaining,
                seen=child_seen,
                path=new_path,
                last_op=step.op_id,
                budget=budget,
            )
        nodes.append(node)
    return nodes
