from __future__ import annotations

import base64
import gzip
import hashlib
import json
import quopri
import zlib

import pytest

from cascade.engine.detect import hash_digest_kind
from cascade.engine.magic import best_node, explore
from cascade.engine.ops.ciphers import vigenere, xor_bytes
from cascade.engine.ops.encodings import (
    atbash,
    rot13,
    rot47,
    rot_n,
    to_base32,
    to_base32hex,
    to_base58,
    to_base64,
    to_base85,
    to_binary,
    to_decimal,
    to_hex,
    to_html_entities,
    to_morse,
    to_unicode_escape,
    to_uu,
    to_utf16be,
    to_utf16le,
    to_zlib,
    url_encode,
)

_MSGS = (
    b"Voici une autre phrase francaise pour valider Auto.",
    b"Another english sentence used only for the second batch.",
    b"Cascade decode sans reseau et sans historique disque.",
    b"Les couches empilees doivent toutes se derouler ici.",
    b"Readable words keep the ranking engine honest today.",
)

# Previously Auto stopped on these exact shapes (batch 1).
_LEGACY = (
    b"Hello world from the offline decoder today.",
    b"Encore une phrase avec des mots pour le moteur auto.",
    b"The quick brown fox stays readable after every layer.",
    b"Le message secret de Cascade est pret pour le test.",
)

_RFC = {"variant": "rfc1924"}
_A85 = {"variant": "ascii85", "adobe": False}
_ADOBE = {"variant": "ascii85", "adobe": True}


def _b64(data: bytes) -> bytes:
    return to_base64(data, {})


def _b32(data: bytes) -> bytes:
    return to_base32(data, {})


def _hex(data: bytes) -> bytes:
    return to_hex(data, {})


def _b85(data: bytes) -> bytes:
    return to_base85(data, _RFC)


def _b32h(data: bytes) -> bytes:
    return to_base32hex(data, {})


def _a85(data: bytes) -> bytes:
    return to_base85(data, _A85)


def _gzip(data: bytes) -> bytes:
    return gzip.compress(data)


def _ps(data: bytes) -> bytes:
    blob = base64.b64encode(data.decode("utf-8").encode("utf-16-le")).decode("ascii")
    return f"powershell -EncodedCommand {blob}".encode("ascii")


def _jwt(sub: str) -> bytes:
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": sub, "offline": True}).encode()
    ).rstrip(b"=")
    return header + b"." + payload + b"."


def _atob(text: bytes) -> bytes:
    inner = _b64(text).decode("ascii")
    return f'atob("{inner}")'.encode("ascii")


def _build_cases() -> list[tuple[str, bytes, bytes, str]]:
    cases: list[tuple[str, bytes, bytes, str]] = []

    def add(name: str, payload: bytes, expected: bytes, mode: str = "exact") -> None:
        cases.append((name, payload, expected, mode))

    # --- Previously failing Auto shapes (must pass now) ---
    for i, msg in enumerate(_LEGACY):
        add(f"legacy_a85_{i}", _a85(msg), msg)
        add(f"legacy_a85_b64_{i}", _b64(_a85(msg)), msg)
        add(f"legacy_b32_b64_{i}", _b32(_b64(msg)), msg)
        add(f"legacy_hex_b32_b64_{i}", _hex(_b32(_b64(msg))), msg)
        add(f"legacy_b32_b85_{i}", _b32(_b85(msg)), msg)
        add(f"legacy_b32_b64_hex_{i}", _b32(_b64(_hex(msg))), msg)

    singles = (
        ("b64", _b64),
        ("b32", _b32),
        ("b32hex", _b32h),
        ("hex", _hex),
        ("b85rfc", _b85),
        ("a85", _a85),
        ("adobe", lambda p: to_base85(p, _ADOBE)),
        ("b58", lambda p: to_base58(p, {})),
        ("uu", lambda p: to_uu(p, {})),
        ("url", lambda p: url_encode(p, {"safe": ""})),
        ("decimal", lambda p: to_decimal(p, {})),
        ("gzip_b64", lambda p: _b64(_gzip(p))),
        ("zlib_hex", lambda p: _hex(to_zlib(p, {}))),
        ("bin", lambda p: to_binary(p, {"grouped": True})),
        ("utf16be_b64", lambda p: _b64(to_utf16be(p, {}))),
        ("qp_b64", lambda p: _b64(quopri.encodestring(p))),
        ("morse_b64", lambda p: _b64(to_morse(p, {}))),
    )
    for msg_i, msg in enumerate(_MSGS):
        for name, encode in singles:
            expected = msg.upper() if name == "morse_b64" else msg
            add(f"s_{name}_{msg_i}", encode(msg), expected)

    doubles = (
        ("hex_colon", lambda p: to_hex(p, {"separator": "colon"})),
        ("hex_slashx", lambda p: b"".join(f"\\x{b:02x}".encode() for b in p)),
        ("b64_url_nopad", lambda p: to_base64(p, {"url_safe": True, "padding": False})),
        ("dec_comma", lambda p: to_decimal(p, {}).replace(b" ", b", ")),
        ("b64_a85", lambda p: _b64(_a85(p))),
        ("hex_adobe", lambda p: _hex(to_base85(p, _ADOBE))),
        ("b32_utf16le", lambda p: _b32(to_utf16le(p, {}))),
        ("b85_b32h", lambda p: _b85(_b32h(p))),
        ("url_b64", lambda p: _b64(url_encode(p, {"safe": ""}))),
        ("gzip_hex", lambda p: _hex(_gzip(p))),
    )
    for msg_i, msg in enumerate(_MSGS[:4]):
        for name, encode in doubles:
            add(f"d_{name}_{msg_i}", encode(msg), msg)

    triples = (
        ("b64_hex_a85", lambda p: _b64(_hex(_a85(p)))),
        ("hex_b64_dec", lambda p: _hex(_b64(to_decimal(p, {})))),
        ("b32_hex_b85", lambda p: _b32(_hex(_b85(p)))),
        ("b64_b32_a85", lambda p: _b64(_b32(_a85(p)))),
        ("hex_url_b64", lambda p: _hex(_b64(url_encode(p, {"safe": ""})))),
    )
    for msg_i, msg in enumerate(_MSGS[:3]):
        for name, encode in triples:
            add(f"t_{name}_{msg_i}", encode(msg), msg)

    permutes = (
        ("rot47_b64", lambda p: _b64(rot47(p, {}))),
        ("rot13_a85", lambda p: _b64(rot13(_a85(p), {}))),
        ("atbash_b85", lambda p: _b85(atbash(p, {}))),
        ("rev_hex", lambda p: _hex(p[::-1])),
        ("rot7_b64", lambda p: _b64(rot_n(p, {"n": 7}))),
        ("rot13_b85", lambda p: _b85(rot13(p, {}))),
        ("atbash_hex", lambda p: _hex(atbash(p, {}))),
        ("rev_b64_b32", lambda p: _b64(_b32(p)[::-1])),
    )
    for msg_i, msg in enumerate(_MSGS[:3]):
        for name, encode in permutes:
            add(f"p_{name}_{msg_i}", encode(msg), msg)

    for msg_i, msg in enumerate(_MSGS):
        xored = xor_bytes(msg, {"key": "42", "key_format": "hex"})
        add(f"xor_hex_{msg_i}", _hex(xored), msg)

    for key in ("CASCADE", "SECRET", "LEMON"):
        for msg_i, msg in enumerate(_MSGS[:3]):
            add(
                f"vig_{key.lower()}_{msg_i}",
                vigenere(msg, {"key": key, "decrypt": False}),
                msg,
            )

    accent = "Cafe creme: encore une phrase avec des mots.".encode("utf-8")
    add("accent_uni", to_unicode_escape(accent, {}), accent)
    add("accent_uni_b64", _b64(to_unicode_escape(accent, {})), accent)
    html_src = b"Hello & world from <Cascade> for the test."
    add("html_raw", to_html_entities(html_src, {}), html_src)
    add("html_b64", _b64(to_html_entities(html_src, {})), html_src)

    add("c_ps", _ps(_MSGS[0]), _MSGS[0])
    add("c_ps2", _ps(_MSGS[2]), _MSGS[2])
    add("c_atob", _atob(_MSGS[1]), _MSGS[1], "contains")
    add("c_jwt", _jwt("batch-two-user"), b"batch-two-user", "contains")

    add("h_sha256", hashlib.sha256(b"cascade-batch2").hexdigest().encode(), hashlib.sha256(b"cascade-batch2").hexdigest().encode(), "one_way")
    add("h_md5", hashlib.md5(b"cascade-batch2").hexdigest().encode(), hashlib.md5(b"cascade-batch2").hexdigest().encode(), "one_way")

    extra_i = 0
    while len(cases) < 200:
        msg = _MSGS[extra_i % len(_MSGS)]
        add(f"x_b85_hex_{extra_i}", _b85(_hex(msg)), msg)
        extra_i += 1
    return cases[:200]


CASES = _build_cases()
assert len(CASES) == 200, len(CASES)
assert len({name for name, *_ in CASES}) == 200


@pytest.mark.parametrize("case_id,payload,expected,mode", CASES, ids=[c[0] for c in CASES])
def test_auto_decode_batch2(case_id: str, payload: bytes, expected: bytes, mode: str) -> None:
    chosen = best_node(explore(payload))
    assert chosen is not None, case_id
    if mode == "one_way":
        kind = hash_digest_kind(payload)
        assert kind is not None, case_id
        assert chosen.path == ()
        assert chosen.data == expected
        return
    if mode == "contains":
        assert expected in chosen.data, case_id
        return
    assert chosen.data == expected, case_id
