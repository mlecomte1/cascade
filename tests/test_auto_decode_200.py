from __future__ import annotations

import base64
import hashlib
import json

import pytest

from cascade.engine.detect import hash_digest_kind
from cascade.engine.magic import best_node, explore
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
    to_hex,
    to_html_entities,
    to_morse,
    to_unicode_escape,
    to_uu,
    to_utf16le,
    to_zlib,
    url_encode,
)

# Auto recoverability cases (explore / best_node).

_MSGS = (
    b"Le message secret de Cascade est pret pour le test.",
    b"Hello world from the offline decoder today.",
    b"Encore une phrase avec des mots pour le moteur auto.",
    b"Premier essai de decodage automatique sans chiffrement.",
    b"The quick brown fox stays readable after every layer.",
)

_RFC = {"variant": "rfc1924"}
_A85 = {"variant": "ascii85", "adobe": False}


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


def _jwt(sub: str) -> bytes:
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": sub, "offline": True}).encode()
    ).rstrip(b"=")
    return header + b"." + payload + b"."


def _atob(text: bytes) -> bytes:
    inner = _b64(text).decode("ascii")
    return f'eval(atob("{inner}"))'.encode("ascii")


def _build_cases() -> list[tuple[str, bytes, bytes, str]]:
    cases: list[tuple[str, bytes, bytes, str]] = []

    def add(name: str, payload: bytes, expected: bytes, mode: str = "exact") -> None:
        cases.append((name, payload, expected, mode))

    singles = (
        ("b64", _b64),
        ("b32", _b32),
        ("b32hex", _b32h),
        ("hex", _hex),
        ("b85rfc", _b85),
        ("b85a85", lambda p: _b64(to_base85(p, _A85))),
        ("b58", lambda p: to_base58(p, {})),
        ("uu", lambda p: to_uu(p, {})),
        ("html", lambda p: _b64(to_html_entities(p, {}))),
        ("uni", lambda p: _b64(to_unicode_escape(p, {}))),
        ("url", lambda p: url_encode(p, {"safe": ""})),
        ("zlib_b64", lambda p: _b64(to_zlib(p, {}))),
        ("bin_b64", lambda p: _b64(to_binary(p, {"grouped": True}))),
        ("utf16_b64", lambda p: _b64(to_utf16le(p, {}))),
        ("morse_b64", lambda p: _b64(to_morse(p, {}))),
    )
    for msg_i, msg in enumerate(_MSGS):
        for name, encode in singles:
            expected = msg.upper() if name == "morse_b64" else msg
            add(f"s_{name}_{msg_i}", encode(msg), expected)

    doubles = (
        ("b64_hex", lambda p: _b64(_hex(p))),
        ("hex_b64", lambda p: _hex(_b64(p))),
        ("b32_b64", lambda p: _b32(_b64(p))),
        ("b64_b32", lambda p: _b64(_b32(p))),
        ("hex_b32", lambda p: _hex(_b32(p))),
        ("b32_hex", lambda p: _b32(_hex(p))),
        ("b85_b64", lambda p: _b85(_b64(p))),
        ("b64_b85", lambda p: _b64(_b85(p))),
        ("b32h_b64", lambda p: _b32h(_b64(p))),
        ("b64_b32h", lambda p: _b64(_b32h(p))),
        ("hex_b85", lambda p: _hex(_b85(p))),
        ("b32_b85", lambda p: _b32(_b85(p))),
    )
    for msg_i, msg in enumerate(_MSGS[:4]):
        for name, encode in doubles:
            add(f"d_{name}_{msg_i}", encode(msg), msg)

    triples = (
        ("b32_hex_b64", lambda p: _b32(_hex(_b64(p)))),
        ("b64_b32_hex", lambda p: _b64(_b32(_hex(p)))),
        ("hex_b64_b85", lambda p: _hex(_b64(_b85(p)))),
        ("b64_b85_b32", lambda p: _b64(_b85(_b32(p)))),
        ("hex_b32_b64", lambda p: _hex(_b32(_b64(p)))),
        ("b64_hex_b32", lambda p: _b64(_hex(_b32(p)))),
        ("b32_b64_hex", lambda p: _b32(_b64(_hex(p)))),
        ("b85_hex_b64", lambda p: _b85(_hex(_b64(p)))),
    )
    for msg_i, msg in enumerate(_MSGS[:3]):
        for name, encode in triples:
            add(f"t_{name}_{msg_i}", encode(msg), msg)

    permutes = (
        ("rot13_b64", lambda p: _b64(rot13(p, {}))),
        ("rot13_hex", lambda p: _hex(rot13(p, {}))),
        ("atbash_b64", lambda p: _b64(atbash(p, {}))),
        ("atbash_hex", lambda p: _hex(atbash(p, {}))),
        ("rev_b64", lambda p: _b64(p[::-1])),
        ("rot47_hex", lambda p: _hex(rot47(p, {}))),
        ("rot5_b64", lambda p: _b64(rot_n(p, {"n": 5}))),
        ("rot13_b32", lambda p: _b32(rot13(p, {}))),
        ("rev_b32", lambda p: _b32(p[::-1])),
        ("atbash_b32", lambda p: _b32(atbash(p, {}))),
    )
    for msg_i, msg in enumerate(_MSGS[:3]):
        for name, encode in permutes:
            add(f"p_{name}_{msg_i}", encode(msg), msg)

    mixed = (
        ("b64_rev_b64", lambda p: _b64(_b64(p)[::-1])),
        ("b32_rot13_b64", lambda p: _b32(rot13(_b64(p), {}))),
        ("hex_atbash_b32", lambda p: _hex(atbash(_b32(p), {}))),
        ("b85_rot13_hex", lambda p: _b85(rot13(_hex(p), {}))),
        ("b64_rot47_hex", lambda p: _b64(rot47(_hex(p), {}))),
        ("hex_rev_b64", lambda p: _hex(_b64(p)[::-1])),
    )
    for msg_i, msg in enumerate(_MSGS[:2]):
        for name, encode in mixed:
            add(f"m_{name}_{msg_i}", encode(msg), msg)

    noise_msg = _MSGS[0]
    wrapped_b64 = _b64(noise_msg)
    add(
        "n_b64_wrap",
        b"\n".join(wrapped_b64[i : i + 16] for i in range(0, len(wrapped_b64), 16)),
        noise_msg,
    )
    add("n_hex_spaces", b" ".join(_hex(noise_msg)[i : i + 2] for i in range(0, 24, 2)) + _hex(noise_msg)[24:], noise_msg)
    add("n_hex_0x", b"0x" + _hex(noise_msg), noise_msg)
    add("n_b64_nopad", _b64(noise_msg).rstrip(b"="), noise_msg)
    add("n_b32_lower", _b32(noise_msg).lower(), noise_msg)
    add("n_b64_url", to_base64(noise_msg, {"url_safe": True, "padding": True}), noise_msg)
    add("n_b64_spaces", _b64(noise_msg)[:20] + b" " + _b64(noise_msg)[20:], noise_msg)
    add("n_hex_upper", _hex(noise_msg).upper(), noise_msg)
    add("n_b85_nl", _b85(noise_msg)[:20] + b"\n" + _b85(noise_msg)[20:], noise_msg)
    add("n_html_b64", _b64(to_html_entities(noise_msg, {})), noise_msg)

    add("c_atob", _atob(_MSGS[1]), _MSGS[1], "contains")
    add("c_jwt", _jwt("cascade-user"), b"cascade-user", "contains")

    for algo, blob in (
        ("md5", hashlib.md5(b"hello").hexdigest().encode()),
        ("sha1", hashlib.sha1(b"hello").hexdigest().encode()),
        ("sha256", hashlib.sha256(b"hello").hexdigest().encode()),
        ("sha512", hashlib.sha512(b"hello").hexdigest().encode()),
    ):
        add(f"h_{algo}", blob, blob, "one_way")

    # Pad / trim to exactly 200 without touching application code.
    extra_i = 0
    while len(cases) < 200:
        msg = _MSGS[extra_i % len(_MSGS)]
        add(f"x_b64_hex_{extra_i}", _b64(_hex(msg)), msg)
        extra_i += 1
    return cases[:200]


CASES = _build_cases()
assert len(CASES) == 200
assert len({name for name, *_ in CASES}) == 200


@pytest.mark.parametrize("case_id,payload,expected,mode", CASES, ids=[c[0] for c in CASES])
def test_auto_decode_200(case_id: str, payload: bytes, expected: bytes, mode: str) -> None:
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
