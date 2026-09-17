from __future__ import annotations

from cascade.engine.ops.encodings import (
    from_base32,
    from_base32hex,
    from_base58,
    from_base64,
    from_base85,
    from_binary,
    from_hex,
    from_morse,
    from_uu,
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
    to_morse,
    to_uu,
    url_decode,
    url_encode,
)
from cascade.engine.recipe import run_steps
from cascade.engine.types import Step


def test_base64_roundtrip() -> None:
    raw = b"Cascade offline decoder"
    encoded = to_base64(raw, {"url_safe": False, "padding": True})
    assert from_base64(encoded, {"url_safe": False}) == raw
    url = to_base64(raw, {"url_safe": True, "padding": False})
    assert from_base64(url, {"url_safe": True}) == raw


def test_base64_missing_padding() -> None:
    assert from_base64(b"YWJj", {}) == b"abc"


def test_hex_noise() -> None:
    assert from_hex(b"0x48 65\\x6c6C6F", {}) == b"Hello"


def test_hex_per_byte_0x_prefix() -> None:
    assert from_hex(b"0x48 0x65 0x6c 0x6c 0x6f", {}) == b"Hello"
    assert from_hex(b"0X52, 0x4F, 0x54", {}) == b"ROT"
    assert from_hex(b"\\x48\\x65\\x6c\\x6c\\x6f", {}) == b"Hello"


def test_base32hex_roundtrip() -> None:
    raw = b"Hello from base32hex"
    encoded = to_base32hex(raw, {})
    assert b"W" not in encoded
    assert from_base32hex(encoded, {}) == raw
    assert from_base32hex(encoded.lower().rstrip(b"="), {}) == raw
    wrapped = b"\n".join(encoded[i : i + 10] for i in range(0, len(encoded), 10))
    assert from_base32hex(wrapped, {}) == raw


def test_uu_roundtrip() -> None:
    raw = b"Hello from uuencode"
    encoded = to_uu(raw, {})
    assert encoded.lstrip().startswith(b"begin ")
    assert from_uu(encoded, {}) == raw
    named = encoded.replace(b"begin 644 -", b"begin 644 hello.txt", 1)
    assert from_uu(named, {}) == raw
    b64_uu = b"begin-base64 644 hello.txt\nSGVsbG8gZnJvbSB1dWVuY29kZQ==\n====\n"
    assert from_uu(b64_uu, {}) == raw


def test_rot47_roundtrip() -> None:
    raw = b"ROT47 couvre plus de caracteres que ROT13!"
    assert rot47(rot47(raw, {}), {}) == raw


def test_rot47_shifts_digits_and_symbols() -> None:
    raw = b"ABC 123 !@#"
    encoded = rot47(raw, {})
    assert encoded != rot13(raw, {})
    assert b"123" not in encoded
    assert b"ABC" not in encoded
    assert encoded != raw
    assert rot47(encoded, {}) == raw
    from cascade.engine.recipe import run_steps
    from cascade.engine.types import Step

    baked = run_steps(raw, [Step("rot47", {})])
    assert baked.data == encoded
    assert baked.data != rot13(raw, {})


def test_rot47_not_confused_with_url() -> None:
    from cascade.engine.detect import looks_url

    raw = b"ROT47 couvre plus de caracteres que ROT13!"
    encoded = rot47(raw, {})
    assert b"%cf" in encoded.lower()
    assert not looks_url(encoded)
    assert url_decode(b"Hello%20World", {}) == b"Hello World"


def test_base32_roundtrip() -> None:
    raw = b"hello"
    assert from_base32(to_base32(raw, {}), {}) == raw


def test_base58_roundtrip() -> None:
    raw = b"\x00\x00hello"
    assert from_base58(to_base58(raw, {}), {}) == raw


def test_base85_roundtrip() -> None:
    raw = b"payload-bytes-01"
    assert from_base85(to_base85(raw, {"variant": "ascii85"}), {"variant": "ascii85"}) == raw
    assert from_base85(to_base85(raw, {"variant": "rfc1924"}), {"variant": "rfc1924"}) == raw


def test_url_and_binary_and_rot() -> None:
    raw = b"a b/c?"
    assert url_decode(url_encode(raw, {"safe": ""}), {}) == raw
    assert from_binary(to_binary(b"Hi", {"grouped": True}), {}) == b"Hi"
    assert rot13(b"Uryyb", {}) == b"Hello"
    assert rot_n(rot_n(b"Hello", {"n": 5}), {"n": 21}) == b"Hello"


def test_morse_roundtrip() -> None:
    raw = b"SOS HELP"
    assert from_morse(to_morse(raw, {}), {}) == raw


def test_recipe_pipeline() -> None:
    text = "Hello"
    encoded = to_base64(text.encode(), {})
    result = run_steps(encoded, [Step("from_base64", {}), Step("rot13", {})])
    assert result.error is None
    assert result.utf8_text == rot13(b"Hello", {}).decode()


def test_hash_ops_are_one_way() -> None:
    import cascade.engine  # noqa: F401 — registers ops
    from cascade.engine.ops.encodings import hash_sha256
    from cascade.engine.registry import get_op

    digest = hash_sha256(b"hello", {})
    assert digest == b"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    for op_id in ("hash_md5", "hash_sha1", "hash_sha256", "hash_sha512"):
        op = get_op(op_id)
        assert op.one_way
        assert op.inverse_id is None


def test_hash_digest_is_not_decoded() -> None:
    import hashlib

    from cascade.engine.detect import hash_digest_kind
    from cascade.engine.magic import best_node, explore

    digest = hashlib.sha256(b"hello").hexdigest().encode()
    assert hash_digest_kind(digest) == "SHA-256"
    plain_hex = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345".hex().encode()
    assert len(plain_hex) == 64
    assert hash_digest_kind(plain_hex) is None
    chosen = best_node(explore(digest))
    assert chosen is not None
    assert chosen.path == ()
    assert chosen.data == digest


def test_read_payload_file(tmp_path) -> None:
    from cascade.ui.panes import read_payload_file

    target = tmp_path / "note.txt"
    target.write_bytes(b"dropped-payload")
    data, error = read_payload_file(str(target))
    assert error is None
    assert data == b"dropped-payload"


def test_read_payload_rejects_directory(tmp_path) -> None:
    from cascade.ui.panes import read_payload_file

    data, error = read_payload_file(str(tmp_path))
    assert data is None
    assert error == "open_not_file"


def test_base32_is_not_detected_as_base64() -> None:
    from cascade.engine.detect import looks_base32, looks_base64

    blob = to_base32(b"Hello world from the offline decoder today.", {})
    assert looks_base32(blob)
    assert not looks_base64(blob)


def test_ascii85_with_slash_is_detected() -> None:
    from cascade.engine.detect import looks_base85

    blob = to_base85(
        b"Hello world from the offline decoder today.",
        {"variant": "ascii85", "adobe": False},
    )
    assert looks_base85(blob)
    # `/` is a valid ASCII85 digit and must not be treated as a URL path.
    if b"/" not in blob:
        blob = b'87cURD]j7BEbo8/Ao_g,+EV:.+E(k(Ch[cu+Co%nDe*F"+EVO4@<jI'
    assert looks_base85(blob)

