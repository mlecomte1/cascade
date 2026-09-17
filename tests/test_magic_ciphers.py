from cascade.engine.magic import best_node, confidence_pct, explore, flatten_nodes, top_nodes
from cascade.engine.ops.encodings import (
    rot13,
    to_base32,
    to_base64,
    to_base85,
    to_hex,
    to_utf16be,
)
from cascade.engine.ops.ciphers import xor_bytes, vigenere, caesar_brute
from cascade.engine.recipe import run_steps
from cascade.engine.types import Step


def test_magic_base64() -> None:
    encoded = to_base64(b"Hello", {})
    nodes = explore(encoded)
    assert nodes
    assert any(b"Hello" == node.data for node in nodes)


def test_magic_nested_hex_then_base64() -> None:
    inner = to_hex(b"Hi", {"separator": "none", "prefix": False})
    outer = to_base64(inner, {})
    nodes = flatten_nodes(explore(outer))
    assert any(node.data == b"Hi" for node in nodes)


def test_magic_rot13() -> None:
    nodes = flatten_nodes(explore(rot13(b"Hello", {})))
    assert any(node.data == b"Hello" for node in nodes)
    assert best_node(explore(rot13(b"Hello", {}))).data == b"Hello"


def test_magic_rot13_with_digits_not_rot47() -> None:
    raw = b"Pass: abc123!#"
    encoded = rot13(raw, {})
    chosen = best_node(explore(encoded))
    assert chosen is not None
    assert chosen.data == raw
    assert chosen.path[0].op_id == "rot13"
    assert all(step.op_id != "rot47" for step in chosen.path)
    assert best_node(explore(rot13(b"Hello, World! 123", {}))).data == b"Hello, World! 123"


def test_magic_rot13_french_apostrophe() -> None:
    payload = b"Yr fbyrvy oevyyr fhe yn zre nhwbheq'uhv."
    chosen = best_node(explore(payload))
    assert chosen is not None
    assert chosen.data == b"Le soleil brille sur la mer aujourd'hui."
    assert chosen.path[0].op_id == "rot13"


def test_magic_base32() -> None:
    encoded = to_base32(b"Hello", {})
    nodes = flatten_nodes(explore(encoded))
    assert any(node.data == b"Hello" for node in nodes)


def test_magic_base64_of_reversed() -> None:
    encoded = to_base64(b"Hello"[::-1], {})
    nodes = flatten_nodes(explore(encoded))
    assert any(node.data == b"Hello" for node in nodes)
    assert best_node(explore(encoded)).data == b"Hello"


def test_magic_reversed_base64() -> None:
    encoded = to_base64(b"Hello", {})[::-1]
    nodes = flatten_nodes(explore(encoded))
    assert any(node.data == b"Hello" for node in nodes)
    assert best_node(explore(encoded)).data == b"Hello"


def test_magic_base64_then_rot13() -> None:
    encoded = to_base64(rot13(b"Hello", {}), {})
    nodes = flatten_nodes(explore(encoded))
    assert any(node.data == b"Hello" for node in nodes)


def test_magic_reverse_then_base32() -> None:
    encoded = to_base32(b"Hello"[::-1], {})
    nodes = flatten_nodes(explore(encoded))
    assert any(node.data == b"Hello" for node in nodes)


def test_magic_triple_reverse_rot13_base64() -> None:
    inner = rot13(b"Hello"[::-1], {})
    encoded = to_base64(inner, {})
    nodes = flatten_nodes(explore(encoded))
    assert any(node.data == b"Hello" for node in nodes)


def test_magic_stays_fast_on_long_base64() -> None:
    import time

    payload = to_base64(b"Hello Cascade " * 40, {})
    started = time.perf_counter()
    nodes = flatten_nodes(explore(payload))
    assert time.perf_counter() - started < 1.5
    assert any(b"Hello Cascade" in node.data for node in nodes)


def test_magic_base85_ascii() -> None:
    encoded = to_base85(b"Hello", {"variant": "ascii85"})
    assert best_node(explore(encoded)).data == b"Hello"


def test_magic_base85_adobe() -> None:
    encoded = to_base85(b"Hello", {"variant": "ascii85", "adobe": True})
    assert best_node(explore(encoded)).data == b"Hello"


def test_magic_base85_rfc1924() -> None:
    encoded = to_base85(b"Hello", {"variant": "rfc1924"})
    assert best_node(explore(encoded)).data == b"Hello"


def test_magic_urlsafe_nopad() -> None:
    encoded = to_base64(b"subjects?id=1", {"url_safe": True, "padding": False})
    assert b"=" not in encoded
    assert best_node(explore(encoded)).data == b"subjects?id=1"


def test_magic_hex_then_base64_best() -> None:
    inner = to_hex(b"Hello", {"separator": "none", "prefix": False})
    outer = to_base64(inner, {})
    assert best_node(explore(outer)).data == b"Hello"


def test_magic_hex_of_base64() -> None:
    inner = to_base64(b"Hello", {})
    encoded = to_hex(inner, {"separator": "none", "prefix": False})
    assert best_node(explore(encoded)).data == b"Hello"


def test_magic_html_entities() -> None:
    encoded = b"&lt;Hello&gt;"
    assert best_node(explore(encoded)).data == b"<Hello>"


def test_magic_unicode_escape() -> None:
    encoded = r"\u0048\u0065\u006c\u006c\u006f".encode()
    assert best_node(explore(encoded)).data == b"Hello"


def test_magic_utf16be() -> None:
    encoded = to_utf16be(b"Hello", {})
    assert best_node(explore(encoded)).data == b"Hello"


def test_batch2_base64_then_rot13() -> None:
    payload = b"D2I0qTHtMz9cplOfMFOlo3DtqUWynKcyVUMcMJ50VTSjpzImVTkyVTWup2Htp29crTShqTHtpKIuqUWyYt=="
    assert b"rot treize" in best_node(explore(payload)).data


def test_batch2_binary() -> None:
    payload = (
        b"01000100 01110101 00100000 01100010 01101001 01101110 01100001 "
        b"01101001 01110010 01100101 00100000 01110000 01110101 01110010 00101110"
    )
    assert best_node(explore(payload)).data == b"Du binaire pur."


def test_batch2_decimal() -> None:
    payload = b"68 101 115 32 110 111 109 98 114 101 115 32 100 101 99 105 109 97 117 120 46"
    assert best_node(explore(payload)).data == b"Des nombres decimaux."


def test_batch2_zlib_base64() -> None:
    payload = (
        b"eJwVisENgDAMA1fxjw9iCSZJWwtFCi00BSGmJ/x8d16Jne6yEfSBMklqvSC3/ejhCbmZ8Zo"
        b"mHJc6WHMr8a1IEtWbPlIHcV4yOmfkfyqM6KwFaqauKXDQotCWDz87KSg="
    )
    text = best_node(explore(payload)).data
    assert b"zlib" in text
    assert b"base soixante" in text


def test_batch2_triple_base64() -> None:
    payload = (
        b"VmtoS2RtRllUV2RaTWpreFdUSm9iR041UW10YVUwSnBXVmhPYkVsSVRuWmhXR2hvWW01U2JFbE"
        b"lSakZaV0ZKNVdsTkNhbHBZVWpCYVUwSnRZakpzZWt4blBUMD0="
    )
    assert best_node(explore(payload)).data == b"Trois couches de base soixante quatre cette fois."


def test_batch2_hex_then_base32() -> None:
    payload = (
        b"GQ4DMNJXHAZDANRUGI3TMMJWGI3GMNZSGY2DEYZSGA3TANZVGY4TOMZSGA3DENRRG4ZTMNJSGA3"
        b"TINZSGY2TMZJXGQ3DKMTEGY2DMNJXGU3TQMRQG4YDMMJXGIZDANRUGY2TOMZXGM3TKNZTGJSQ===="
    )
    assert b"trente-deux" in best_node(explore(payload)).data


def test_batch2_ascii85() -> None:
    payload = (
        b'<Gl@jG%#E*@;^0u+Clj.F(8ou+E;O4FE1qEG%ki,F=h!:DK.3MA8,XfATD@"FCcS*'
        b"FWb.%F(HJ6F^]B4AM&(>DJ+&C@qfh#+Cf4rF)u&8F_*0"
    )
    assert b"ascii" in best_node(explore(payload)).data.lower()


def test_batch2_rot13_reverse_base64() -> None:
    payload = b"LmVycWJwcnEgbiBmZWJncmUgZ2FyenJlcnZ5aHB2Z2VuYyBnZnIgdnAtdmh5clA="
    assert b"retors" in best_node(explore(payload)).data


def test_batch2_base16() -> None:
    payload = (
        b"42617365207365697A652C207175692065737420656E2066616974206A7573746520646520"
        b"6C2768657861646563696D616C20656E206D616A757363756C65732E"
    )
    assert b"hexadecimal" in best_node(explore(payload)).data.lower()


def test_xor_roundtrip() -> None:
    raw = b"secret-bytes"
    xored = xor_bytes(raw, {"key": "k", "key_format": "text"})
    assert xor_bytes(xored, {"key": "k", "key_format": "text"}) == raw


def test_vigenere_roundtrip() -> None:
    raw = b"AttackAtDawn"
    enc = vigenere(raw, {"key": "LEMON", "decrypt": False})
    assert vigenere(enc, {"key": "LEMON", "decrypt": True}) == raw


def test_caesar_brute_contains_rot13() -> None:
    report = caesar_brute(b"Uryyb", {}).decode()
    assert "n=13" in report
    assert "Hello" in report


def test_xor_pipeline() -> None:
    xored = xor_bytes(b"abc", {"key": "01", "key_format": "hex"})
    result = run_steps(xored, [Step("xor", {"key": "01", "key_format": "hex"})])
    assert result.utf8_text == "abc"


def test_jwt_display() -> None:
    from cascade.engine.ops.ctf import from_jwt

    token = b"eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
    out = from_jwt(token, {})
    assert b'"user": "admin"' in out
    assert b'"verified": false' in out


def test_powershell_encoded() -> None:
    import base64

    from cascade.engine.ops.ctf import from_powershell_encoded

    encoded = base64.b64encode("Write-Output hi".encode("utf-16-le")).decode("ascii")
    out = from_powershell_encoded(f"powershell -EncodedCommand {encoded}".encode(), {})
    assert out == b"Write-Output hi"


def test_js_atob_unwrap() -> None:
    from cascade.engine.ops.ctf import js_atob_unwrap

    out = js_atob_unwrap(b'eval(atob("SGVsbG8="))', {})
    assert out == b"Hello"


def test_magic_hex_0x_prefixed() -> None:
    payload = b"0x48 0x65 0x6c 0x6c 0x6f"
    assert best_node(explore(payload)).data == b"Hello"
    raw = b"Hello from hex"
    spaced = b" ".join(f"0x{byte:02x}".encode() for byte in raw)
    assert best_node(explore(spaced)).data == raw


def test_magic_base32hex() -> None:
    from cascade.engine.ops.encodings import to_base32hex

    raw = b"Hello from base32hex"
    encoded = to_base32hex(raw, {})
    assert best_node(explore(encoded)).data == raw
    assert best_node(explore(encoded.lower().rstrip(b"="))).data == raw


def test_magic_uuencode() -> None:
    from cascade.engine.ops.encodings import to_uu

    raw = b"Hello from uuencode"
    encoded = to_uu(raw, {})
    assert best_node(explore(encoded)).data == raw
    named = encoded.replace(b"begin 644 -", b"begin 644 hello.txt", 1)
    assert best_node(explore(named)).data == raw
    b64_uu = b"begin-base64 644 hello.txt\nSGVsbG8gZnJvbSB1dWVuY29kZQ==\n====\n"
    assert best_node(explore(b64_uu)).data == raw


def test_magic_rot47_sentence() -> None:
    from cascade.engine.ops.encodings import rot47

    raw = b"ROT47 couvre plus de caracteres que ROT13!"
    encoded = rot47(raw, {})
    chosen = best_node(explore(encoded))
    assert chosen is not None
    assert chosen.data == raw
    assert chosen.path[0].op_id == "rot47"
    assert not any(step.op_id == "url_decode" for step in chosen.path)
    assert not any(step.op_id == "rot13" for step in chosen.path)


def test_magic_rot47_keeps_digits_and_symbols() -> None:
    from cascade.engine.ops.encodings import rot47, rot13

    raw = b"Pass: abc123!#"
    encoded = rot47(raw, {})
    assert encoded != rot13(raw, {})
    chosen = best_node(explore(encoded))
    assert chosen is not None
    assert chosen.data == raw
    assert chosen.path[0].op_id == "rot47"
    assert all(step.op_id != "rot13" for step in chosen.path)


def test_magic_rot47_flag_and_promo() -> None:
    from cascade.engine.ops.encodings import rot47

    for raw in (b"flag{R0T47_is_not_rot13}", b"Prix : 10e #promo 50%"):
        chosen = best_node(explore(rot47(raw, {})))
        assert chosen is not None, raw
        assert chosen.data == raw
        assert chosen.path[0].op_id == "rot47"


def test_magic_url_percent_still_decodes() -> None:
    payload = b"Hello%20World"
    assert best_node(explore(payload)).data == b"Hello World"


def test_magic_base64_then_atbash() -> None:
    from cascade.engine.ops.encodings import atbash

    raw = b"Hello from nested atbash and base64"
    layered = atbash(to_base64(raw, {}), {})
    chosen = best_node(explore(layered))
    assert chosen is not None
    assert chosen.data == raw
    assert "atbash" in {step.op_id for step in chosen.path}
    assert "from_base64" in {step.op_id for step in chosen.path}


def test_magic_xor_hex_single_byte() -> None:
    raw = b"Hello from xor with a single byte key"
    for key in (0x42, 42):
        xored = bytes(byte ^ key for byte in raw)
        payload = to_hex(xored, {"separator": "none", "prefix": False})
        chosen = best_node(explore(payload))
        assert chosen is not None
        assert chosen.data == raw


def test_magic_vigenere_common_key() -> None:
    raw = b"Ceci est un message secret pour le test"
    encoded = vigenere(raw, {"key": "CLE", "decrypt": False})
    chosen = best_node(explore(encoded))
    assert chosen is not None
    assert chosen.data == raw


def test_magic_rot13_then_atbash() -> None:
    from cascade.engine.ops.encodings import atbash

    raw = b"Ceci est un message avec virgules, les points ; et le reste."
    layered = atbash(rot13(raw, {}), {})
    chosen = best_node(explore(layered))
    assert chosen is not None
    assert chosen.data == raw
    ops = {step.op_id for step in chosen.path}
    assert "rot13" in ops
    assert "atbash" in ops


def test_magic_base64_rot47_base64() -> None:
    from cascade.engine.ops.encodings import rot47

    raw = b"Ceci est un message avec virgules, les points ; et le reste."
    layered = to_base64(rot47(to_base64(raw, {}), {}), {})
    chosen = best_node(explore(layered))
    assert chosen is not None
    assert chosen.data == raw
    ops = [step.op_id for step in chosen.path]
    assert ops.count("from_base64") >= 2
    assert "rot47" in ops


def test_magic_keeps_word_les() -> None:
    raw = b"virgules, les points ; encore les virgules."
    encoded = to_base64(raw, {})
    chosen = best_node(explore(encoded))
    assert chosen is not None
    assert chosen.data == raw
    assert b"les" in chosen.data
    assert b"virgules" in chosen.data


def test_top_nodes_and_confidence_cap() -> None:
    encoded = to_base64(b"Hello from a longer confidence check here", {})
    nodes = explore(encoded)
    tops = top_nodes(nodes, 3)
    assert 1 <= len(tops) <= 3
    for node in tops:
        assert 8 <= confidence_pct(node) <= 98


def test_user_rot13_then_atbash_payload() -> None:
    payload = b"Sz mstvi kyaly: vyt tvieni xseu mtlmuf."
    chosen = best_node(explore(payload))
    assert chosen is not None
    assert chosen.data == b"Un autre combo: rot treize puis atbash."


def test_user_base64_rot47_base64_payload() -> None:
    payload = (
        b"J3d5RzIpfDgrKSM5NHYnS346cToqKX09fTsiRHh3eUc1cyJie3JxSDUoPUt4d3k9eyh5OTRhJmF9cmNs"
    )
    chosen = best_node(explore(payload))
    assert chosen is not None
    assert chosen.data == b"Trois etapes: base64, rot47, puis re-base64."


def test_magic_short_base64_phrases() -> None:
    for raw in (b"Regarde les.", b"test moins"):
        encoded = to_base64(raw, {})
        chosen = best_node(explore(encoded))
        assert chosen is not None, raw
        assert chosen.data == raw


def test_magic_base64_symbols_and_newlines() -> None:
    raw = "Prix : 10€ #promo 50%\nSeconde ligne.".encode("utf-8")
    encoded = to_base64(raw, {})
    chosen = best_node(explore(encoded))
    assert chosen is not None
    assert chosen.data == raw
    assert b"\n" in chosen.data
    assert "€".encode() in chosen.data


def test_multiline_prose_is_not_uu() -> None:
    from cascade.engine.detect import looks_uu

    prose = b"Ligne une.\nLigne deux.\nLigne trois."
    assert not looks_uu(prose)
    chosen = best_node(explore(prose))
    assert chosen is None or chosen.data == prose or b"Ligne" in chosen.data


def test_magic_double_base64_then_rot13_sentence() -> None:
    payload = (
        b"Vm5CMklHSmhJSEJpZW5weVlYQnlJR051WlNCbFltY2daMlZ5ZG0xeUlHNXBibUZu"
        b"SUhGeWFHc2djR0pvY0hWeVppQnZibVp5SUdaaWRtdHVZV2R5SUdSb2JtZGxjaTQ9"
    )
    chosen = best_node(explore(payload))
    assert chosen is not None
    assert chosen.data == (
        b"Ici on commence par rot treize avant deux couches base soixante quatre."
    )
    assert [step.op_id for step in chosen.path] == ["from_base64", "from_base64", "rot13"]


def test_magic_rot13_base64_hex_sentence() -> None:
    payload = (
        b"AGN3ZwL1AzD2BGL1AmV2AGVjAwZ2BQLkAwx2MGL1ZwN2ZGVjAmD3ZwMzAwx3ZmVj"
        b"AwH3AQLkAmN2AGpmZwN2ZwL5AwH2MGVjAwD2BGpmAmD2BGMyAwZ3AQL1AmZlMD=="
    )
    nodes = explore(payload)
    chosen = best_node(nodes)
    assert chosen is not None
    assert chosen.data == b"Premiere chaine a trois etapes bien distinctes."
    tops = top_nodes(nodes, 3)
    assert tops
    assert tops[0].data == chosen.data
    assert b"C6>:6C6" not in chosen.data


def test_magic_base64_rot13_base85_rfc1924() -> None:
    from cascade.engine.ops.encodings import rot13, to_base64, to_base85

    plains = (
        b"Nouvelle tentative avec exactement la meme combinaison de trois etapes.",
        b"Dernier test pour confirmer que ca fonctionne bien a chaque fois.",
        b"Encore une autre phrase pour le meme enchainement base85 rot13 base64.",
    )
    for raw in plains:
        encoded = to_base64(rot13(to_base85(raw, {"variant": "rfc1924"}), {}), {})
        chosen = best_node(explore(encoded))
        assert chosen is not None, raw
        assert chosen.data == raw
        ops = [step.op_id for step in chosen.path]
        assert ops[0] == "from_base64"
        assert "rot13" in ops
        assert "from_base85" in ops

    payload = (
        b"WX11TGVLPURFUG9MKndBTm5VWkpuaSk9VE1zMGQ2TVFhI1RucXktQUlfX3Q+TSpT"
        b"Nk9LPkk/T0p0aHB7SmJ7ZjBOTCo3QG5xeS1BSl5NTDhSJg=="
    )
    chosen = best_node(explore(payload))
    assert chosen is not None
    assert chosen.data == (
        b"Dernier test pour confirmer que ca fonctionne bien a chaque fois."
    )
