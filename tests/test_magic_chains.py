from __future__ import annotations

from cascade.engine.magic import best_node, explore
from cascade.engine.ops.encodings import (
    atbash,
    from_base32,
    from_base64,
    from_hex,
    hash_sha256,
    rot13,
    rot47,
    rot_n,
    to_base32,
    to_base64,
    to_base85,
    to_hex,
    to_html_entities,
    to_unicode_escape,
)
from cascade.engine.recipe import run_steps
from cascade.engine.types import Step

USER_ENCODING = {
    "e1": (
        b"GU2TIOBUME3GGNRSGU3TMYZWMM3DGNRZGQZDMYZWGI3GINDFGZTDKOJVG43GGNZVGVQTKNZTGE3GGNRSGZSTKMJWG42TSNJYGVQTMYZVHE3TSNBSGMYTMMRWMQ3GGNZYGY2DKNZVGY3TINLBGU3TGNJTGA2DSNBXGUZDMYZWGM3TSNBSGZRTMMRWMQ2GKNZWGVQTINZUGY3GKNLBGU4DIZBWG43DGNBYGU3DOOJWGM3TSMZUGNSA====",
        b"Premier enchainement avec uniquement des encodages purs.",
    ),
    "e2": (
        b"R1EyRE1OSlhHVTNUUU5SWkdZMlRNWkJXR1VaREFOUlRHWTRETU1KV0hFM0dLTlJWR0pSVEVNQlhHTTNES05aVkdaUlRNTkpXTVEzREtOVEZHNDJERU1CV0dRM0RLTlpUR0lZRE1aQldHVTNUSU5SWUdaVERNTkJXR1UzVEdNUlFHWTJERU5aV0dVM0dLTlJUR1pURE1OQldHRTNET05SVkdJWURNTVpXTU0zRENOWlRHNFpUTU9KWEdFM1RLTlJWRzRaVEVaST0=",
        b"Deuxieme chaine, seulement des methodes d'encodage classiques.",
    ),
    "e3": (
        b"556b4a2b514431694e31354a4e56646e645731465632382b5754565861454238546c706c64334535563264324f4535614b58524f546c6476666a423756303150515870694d454a72536c706e56574248574778614e6a78684a5559354d46706e5a57633d",
        b"Troisieme exemple, encore trois encodages sans chiffrement.",
    ),
    "e4": (
        b"T0dZd1JMcDROR1BEV0UjR0ZuUE9QZn1BQE0+UnJDTU03NnNPRVhNSE1NN0NmTUtWbEpPLUB4PEwwVT5kTy0zX0VPSWNiJFBnWW4lS3tHUWBPO1REJU9HIWpVUERXSG1PPEdKLU87JVYpTmxafmE=",
        b"Quatrieme test, meme principe avec un ordre different.",
    ),
    "e5": (
        b"4b455a4759354c444c424c48415753584746574553523257474245554f55544d4d4e57544b3443324c42455847534b494b4a3347495633514f5a5346515354324a4645464d354c424c4244444357535847465747453353524d354e454f5654324a4644564d354b5a4749345757574b584d52574747364a5548553d3d3d3d3d3d",
        b"Cinquieme et dernier, toujours uniquement des encodages.",
    ),
}

USER_MIXED = {
    "c1": (
        b"V001YHNXbl5WRldvVHQmVz9eQXBXbipQeldvMmIoVlA5b3FXb1R0KFdvMmIoV255SiRXaSh9RVZQOW9uV0BUayRXbnk3cFc/Kkp5V25nQXdXP15NeVZQOW9yV0BCWXdXP3lBd1dAMkdxV25eVkdWUDlvcFdvS256V29UdEtXbl5KQw==",
        b"Premier defi difficile avec quatre etapes en chaine.",
    ),
    "c2": (
        b"4a425458433354444d3534574f4944494d3554474749444c4f4254575349445250415148535a33324e4e34474b5a5a414e42545341324c454d4e54474d354448504654585134545445425558553233544f4e52584b344c484f4d58413d3d3d3d",
        b"Deuxieme defi avec un melange de chiffrements classiques.",
    ),
    "c3": (
        b"OVTW2YZSNRXGINSCINQXKQTJMNUFU3TCGFBEQSLZIZEES2CKNVSG2VTNMNYEM3LEM5EVQWLPIJBWG6LMNVRGOWJTMN4UMSCJPFYG4YZSLJWWI2KWGJJA====",
        b"Troisieme defi avec une inversion de chaine au milieu.",
    ),
    "c4": (
        b"65535a316556784c5644786f59334e464e304d7763323953574864304d584a4758334a596546776e4b3342686343647962574e315a585178575678684b3342734e434e7950324e4c626b70664b6d4170536d686e4b6e3530544539365a536456",
        b"Quatrieme defi, celui-ci empile cinq methodes distinctes.",
    ),
    "c5": (
        b"S1I1R0syRE1QSjNHSTVSQU9aVlNBNUxXTkZTWFU1VEpFQjJYTTUzMkVCMlhNSURVT1pWV1c1UkFOSjNHUzZUV0ZRUUhHWlRGRUIyR00zREpPSjRITUxRPQ==",
        b"Cinquieme et dernier defi de cette serie, bon courage.",
    ),
}


def _assert_best(payload: bytes, expected: bytes) -> None:
    chosen = best_node(explore(payload))
    assert chosen is not None, payload[:40]
    assert chosen.data == expected


def test_user_encoding_only_chains() -> None:
    for payload, expected in USER_ENCODING.values():
        _assert_best(payload, expected)


def test_user_mixed_cipher_chains() -> None:
    for payload, expected in USER_MIXED.values():
        _assert_best(payload, expected)


def test_magic_any_three_encoding_orders() -> None:
    raw = b"Une phrase pour verifier n importe quel ordre d encodage."
    chains = (
        lambda p: to_base32(to_hex(to_base64(p, {}), {}), {}),
        lambda p: to_base64(to_base32(to_hex(p, {}), {}), {}),
        lambda p: to_hex(to_base64(to_base85(p, {"variant": "rfc1924"}), {}), {}),
        lambda p: to_base64(to_base85(to_base32(p, {}), {"variant": "rfc1924"}), {}),
        lambda p: to_hex(to_base32(to_base64(p, {}), {}), {}),
        lambda p: to_base64(to_hex(to_base32(p, {}), {}), {}),
        lambda p: to_base32(to_base64(to_hex(p, {}), {}), {}),
    )
    for encode in chains:
        encoded = encode(raw)
        _assert_best(encoded, raw)


def test_magic_mixed_layers_generic() -> None:
    raw = b"Encore une phrase avec des mots pour le moteur auto."
    layered = to_base64(to_base85(rot47(to_hex(raw, {}), {}), {"variant": "rfc1924"}), {})
    _assert_best(layered, raw)
    reversed_b64 = to_base32(to_base64(rot13(raw, {}), {})[::-1], {})
    _assert_best(reversed_b64, raw)
    caesar = to_base64(to_base32(rot13(rot_n(raw, {"n": 4}), {}), {}), {})
    _assert_best(caesar, raw)
    atbash_caesar = to_hex(to_base32(rot_n(atbash(raw, {}), {"n": 11}), {}), {})
    _assert_best(atbash_caesar, raw)


def test_manual_peel_helpers_still_match_user_c3() -> None:
    payload, expected = USER_MIXED["c3"]
    peeled = rot13(from_base64(from_base32(payload, {})[::-1], {}), {})
    assert peeled == expected


def test_hash_and_escape_encode_ops() -> None:
    raw = b"Cascade <test> & encode"
    assert hash_sha256(raw, {}) == __import__("hashlib").sha256(raw).hexdigest().encode()
    escaped = to_html_entities(raw, {})
    assert b"&lt;test&gt;" in escaped
    uni = to_unicode_escape("été".encode(), {})
    assert b"\\u" in uni or b"\\xe" in uni
    result = run_steps(raw, [Step("to_base64", {}), Step("to_hex", {})])
    assert result.error is None
    assert from_hex(result.data, {}) == to_base64(raw, {})
