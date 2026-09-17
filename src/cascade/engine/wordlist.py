"""Short in-memory XOR keys (not a dump of rockyou)."""

BUILTIN_XOR_KEYS: tuple[bytes, ...] = (
    b"a",
    b"key",
    b"KEY",
    b"xor",
    b"XOR",
    b"flag",
    b"FLAG",
    b"ctf",
    b"CTF",
    b"pass",
    b"password",
    b"secret",
    b"admin",
    b"user",
    b"test",
    b"crypto",
    b"cipher",
    b"hidden",
    b"decode",
    b"hello",
    b"world",
    b"1234",
    b"12345",
    b"123456",
    b"abc",
    b"abcd",
    b"qwerty",
    b"letmein",
    b"base64",
    b"hex",
    b"salt",
    b"iv",
    b"aes",
    b"des",
    b"rc4",
    b"vpn",
    b"root",
    b"toor",
    b"guest",
    b"changeme",
    b"default",
    b"master",
    b"private",
    b"public",
    b"token",
    b"jwt",
    b"payload",
    b"offline",
    b"cascade",
    b"\x00",
    b"\xff",
    b"\x42",
    b"\x13\x37",
    b"\xde\xad",
    b"\xbe\xef",
    b"\xca\xfe",
    b"\xfa\xce",
)


def parse_pasted_keys(blob: str) -> list[bytes]:
    keys: list[bytes] = []
    for line in blob.replace(",", "\n").splitlines():
        item = line.strip()
        if not item:
            continue
        keys.append(item.encode("utf-8"))
        hexed = "".join(ch for ch in item if ch in "0123456789abcdefABCDEF")
        if len(hexed) >= 2 and len(hexed) % 2 == 0 and hexed.lower() == item.lower().replace("0x", ""):
            try:
                keys.append(bytes.fromhex(hexed))
            except ValueError:
                pass
    return keys
