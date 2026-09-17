from __future__ import annotations

from cascade.engine.limits import MAX_HEXDUMP_BYTES


def to_hexdump(data: bytes, width: int = 16, *, limit: int = MAX_HEXDUMP_BYTES) -> str:
    if not data:
        return ""
    sample = data
    prefix = ""
    if limit and len(data) > limit:
        sample = data[:limit]
        prefix = f"# truncated after {limit} of {len(data)} bytes\n"
    lines: list[str] = []
    for offset in range(0, len(sample), width):
        chunk = sample[offset : offset + width]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:08X}  {hex_part:<{width * 3}} {ascii_part}")
    return prefix + "\n".join(lines)


def decode_utf8_view(data: bytes) -> tuple[str, bool]:
    try:
        return data.decode("utf-8"), True
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), False
