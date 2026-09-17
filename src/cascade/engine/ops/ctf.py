from __future__ import annotations

import base64
import json
import re
from typing import Any

from cascade.engine.errors import DecodeError
from cascade.engine.limits import MAX_JWT_BYTES
from cascade.engine.registry import Operation, has_op, register

_PS_FLAG = re.compile(
    r"(?:-(?:encodedcommand|enc|e))\s+([A-Za-z0-9+/=\s]+)",
    re.IGNORECASE,
)
_ATOB = re.compile(
    r"""(?:eval\s*\(\s*)?atob\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)\s*\)?""",
    re.IGNORECASE,
)


def _b64url_decode(part: bytes) -> bytes:
    compact = part.strip().replace(b"-", b"+").replace(b"_", b"/")
    compact += b"=" * ((4 - len(compact) % 4) % 4)
    try:
        return base64.b64decode(compact)
    except Exception as exc:
        raise DecodeError("Bloc JWT Base64URL invalide.", "Invalid JWT Base64URL segment.") from exc


def from_jwt(data: bytes, _params: dict[str, Any]) -> bytes:
    if len(data) > MAX_JWT_BYTES:
        raise DecodeError("JWT trop volumineux.", "JWT too large.")
    parts = data.strip().split(b".")
    if len(parts) not in (2, 3):
        raise DecodeError("JWT : attend header.payload[.sig].", "JWT: expected header.payload[.sig].")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except DecodeError:
        raise
    except Exception as exc:
        raise DecodeError("JWT JSON invalide.", "Invalid JWT JSON.") from exc
    doc = {
        "warning": "Signature NON vérifiée. Cascade décode seulement header/payload, sans confiance.",
        "verified": False,
        "header": header,
        "payload": payload,
        "signature": parts[2].decode("ascii", errors="replace") if len(parts) == 3 else "",
    }
    return json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")


def from_powershell_encoded(data: bytes, _params: dict[str, Any]) -> bytes:
    text = data.decode("utf-8", errors="latin-1").strip()
    match = _PS_FLAG.search(text)
    blob = match.group(1) if match else text
    compact = "".join(blob.split())
    pad = (-len(compact)) % 4
    try:
        raw = base64.b64decode(compact + ("=" * pad))
    except Exception as exc:
        raise DecodeError("Commande PowerShell encodée invalide.", "Invalid encoded PowerShell.") from exc
    try:
        return raw.decode("utf-16-le").encode("utf-8")
    except UnicodeError as exc:
        raise DecodeError("UTF-16 LE PowerShell invalide.", "Invalid PowerShell UTF-16 LE.") from exc


def js_atob_unwrap(data: bytes, _params: dict[str, Any]) -> bytes:
    text = data.decode("utf-8", errors="latin-1")
    for _ in range(16):
        def repl(match: re.Match[str]) -> str:
            blob = match.group(1)
            blob += "=" * ((4 - len(blob) % 4) % 4)
            try:
                decoded = base64.b64decode(blob)
            except Exception:
                return match.group(0)
            return decoded.decode("utf-8", errors="replace")

        nxt = _ATOB.sub(repl, text)
        if nxt == text:
            break
        text = nxt
    return text.encode("utf-8")


def js_beautify(data: bytes, _params: dict[str, Any]) -> bytes:
    src = data.decode("utf-8", errors="replace")
    out: list[str] = []
    indent = 0
    i = 0
    n = len(src)
    in_str: str | None = None
    escape = False
    line_comment = False
    block_comment = False
    newline = True

    def write_indent() -> None:
        out.append("    " * max(indent, 0))

    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if line_comment:
            out.append(ch)
            if ch == "\n":
                line_comment = False
                newline = True
            i += 1
            continue
        if block_comment:
            out.append(ch)
            if ch == "*" and nxt == "/":
                out.append("/")
                i += 2
                block_comment = False
                continue
            i += 1
            continue
        if in_str:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in "\"'`":
            if newline:
                write_indent()
                newline = False
            in_str = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            if newline:
                write_indent()
                newline = False
            line_comment = True
            out.append("//")
            i += 2
            continue
        if ch == "/" and nxt == "*":
            if newline:
                write_indent()
                newline = False
            block_comment = True
            out.append("/*")
            i += 2
            continue
        if ch in " \t" and newline:
            i += 1
            continue
        if ch == "{":
            if newline:
                write_indent()
            out.append("{")
            out.append("\n")
            indent = min(indent + 1, 32)
            newline = True
            i += 1
            continue
        if ch == "}":
            if not newline:
                out.append("\n")
            indent = max(indent - 1, 0)
            write_indent()
            out.append("}")
            out.append("\n")
            newline = True
            i += 1
            continue
        if ch == ";":
            out.append(";")
            out.append("\n")
            newline = True
            i += 1
            continue
        if ch == "\n":
            if not newline:
                out.append("\n")
                newline = True
            i += 1
            continue
        if newline:
            write_indent()
            newline = False
        out.append(ch)
        i += 1
    return "".join(out).encode("utf-8")


def register_ctf_ops() -> None:
    if has_op("js_beautify"):
        return
    register(
        Operation(
            id="from_jwt",
            family="ctf",
            label_fr="JWT (affichage)",
            label_en="JWT (display)",
            description_fr="Décode header/payload JWT. Signature NON vérifiée, aucun réseau.",
            description_en="Decode JWT header/payload. Signature NOT verified; no network.",
            handler=from_jwt,
        )
    )
    register(
        Operation(
            id="from_powershell_encoded",
            family="ctf",
            label_fr="PowerShell -EncodedCommand",
            label_en="PowerShell -EncodedCommand",
            description_fr="Décode Base64 UTF-16 LE (sans exécuter).",
            description_en="Decode Base64 UTF-16 LE (does not execute).",
            handler=from_powershell_encoded,
        )
    )
    register(
        Operation(
            id="js_atob_unwrap",
            family="deobf",
            label_fr="JS atob/eval (unwrap)",
            label_en="JS atob/eval (unwrap)",
            description_fr="Déplie atob/eval statiquement, sans exécuter le JavaScript.",
            description_en="Statically unwrap atob/eval, without executing JavaScript.",
            handler=js_atob_unwrap,
        )
    )
    register(
        Operation(
            id="js_beautify",
            family="deobf",
            label_fr="JS beautify",
            label_en="JS beautify",
            description_fr="Indente le JavaScript sans l'exécuter.",
            description_en="Indent JavaScript without executing it.",
            handler=js_beautify,
        )
    )
