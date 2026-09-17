from __future__ import annotations

from typing import Any

from cascade.engine.errors import DecodeError
from cascade.engine.hexdump import decode_utf8_view, to_hexdump
from cascade.engine.limits import MAX_MANUAL_BYTES
from cascade.engine.registry import get_op
from cascade.engine.types import BakeResult, Step


def ensure_size(data: bytes, limit: int = MAX_MANUAL_BYTES) -> None:
    if len(data) > limit:
        raise DecodeError(
            f"Entrée trop volumineuse ({len(data)} octets, max {limit}).",
            f"Input too large ({len(data)} bytes, max {limit}).",
        )


def run_steps(data: bytes, steps: list[Step], *, lang: str = "fr") -> BakeResult:
    ensure_size(data)
    current = data
    for index, step in enumerate(steps):
        op = get_op(step.op_id)
        try:
            current = op.run(current, step.params)
        except DecodeError as exc:
            text, utf8_ok = decode_utf8_view(current)
            return BakeResult(
                data=current,
                utf8_text=text,
                utf8_ok=utf8_ok,
                hexdump=to_hexdump(current),
                byte_len=len(current),
                steps_ok=index,
                error=exc.localized(lang),
                error_step=index,
            )
        ensure_size(current)

    text, utf8_ok = decode_utf8_view(current)
    return BakeResult(
        data=current,
        utf8_text=text,
        utf8_ok=utf8_ok,
        hexdump=to_hexdump(current),
        byte_len=len(current),
        steps_ok=len(steps),
    )


def default_params(op_id: str) -> dict[str, Any]:
    op = get_op(op_id)
    return {spec.key: spec.default for spec in op.params}
