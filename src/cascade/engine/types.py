from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

ParamKind = Literal["bool", "int", "choice", "text"]


@dataclass(frozen=True)
class ParamSpec:
    key: str
    kind: ParamKind
    default: Any
    label_fr: str
    label_en: str
    minimum: int | None = None
    maximum: int | None = None
    choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class Step:
    op_id: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class BakeResult:
    data: bytes
    utf8_text: str
    utf8_ok: bool
    hexdump: str
    byte_len: int
    steps_ok: int
    error: str | None = None
    error_step: int | None = None
