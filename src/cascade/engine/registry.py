from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cascade.engine.errors import DecodeError
from cascade.engine.types import ParamSpec

Handler = Callable[[bytes, dict[str, Any]], bytes]


@dataclass(frozen=True)
class Operation:
    id: str
    family: str
    label_fr: str
    label_en: str
    description_fr: str
    description_en: str
    handler: Handler
    params: tuple[ParamSpec, ...] = ()
    inverse_id: str | None = None
    encode: bool = False
    one_way: bool = False

    def label(self, lang: str) -> str:
        return self.label_en if lang == "en" else self.label_fr

    def description(self, lang: str) -> str:
        return self.description_en if lang == "en" else self.description_fr

    def run(self, data: bytes, params: dict[str, Any] | None = None) -> bytes:
        merged = {spec.key: spec.default for spec in self.params}
        if params:
            merged.update(params)
        try:
            return self.handler(data, merged)
        except DecodeError:
            raise
        except Exception as exc:
            raise DecodeError(
                f"Échec de « {self.label_fr} ».",
                f"“{self.label_en}” failed.",
            ) from exc


_OPS: dict[str, Operation] = {}


def register(op: Operation) -> Operation:
    _OPS[op.id] = op
    return op


def has_op(op_id: str) -> bool:
    return op_id in _OPS


def get_op(op_id: str) -> Operation:
    try:
        return _OPS[op_id]
    except KeyError as exc:
        raise DecodeError(
            f"Opération inconnue : {op_id}",
            f"Unknown operation: {op_id}",
        ) from exc


def all_ops() -> list[Operation]:
    return list(_OPS.values())
