from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from cascade.engine.registry import get_op
from cascade.engine.types import ParamSpec, Step
from cascade.i18n import t
from cascade.ui.flow import FlowLayout, hug


def _short_label(op, lang: str) -> str:
    title = op.label(lang)
    for prefix in ("Vers ", "Depuis ", "To ", "From "):
        if title.startswith(prefix):
            return title[len(prefix):]
    return title


def _visible_params(op) -> list[ParamSpec]:
    return [spec for spec in op.params if spec.key != "decrypt"]


class StepCard(QFrame):
    picked = Signal()
    removed = Signal()

    def __init__(self, step: Step, index: int, lang: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("recipeCard")
        self.step = step
        self._lang = lang
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(4)

        self._pick = QPushButton()
        self._pick.setObjectName("recipeChip")
        self._pick.setCheckable(True)
        self._pick.setCursor(Qt.CursorShape.PointingHandCursor)
        self._pick.clicked.connect(self.picked.emit)
        layout.addWidget(self._pick)

        remove = QPushButton("×")
        remove.setFixedSize(22, 22)
        remove.setObjectName("danger")
        remove.clicked.connect(self.removed.emit)
        layout.addWidget(remove)
        self.set_index(index)

    def set_index(self, index: int) -> None:
        op = get_op(self.step.op_id)
        mark = "  ⊘" if op.one_way else ""
        self._pick.setText(f"{index + 1}. {_short_label(op, self._lang)}{mark}")

    def set_checked(self, checked: bool) -> None:
        self._pick.blockSignals(True)
        self._pick.setChecked(checked)
        self._pick.blockSignals(False)

    def retranslate(self, lang: str) -> None:
        self._lang = lang
        current = self._pick.text().split(".", 1)[0]
        try:
            index = max(0, int(current) - 1)
        except ValueError:
            index = 0
        self.set_index(index)


class RecipeBar(QWidget):
    changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("recipePanel")
        self._lang = "fr"
        self.steps: list[Step] = []
        self._cards: list[StepCard] = []
        self._selected: StepCard | None = None
        self._param_widgets: list[QWidget] = []

        self._compact = False
        self._title = QLabel()
        self._title.setObjectName("title")
        self._hint = QLabel()
        self._hint.setObjectName("muted")
        self._hint.setWordWrap(True)

        self._clear_btn = hug(QPushButton())
        self._invert_btn = hug(QPushButton())
        self._clear_btn.clicked.connect(self.clear)
        self._invert_btn.clicked.connect(self.invert_last)
        self._chips = QWidget()
        chips_l = QHBoxLayout(self._chips)
        chips_l.setContentsMargins(0, 0, 0, 0)
        chips_l.setSpacing(6)
        self._chip_ids = (
            ("to_base64", "quick_base64"),
            ("to_hex", "quick_hex"),
            ("to_base32", "quick_base32"),
            ("url_encode", "quick_url"),
            ("rot13", "quick_rot13"),
            ("hash_sha256", "quick_sha256"),
        )
        self._chip_buttons: list[QPushButton] = []
        for op_id, key in self._chip_ids:
            chip = hug(QPushButton())
            chip.setObjectName("chip")
            chip.clicked.connect(lambda _checked=False, oid=op_id: self.add_op(oid))
            chips_l.addWidget(chip)
            self._chip_buttons.append(chip)
        chips_l.addStretch(1)

        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(8)
        self._top_bar = top
        top.addWidget(self._title, 1)
        top.addWidget(self._invert_btn)
        top.addWidget(self._clear_btn)

        self._inner = QWidget()
        self._inner.setObjectName("recipeInner")
        self._inner.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self._cards_layout = FlowLayout(self._inner, spacing=6)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setWidget(self._inner)
        scroll.setMinimumHeight(40)
        scroll.setMaximumHeight(84)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        self._scroll = scroll

        self._params = QWidget()
        self._params.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self._params_l = FlowLayout(self._params, spacing=8)
        self._params.hide()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addLayout(top)
        layout.addWidget(self._chips)
        layout.addWidget(self._hint)
        layout.addWidget(scroll)
        layout.addWidget(self._params)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        self.retranslate("fr")

    def retranslate(self, lang: str) -> None:
        self._lang = lang
        self._title.setText(t(lang, "recipe"))
        clear_key = "clear_recipe_short" if self._compact else "clear_recipe"
        invert_key = "invert_last_short" if self._compact else "invert_last"
        self._clear_btn.setText(t(lang, clear_key))
        self._invert_btn.setText(t(lang, invert_key))
        self._clear_btn.setToolTip(t(lang, "clear_recipe"))
        self._invert_btn.setToolTip(t(lang, "invert_last"))
        for button, (_op_id, key) in zip(self._chip_buttons, self._chip_ids, strict=True):
            button.setText(t(lang, key))
        self._hint.setText(t(lang, "empty_recipe") if not self.steps else "")
        self._chips.setVisible(not self._compact)
        for card in self._cards:
            card.retranslate(lang)
        self._sync_scroll()
        self._rebuild_params()

    def set_compact(self, compact: bool) -> None:
        if compact == self._compact:
            return
        self._compact = compact
        self.retranslate(self._lang)

    def _sync_scroll(self) -> None:
        has_steps = bool(self.steps)
        self._scroll.setVisible(has_steps)
        self._hint.setVisible((not self._compact) and not has_steps)
        last = get_op(self.steps[-1].op_id) if self.steps else None
        self._invert_btn.setEnabled(bool(last and last.inverse_id))

    def add_op(self, op_id: str, params: dict | None = None) -> None:
        from cascade.engine.recipe import default_params

        step = Step(op_id=op_id, params=params or default_params(op_id))
        self.steps.append(step)
        self._mount_card(step)
        self._hint.setText("")
        self._sync_scroll()
        self.changed.emit()

    def _mount_card(self, step: Step) -> None:
        card = StepCard(step, len(self._cards), self._lang)
        card.picked.connect(lambda c=card: self._select_card(c))
        card.removed.connect(lambda c=card: self._remove_card(c))
        self._cards.append(card)
        self._cards_layout.addWidget(card)
        self._select_card(card)

    def _select_card(self, card: StepCard) -> None:
        self._selected = card
        for item in self._cards:
            item.set_checked(item is card)
        self._rebuild_params()

    def _rebuild_params(self) -> None:
        while self._params_l.count():
            item = self._params_l.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._param_widgets.clear()
        card = self._selected
        if card is None or card not in self._cards:
            self._params.hide()
            return
        op = get_op(card.step.op_id)
        specs = _visible_params(op)
        if not specs:
            self._params.hide()
            return
        caption = QLabel(_short_label(op, self._lang))
        caption.setObjectName("muted")
        self._params_l.addWidget(caption)
        for spec in specs:
            self._params_l.addWidget(
                self._build_param(card.step, spec, card.step.params.get(spec.key, spec.default))
            )
        self._params.show()

    def _build_param(self, step: Step, spec: ParamSpec, value: Any) -> QWidget:
        label = spec.label_en if self._lang == "en" else spec.label_fr
        if spec.kind == "bool":
            box = QCheckBox(label)
            box.setChecked(bool(value))
            box.toggled.connect(lambda checked, key=spec.key: self._set_param(step, key, checked))
            self._param_widgets.append(box)
            return box
        if spec.kind == "int":
            spin = QSpinBox()
            spin.setRange(spec.minimum or 0, spec.maximum or 99)
            spin.setValue(int(value))
            spin.setToolTip(label)
            spin.setMaximumWidth(80)
            spin.valueChanged.connect(lambda n, key=spec.key: self._set_param(step, key, n))
            self._param_widgets.append(spin)
            return spin
        if spec.kind == "choice":
            combo = QComboBox()
            combo.addItems(list(spec.choices))
            combo.setCurrentText(str(value))
            combo.setToolTip(label)
            combo.setMaximumWidth(140)
            combo.currentTextChanged.connect(lambda text, key=spec.key: self._set_param(step, key, text))
            self._param_widgets.append(combo)
            return combo
        edit = QLineEdit()
        edit.setText(str(value))
        edit.setPlaceholderText(label)
        edit.setToolTip(label)
        edit.setMaximumWidth(160)
        edit.textChanged.connect(lambda text, key=spec.key: self._set_param(step, key, text))
        self._param_widgets.append(edit)
        return edit

    def _set_param(self, step: Step, key: str, value: Any) -> None:
        step.params[key] = value
        self.changed.emit()

    def _remove_card(self, card: StepCard) -> None:
        index = self._cards.index(card)
        self._cards.pop(index)
        self.steps.pop(index)
        card.deleteLater()
        for i, remaining in enumerate(self._cards):
            remaining.set_index(i)
        if self._selected is card:
            self._selected = self._cards[index - 1] if self._cards else None
            if self._selected is not None:
                self._select_card(self._selected)
            else:
                self._rebuild_params()
        if not self.steps:
            self._hint.setText(t(self._lang, "empty_recipe"))
        self._sync_scroll()
        self.changed.emit()

    def clear(self) -> None:
        for card in self._cards:
            card.deleteLater()
        self._cards.clear()
        self.steps.clear()
        self._selected = None
        self._hint.setText(t(self._lang, "empty_recipe"))
        self._rebuild_params()
        self._sync_scroll()
        self.changed.emit()

    def invert_last(self) -> None:
        if not self.steps:
            return
        last = self.steps[-1]
        op = get_op(last.op_id)
        if not op.inverse_id:
            return
        params = dict(last.params)
        if op.id == "rot_n" or op.inverse_id == "rot_n":
            n = int(params.get("n", 13))
            params = {"n": (26 - n) % 26}
        self.add_op(op.inverse_id, params)
