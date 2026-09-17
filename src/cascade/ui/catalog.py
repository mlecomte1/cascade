from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from cascade.engine.registry import all_ops
from cascade.i18n import t
from cascade.ui.flow import FlowLayout

_TRANSFORMS = frozenset(
    {"rot13", "rot_n", "atbash", "rot47", "reverse", "xor", "vigenere", "aes", "des", "des3", "rc4"}
)
_BRUTE = frozenset({"caesar_brute", "xor_brute1", "xor_brute2", "xor_brute3", "xor_wordlist"})


class CatalogPanel(QWidget):
    op_chosen = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("catalogPanel")
        self._lang = "fr"
        self._compact = False
        self._title = QLabel()
        self._title.setObjectName("title")
        self._title.setTextFormat(Qt.TextFormat.PlainText)
        self._hint = QLabel()
        self._hint.setObjectName("muted")
        self._hint.setWordWrap(True)
        self._hint.setTextFormat(Qt.TextFormat.PlainText)
        self._search = QLineEdit()
        self._encode_heading = QLabel()
        self._encode_heading.setObjectName("kicker")
        self._hash_heading = QLabel()
        self._hash_heading.setObjectName("kicker")
        self._transform_heading = QLabel()
        self._transform_heading.setObjectName("kicker")
        self._search.textChanged.connect(self.refresh)

        self._encode_host = QWidget()
        self._encode_host.setObjectName("tileHost")
        self._encode_host.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self._encode_flow = FlowLayout(self._encode_host, spacing=8)
        self._hash_host = QWidget()
        self._hash_host.setObjectName("tileHost")
        self._hash_host.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self._hash_flow = FlowLayout(self._hash_host, spacing=8)
        self._transform_host = QWidget()
        self._transform_host.setObjectName("tileHost")
        self._transform_host.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self._transform_flow = FlowLayout(self._transform_host, spacing=8)

        inner = QWidget()
        inner.setObjectName("tileHost")
        inner_l = QVBoxLayout(inner)
        inner_l.setContentsMargins(0, 0, 0, 0)
        inner_l.setSpacing(8)
        inner_l.addWidget(self._encode_heading)
        inner_l.addWidget(self._encode_host)
        inner_l.addWidget(self._hash_heading)
        inner_l.addWidget(self._hash_host)
        inner_l.addWidget(self._transform_heading)
        inner_l.addWidget(self._transform_host)
        inner_l.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(inner)
        self._scroll = scroll

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self._title)
        layout.addWidget(self._hint)
        layout.addWidget(self._search)
        layout.addWidget(scroll, 1)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        self.retranslate("fr")

    def set_compact(self, compact: bool) -> None:
        if compact == getattr(self, "_compact", None):
            return
        self._compact = compact
        self._hint.setVisible(not compact)
        self._title.setVisible(not compact)
        self._encode_heading.setVisible(not compact)
        self._hash_heading.setVisible(not compact)
        self._transform_heading.setVisible(not compact)

    def retranslate(self, lang: str) -> None:
        self._lang = lang
        self._title.setText(t(lang, "catalog"))
        self._hint.setText(t(lang, "catalog_hint"))
        self._search.setPlaceholderText(t(lang, "search"))
        self._encode_heading.setText(t(lang, "encode_group"))
        self._hash_heading.setText(t(lang, "hash_group"))
        self._transform_heading.setText(t(lang, "decode_group"))
        self.refresh()

    def _ops(self):
        for op in all_ops():
            if op.id in _BRUTE:
                continue
            if op.encode or op.id in _TRANSFORMS:
                yield op

    def refresh(self) -> None:
        query = self._search.text().strip().lower()
        encode_ops = [op for op in self._ops() if op.encode and not op.one_way]
        hash_ops = [op for op in self._ops() if op.one_way]
        transform_ops = [op for op in self._ops() if not op.encode]
        self._fill(self._encode_flow, encode_ops, query, "encodeTile")
        self._fill(self._hash_flow, hash_ops, query, "hashTile", one_way=True)
        self._fill(self._transform_flow, transform_ops, query, "transformTile")
        show_headings = not self._compact
        self._encode_heading.setVisible(show_headings and self._encode_flow.count() > 0)
        self._hash_heading.setVisible(show_headings and self._hash_flow.count() > 0)
        self._transform_heading.setVisible(show_headings and self._transform_flow.count() > 0)

    def _fill(self, flow: FlowLayout, ops, query: str, object_name: str, *, one_way: bool = False) -> None:
        while flow.count():
            item = flow.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for op in ops:
            hay = f"{op.label_fr} {op.label_en} {op.id} {op.description_fr} {op.description_en}".lower()
            if query and query not in hay:
                continue
            label = op.label(self._lang)
            if one_way:
                label = f"{label}  ⊘"
            tile = QPushButton(label)
            tile.setObjectName(object_name)
            tile.setCursor(Qt.CursorShape.PointingHandCursor)
            tile.setToolTip(op.description(self._lang))
            tile.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            tile.clicked.connect(lambda _checked=False, oid=op.id: self._pick(oid))
            flow.addWidget(tile)

    def _pick(self, op_id: str) -> None:
        self.op_chosen.emit(op_id)
