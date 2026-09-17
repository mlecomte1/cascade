from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTabBar,
    QVBoxLayout,
    QWidget,
)

from cascade.engine.detect import hash_digest_kind
from cascade.engine.magic import MagicNode, confidence_pct, format_path
from cascade.engine.registry import get_op
from cascade.i18n import t
from cascade.ui.flow import hug


def _plain(label: QLabel) -> QLabel:
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class CascadePanel(QWidget):
    node_selected = Signal(object)
    copy_path = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("cascadePanel")
        self._lang = "fr"
        self._nodes: list[MagicNode] = []
        self._compact = False

        self._title = _plain(QLabel())
        self._title.setObjectName("title")
        self._hint = _plain(QLabel())
        self._hint.setObjectName("muted")
        self._hint.setWordWrap(True)

        self._tabs = QTabBar()
        self._tabs.setObjectName("pathTabs")
        self._tabs.setDocumentMode(True)
        self._tabs.setDrawBase(False)
        self._tabs.setExpanding(False)
        self._tabs.setUsesScrollButtons(True)
        self._tabs.setElideMode(Qt.TextElideMode.ElideRight)
        self._tabs.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._tabs.currentChanged.connect(self._on_tab)

        self._use = hug(QPushButton())
        self._use.setObjectName("ghost")
        self._use.clicked.connect(self._emit_use)

        tab_row = QWidget()
        tab_l = QHBoxLayout(tab_row)
        tab_l.setContentsMargins(0, 0, 0, 0)
        tab_l.setSpacing(8)
        tab_l.addWidget(self._tabs, 1)
        tab_l.addWidget(self._use, 0, Qt.AlignmentFlag.AlignVCenter)
        self._tab_row = tab_row

        self._caption = _plain(QLabel())
        self._caption.setObjectName("muted")
        self._caption.setWordWrap(False)

        self._rule = QFrame()
        self._rule.setObjectName("rule")
        self._rule.setFixedHeight(2)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 2)
        layout.setSpacing(4)
        layout.addWidget(self._title)
        layout.addWidget(self._hint)
        layout.addWidget(tab_row)
        layout.addWidget(self._rule)
        layout.addWidget(self._caption)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        self.setMinimumHeight(52)
        self.setMaximumHeight(118)
        self.retranslate("fr")
        self._sync_empty()

    def retranslate(self, lang: str) -> None:
        self._lang = lang
        self._title.setText(t(lang, "cascade_title"))
        self._use.setText(t(lang, "cascade_use_short" if self._compact else "cascade_use"))
        if self._nodes:
            self.set_nodes(self._nodes, selected=self._current())
        else:
            self._sync_empty()

    def set_compact(self, compact: bool) -> None:
        if compact == self._compact:
            return
        self._compact = compact
        self._hint.setVisible(not compact)
        self._title.setVisible(not compact)
        self._use.setText(t(self._lang, "cascade_use_short" if compact else "cascade_use"))
        self.setMaximumHeight(88 if compact else 118)
        self._sync_empty()

    def set_nodes(self, nodes: list[MagicNode], selected: MagicNode | None = None) -> None:
        self._nodes = list(nodes)
        current = selected.path if selected is not None else None
        self._tabs.blockSignals(True)
        while self._tabs.count():
            self._tabs.removeTab(0)
        index = 0
        chosen = 0
        for node in self._nodes[:3]:
            op = get_op(node.path[-1].op_id) if node.path else None
            if op:
                title = op.label(self._lang)
                for prefix in ("Depuis ", "Vers ", "From ", "To "):
                    if title.startswith(prefix):
                        title = title[len(prefix):]
                        break
            else:
                kind = hash_digest_kind(node.data)
                title = f"{kind}  ⊘" if kind else t(self._lang, "cascade_title")
            pct = confidence_pct(node)
            self._tabs.addTab(f"{title} {pct}%")
            path = format_path(node.path, self._lang)
            tip = path or title
            if node.preview:
                tip = f"{tip}\n{node.preview}"
            self._tabs.setTabToolTip(index, tip)
            if current is not None and node.path == current:
                chosen = index
            index += 1
        if self._tabs.count():
            self._tabs.setCurrentIndex(chosen)
        self._tabs.blockSignals(False)
        self._sync_empty()
        self._refresh_caption()

    def _current(self) -> MagicNode | None:
        idx = self._tabs.currentIndex()
        if 0 <= idx < len(self._nodes):
            return self._nodes[idx]
        return None

    def _on_tab(self, index: int) -> None:
        if 0 <= index < len(self._nodes):
            self.node_selected.emit(self._nodes[index])
            self._refresh_caption()

    def _emit_use(self) -> None:
        node = self._current()
        if node is not None:
            self.copy_path.emit(format_path(node.path, self._lang))

    def _sync_empty(self) -> None:
        empty = not self._nodes
        self._tabs.setVisible(not empty)
        self._use.setVisible(not empty)
        self._caption.setVisible(not empty)
        self._rule.setVisible(not empty)
        self._title.setVisible(not self._compact)
        self._hint.setVisible((not self._compact) or empty)
        if empty:
            self._hint.setText(t(self._lang, "cascade_empty"))
            self._caption.clear()
            self._caption.setToolTip("")
        else:
            self._hint.setText(t(self._lang, "cascade_hint"))

    def _refresh_caption(self) -> None:
        node = self._current()
        if node is None:
            self._caption.clear()
            return
        path = format_path(node.path, self._lang)
        preview = (node.preview or "").replace("\n", " ")
        text = f"{path}  ·  {preview}" if path else preview
        self._caption.setText(text)
        self._caption.setToolTip(text)
        self._elide_caption()

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._elide_caption()

    def _elide_caption(self) -> None:
        full = self._caption.toolTip() if self._caption.text() else ""
        if not full:
            return
        metrics = QFontMetrics(self._caption.font())
        width = max(40, self._caption.width() - 8)
        self._caption.setText(metrics.elidedText(full, Qt.TextElideMode.ElideMiddle, width))
