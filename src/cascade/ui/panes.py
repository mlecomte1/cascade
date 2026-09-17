from __future__ import annotations

import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from cascade.engine.detect import looks_image
from cascade.engine.limits import MAX_MANUAL_BYTES
from cascade.i18n import t
from cascade.ui.flow import hug


def read_payload_file(path: str) -> tuple[bytes | None, str | None]:
    if not os.path.isfile(path):
        return None, "open_not_file"
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_MANUAL_BYTES + 1)
    except OSError:
        return None, "open_failed"
    if len(data) > MAX_MANUAL_BYTES:
        return None, "open_too_large"
    return data, None


class DropTextEdit(QPlainTextEdit):
    files_dropped = Signal(str)

    def dragEnterEvent(self, event) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragEnterEvent(event)

    def dragMoveEvent(self, event) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragMoveEvent(event)

    def dropEvent(self, event) -> None:  # noqa: N802
        urls = event.mimeData().urls()
        path = urls[0].toLocalFile() if urls else ""
        if path:
            event.acceptProposedAction()
            self.files_dropped.emit(path)
            return
        super().dropEvent(event)


class IoPane(QFrame):
    copy_requested = Signal()
    save_requested = Signal()
    file_loaded = Signal(bytes, str)
    swap_requested = Signal()
    clear_requested = Signal()

    def __init__(self, kind: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ioCard")
        self.setMinimumWidth(160)
        self.setMinimumHeight(160)
        self.kind = kind
        self._lang = "fr"
        self._compact = False
        self._workspace = "auto"
        self._kicker = QLabel()
        self._kicker.setObjectName("kicker")
        self._kicker.setTextFormat(Qt.TextFormat.PlainText)
        self._title = QLabel()
        self._title.setObjectName("title")
        self._title.setTextFormat(Qt.TextFormat.PlainText)
        self._title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self._title.setMinimumWidth(48)
        self.editor = DropTextEdit()
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        instance = QApplication.instance()
        mono = "Consolas"
        if instance is not None:
            mono = str(instance.property("cascadeMonoFamily") or "Consolas")
        editor_font = QFont(mono, 10)
        editor_font.setStyleHint(QFont.StyleHint.TypeWriter)
        editor_font.setStyleStrategy(
            QFont.StyleStrategy.PreferOutline | QFont.StyleStrategy.NoFontMerging
        )
        editor_font.setFixedPitch(True)
        self.editor.setFont(editor_font)
        self.editor.setMinimumHeight(72)
        self._copy = hug(QPushButton())
        self._copy.setObjectName("accent")
        self._copy.clicked.connect(self.copy_requested.emit)
        self._save = hug(QPushButton())
        self._save.setObjectName("ghost")
        self._save.clicked.connect(self.save_requested.emit)
        self._open = hug(QPushButton())
        self._clear = hug(QPushButton())
        self._swap = hug(QPushButton())
        self._open.setObjectName("ghost")
        self._clear.setObjectName("ghost")
        self._swap.setObjectName("ghost")
        self._banner = QLabel()
        self._banner.setObjectName("muted")
        self._banner.setWordWrap(True)
        self._banner.setTextFormat(Qt.TextFormat.PlainText)
        self._stats = QLabel()
        self._stats.setObjectName("muted")
        self._stats.setTextFormat(Qt.TextFormat.PlainText)
        self._open.clicked.connect(self._pick_file)
        self._clear.clicked.connect(self.clear_requested.emit)
        self._swap.clicked.connect(self.swap_requested.emit)
        self.editor.textChanged.connect(self._refresh_stats)
        if kind == "input":
            self.setAcceptDrops(True)
            self.editor.files_dropped.connect(self._load_path)

        heading = QVBoxLayout()
        heading.setContentsMargins(0, 0, 0, 0)
        heading.setSpacing(1)
        heading.addWidget(self._kicker)
        heading.addWidget(self._title)

        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(8)
        header.addLayout(heading, 1)
        if kind == "output":
            header.addWidget(self._swap)
            header.addWidget(self._save)
            header.addWidget(self._copy)
            self.editor.setReadOnly(True)
        else:
            header.addWidget(self._open)
            header.addWidget(self._clear)
        self._path = QLabel()
        self._path.setObjectName("muted")
        self._path.setWordWrap(True)
        self._path.setTextFormat(Qt.TextFormat.PlainText)
        self._path.hide()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)
        layout.addLayout(header)
        if kind == "output":
            layout.addWidget(self._path)
        if kind == "input":
            layout.addWidget(self._banner)
            self._banner.hide()
        layout.addWidget(self.editor, 1)
        layout.addWidget(self._stats)
        self.retranslate("fr")
        self._refresh_stats()

    def dragEnterEvent(self, event) -> None:  # noqa: N802
        if self.kind == "input" and event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragEnterEvent(event)

    def dragMoveEvent(self, event) -> None:  # noqa: N802
        if self.kind == "input" and event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        super().dragMoveEvent(event)

    def dropEvent(self, event) -> None:  # noqa: N802
        if self.kind != "input":
            return
        urls = event.mimeData().urls()
        path = urls[0].toLocalFile() if urls else ""
        if path:
            event.acceptProposedAction()
            self._load_path(path)

    def _pick_file(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self,
            t(self._lang, "open_file"),
            "",
            t(self._lang, "open_filter"),
        )
        if path:
            self._load_path(path)

    def _load_path(self, path: str) -> None:
        data, error = read_payload_file(path)
        if error:
            self._banner.setText(t(self._lang, error))
            self._banner.show()
            return
        if data is None:
            return
        self.file_loaded.emit(data, path)

    def load_text(self, text: str) -> None:
        self.editor.blockSignals(True)
        self.editor.setPlainText(text)
        self.editor.blockSignals(False)
        self._refresh_stats()

    def set_workspace(self, mode: str) -> None:
        self._workspace = mode
        self.retranslate(self._lang)

    def set_compact(self, compact: bool) -> None:
        if compact == self._compact:
            return
        self._compact = compact
        self._kicker.setVisible(not compact)
        self._path.setWordWrap(not compact)
        self.setMinimumHeight(140 if compact else 160)
        self.setMinimumWidth(140 if compact else 160)
        self.retranslate(self._lang)

    def set_file_banner(self, message: str | None) -> None:
        if self.kind != "input":
            return
        if message:
            self._banner.setText(message)
            self._banner.show()
        else:
            self._banner.hide()
            self._banner.clear()

    def set_path_caption(self, text: str | None) -> None:
        if self.kind != "output":
            return
        if text:
            self._path.setText(text)
            self._path.show()
        else:
            self._path.clear()
            self._path.hide()

    def _refresh_stats(self) -> None:
        text = self.editor.toPlainText()
        raw = text.encode("utf-8")
        lines = text.count("\n") + (1 if text else 0)
        self._stats.setText(
            t(self._lang, "io_stats").format(chars=len(text), bytes=len(raw), lines=lines)
        )

    def retranslate(self, lang: str) -> None:
        self._lang = lang
        encode = self._workspace == "manual"
        if self.kind == "input":
            self._kicker.setText(t(lang, "input_kicker"))
            self._title.setText(t(lang, "input_encode" if encode else "input_decode"))
            self.editor.setPlaceholderText(
                t(lang, "input_hint_encode" if encode else "input_hint_decode")
            )
            open_key = "open_file_short" if self._compact else "open_file"
            clear_key = "clear_input_short" if self._compact else "clear_input"
            self._open.setText(t(lang, open_key))
            self._clear.setText(t(lang, clear_key))
            self._open.setToolTip(t(lang, "open_file"))
            self._clear.setToolTip(t(lang, "clear_input"))
        else:
            self._kicker.setText(t(lang, "output_kicker"))
            self._title.setText(t(lang, "output_encode" if encode else "output_decode"))
            self.editor.setPlaceholderText(
                t(lang, "output_hint_encode" if encode else "output_hint_decode")
            )
            self._copy.setText(t(lang, "copy"))
            save_key = "save_short" if self._compact else "save_file"
            self._save.setText(t(lang, save_key))
            self._save.setToolTip(t(lang, "save_file"))
            swap_key = "swap_short" if self._compact else "swap_io"
            self._swap.setText(t(lang, swap_key))
            self._swap.setToolTip(t(lang, "swap_io"))
        self._refresh_stats()


def text_from_bytes(data: bytes) -> str:
    if looks_image(data):
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")
