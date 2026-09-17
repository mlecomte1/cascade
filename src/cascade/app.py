from __future__ import annotations

import sys

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Qt, Signal
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QBoxLayout,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from cascade.engine.detect import hash_digest_kind, looks_image
from cascade.engine.errors import DecodeError
from cascade.engine.hexdump import decode_utf8_view, to_hexdump
from cascade.engine.magic import MagicNode, best_node, explore, format_path, top_nodes
from cascade.engine.limits import MAX_MANUAL_BYTES
from cascade.engine.recipe import default_params, run_steps
from cascade.engine.registry import get_op
from cascade.engine.types import BakeResult, Step
from cascade.i18n import t
from cascade.style import apply_app_fonts, themed_stylesheet
from cascade.ui.cascade import CascadePanel
from cascade.ui.catalog import CatalogPanel
from cascade.ui.flow import hug
from cascade.ui.panes import IoPane, text_from_bytes
from cascade.ui.recipe import RecipeBar


class _ExploreSignals(QObject):
    finished = Signal(int, object)


class _ExploreJob(QRunnable):
    def __init__(self, generation: int, data: bytes, signals: _ExploreSignals) -> None:
        super().__init__()
        self.setAutoDelete(True)
        self._generation = generation
        self._data = data
        self._signals = signals

    def run(self) -> None:
        try:
            result: object = explore(self._data)
        except Exception as exc:  # noqa: BLE001 — forwarded to UI thread
            result = exc
        self._signals.finished.emit(self._generation, result)


class _BakeSignals(QObject):
    finished = Signal(int, object)


class _BakeJob(QRunnable):
    def __init__(
        self,
        generation: int,
        data: bytes,
        steps: list[Step],
        lang: str,
        signals: _BakeSignals,
    ) -> None:
        super().__init__()
        self.setAutoDelete(True)
        self._generation = generation
        self._data = data
        self._steps = steps
        self._lang = lang
        self._signals = signals

    def run(self) -> None:
        try:
            result: object = run_steps(self._data, self._steps, lang=self._lang)
        except Exception as exc:  # noqa: BLE001 — forwarded to UI thread
            result = exc
        self._signals.finished.emit(self._generation, result)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.lang = "fr"
        self.mode = "auto"
        self.view_mode = "text"
        self._file_bytes: bytes | None = None
        self._last: BakeResult | None = None
        self._magic_nodes: list[MagicNode] = []
        self._magic_gen = 0
        self._bake_gen = 0
        self._explore_signals = _ExploreSignals()
        self._explore_signals.finished.connect(self._on_magic_done)
        self._bake_signals = _BakeSignals()
        self._bake_signals.finished.connect(self._on_bake_done)
        self._explore_pool = QThreadPool(self)
        self._explore_pool.setMaxThreadCount(1)
        self._bake_pool = QThreadPool(self)
        self._bake_pool.setMaxThreadCount(1)
        self._bake_timer = QTimer(self)
        self._bake_timer.setSingleShot(True)
        self._bake_timer.setInterval(80)
        self._bake_timer.timeout.connect(self.bake)

        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)

        self._brand = QLabel("CASCADE")
        self._brand.setObjectName("brand")
        self._brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._brand_mark = QLabel()
        self._brand_mark.setObjectName("brandMark")
        self._brand_mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._manual_btn = QPushButton()
        self._auto_btn = QPushButton()
        self._manual_btn.setObjectName("modeEncode")
        self._auto_btn.setObjectName("modeDecode")
        self._manual_btn.setCheckable(True)
        self._auto_btn.setCheckable(True)
        self._manual_btn.setChecked(False)
        self._auto_btn.setChecked(True)
        self._manual_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._auto_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._manual_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._auto_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._fr_btn = hug(QPushButton("FR"))
        self._en_btn = hug(QPushButton("EN"))
        self._fr_btn.setCheckable(True)
        self._en_btn.setCheckable(True)
        self._fr_btn.setChecked(True)
        self._text_btn = hug(QPushButton())
        self._hex_btn = hug(QPushButton())
        self._text_btn.setCheckable(True)
        self._hex_btn.setCheckable(True)
        self._text_btn.setChecked(True)
        self._offline = QLabel()
        self._offline.setObjectName("muted")
        self._offline.setWordWrap(True)
        self._offline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._offline.setTextFormat(Qt.TextFormat.PlainText)
        self._hero_title = QLabel()
        self._hero_title.setObjectName("heroTitle")
        self._hero_title.setTextFormat(Qt.TextFormat.PlainText)
        self._mode_hint = QLabel()
        self._mode_hint.setObjectName("heroSub")
        self._mode_hint.setWordWrap(True)
        self._mode_hint.setTextFormat(Qt.TextFormat.PlainText)

        self._manual_btn.clicked.connect(lambda: self._set_mode("manual"))
        self._auto_btn.clicked.connect(lambda: self._set_mode("auto"))
        self._fr_btn.clicked.connect(lambda: self._set_lang("fr"))
        self._en_btn.clicked.connect(lambda: self._set_lang("en"))
        self._text_btn.clicked.connect(lambda: self._set_view("text"))
        self._hex_btn.clicked.connect(lambda: self._set_view("hex"))

        view_seg = QFrame()
        view_seg.setObjectName("seg")
        view_l = QHBoxLayout(view_seg)
        view_l.setContentsMargins(4, 4, 4, 4)
        view_l.setSpacing(4)
        view_l.addWidget(self._text_btn)
        view_l.addWidget(self._hex_btn)

        lang_seg = QFrame()
        lang_seg.setObjectName("seg")
        lang_l = QHBoxLayout(lang_seg)
        lang_l.setContentsMargins(4, 4, 4, 4)
        lang_l.setSpacing(4)
        lang_l.addWidget(self._fr_btn)
        lang_l.addWidget(self._en_btn)

        rail = QFrame()
        rail.setObjectName("rail")
        rail.setFixedWidth(168)
        rail_l = QVBoxLayout(rail)
        rail_l.setContentsMargins(14, 18, 14, 16)
        rail_l.setSpacing(10)
        rail_l.addWidget(self._brand)
        rail_l.addWidget(self._brand_mark)
        rail_l.addSpacing(8)
        rail_l.addWidget(self._auto_btn)
        rail_l.addWidget(self._manual_btn)
        rail_l.addStretch(1)
        rail_l.addWidget(view_seg)
        rail_l.addWidget(lang_seg)
        rail_l.addWidget(self._offline)
        self._rail = rail

        hero = QFrame()
        hero.setObjectName("hero")
        hero_l = QVBoxLayout(hero)
        hero_l.setContentsMargins(18, 14, 18, 14)
        hero_l.setSpacing(4)
        hero_l.addWidget(self._hero_title)
        hero_l.addWidget(self._mode_hint)
        self._hero = hero

        self.catalog = CatalogPanel()
        self.input_pane = IoPane("input")
        self.output_pane = IoPane("output")
        self.recipe = RecipeBar()
        self.cascade = CascadePanel()

        self.catalog.op_chosen.connect(self._add_encode_op)
        self.recipe.changed.connect(self.schedule_bake)
        self.input_pane.editor.textChanged.connect(self._on_input_typed)
        self.input_pane.file_loaded.connect(self._load_file)
        self.input_pane.clear_requested.connect(self._clear_input)
        self.output_pane.copy_requested.connect(self.copy_output)
        self.output_pane.save_requested.connect(self._save_output)
        self.output_pane.swap_requested.connect(self._swap_io)
        self.cascade.node_selected.connect(self._show_magic_node)
        self.cascade.copy_path.connect(self._copy_path)

        self._side = QFrame()
        self._side.setObjectName("sideCard")
        side_l = QVBoxLayout(self._side)
        side_l.setContentsMargins(14, 14, 14, 14)
        side_l.addWidget(self.catalog)

        recipe_shell = QFrame()
        recipe_shell.setObjectName("recipeShell")
        recipe_shell_l = QVBoxLayout(recipe_shell)
        recipe_shell_l.setContentsMargins(14, 12, 14, 12)
        recipe_shell_l.addWidget(self.recipe)
        self._recipe_shell = recipe_shell

        track = QFrame()
        track.setObjectName("trackCard")
        track_l = QVBoxLayout(track)
        track_l.setContentsMargins(14, 12, 14, 12)
        track_l.addWidget(self.cascade)
        self._track = track

        self._splitter = QSplitter()
        self._splitter.addWidget(self.input_pane)
        self._splitter.addWidget(self.output_pane)
        self._splitter.setStretchFactor(0, 1)
        self._splitter.setStretchFactor(1, 1)
        self._splitter.setChildrenCollapsible(False)
        self._splitter.setMinimumHeight(280)

        self._work = QWidget()
        self._work_l = QHBoxLayout(self._work)
        self._work_l.setContentsMargins(0, 0, 0, 0)
        self._work_l.setSpacing(12)
        self._work_l.addWidget(self._side, 0)
        self._work_l.addWidget(self._splitter, 1)

        stage = QWidget()
        stage_l = QVBoxLayout(stage)
        stage_l.setContentsMargins(0, 0, 0, 0)
        stage_l.setSpacing(10)
        stage_l.addWidget(self._hero)
        stage_l.addWidget(self._recipe_shell)
        stage_l.addWidget(self._track)
        stage_l.addWidget(self._work, 1)
        self._stage_l = stage_l

        layout = QHBoxLayout(root)
        layout.setContentsMargins(12, 12, 12, 8)
        layout.setSpacing(12)
        layout.addWidget(self._rail)
        layout.addWidget(stage, 1)

        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._error = QLabel()
        self._error.setObjectName("error")
        self._error.setWordWrap(True)
        self._error.setTextFormat(Qt.TextFormat.PlainText)
        stage_l.addWidget(self._error)

        copy_shortcut = QAction(self)
        copy_shortcut.setShortcut(QKeySequence("Ctrl+Shift+C"))
        copy_shortcut.triggered.connect(self.copy_output)
        self.addAction(copy_shortcut)

        self.retranslate()
        self.setMinimumSize(640, 520)
        self.resize(1280, 800)
        self._apply_mode_layout()
        self._layout_key = None
        self._apply_responsive_layout()
        self.schedule_bake()

    def retranslate(self) -> None:
        lang = self.lang
        self.setWindowTitle(t(lang, "app_title"))
        self._manual_btn.setText(t(lang, "mode_manual"))
        self._auto_btn.setText(t(lang, "mode_auto"))
        self._text_btn.setText(t(lang, "view_text"))
        self._hex_btn.setText(t(lang, "view_hex"))
        self._offline.setText(t(lang, "offline"))
        self._brand_mark.setText(t(lang, "brand_mark"))
        self._hero_title.setText(
            t(lang, "hero_manual" if self.mode == "manual" else "hero_auto")
        )
        self._mode_hint.setText(
            t(lang, "mode_hint_auto" if self.mode == "auto" else "mode_hint_manual")
        )
        self.catalog.retranslate(lang)
        self.input_pane.set_workspace(self.mode)
        self.output_pane.set_workspace(self.mode)
        self.recipe.retranslate(lang)
        self.cascade.retranslate(lang)
        if self.mode == "auto" and self._magic_nodes:
            chosen = best_node(self._magic_nodes)
            self._set_cascade_nodes(chosen)
        if self._last:
            self._render_result(self._last)
        self._refresh_file_banner()

    def _add_encode_op(self, op_id: str) -> None:
        if not op_id:
            return
        params = default_params(op_id)
        if "decrypt" in params:
            params["decrypt"] = False
        self.recipe.add_op(op_id, params)

    def _on_input_typed(self) -> None:
        if self.input_pane.editor.toPlainText():
            self._file_bytes = None
            self._refresh_file_banner()
        self.schedule_bake()

    def _load_file(self, data: bytes, _path: str) -> None:
        self._file_bytes = data
        if looks_image(data):
            self.input_pane.load_text("")
        else:
            self.input_pane.load_text(text_from_bytes(data))
        self._refresh_file_banner()
        self.schedule_bake()

    def _clear_input(self) -> None:
        self._file_bytes = None
        self.input_pane.load_text("")
        self._refresh_file_banner()
        self.schedule_bake()

    def _swap_io(self) -> None:
        incoming = self.output_pane.editor.toPlainText()
        outgoing = self.input_pane.editor.toPlainText()
        self._file_bytes = None
        self.input_pane.load_text(incoming)
        self.output_pane.editor.setPlainText(outgoing)
        self._refresh_file_banner()
        self.schedule_bake()

    def _copy_path(self, path: str) -> None:
        if path:
            QGuiApplication.clipboard().setText(path)
            self._status.showMessage(t(self.lang, "path_copied"), 2000)

    def _refresh_file_banner(self) -> None:
        if not self._file_bytes:
            self.input_pane.set_file_banner(None)
            return
        key = "image_loaded" if looks_image(self._file_bytes) else "file_loaded"
        self.input_pane.set_file_banner(t(self.lang, key).format(n=len(self._file_bytes)))

    def _input_bytes(self) -> bytes:
        if self._file_bytes is not None:
            return self._file_bytes
        return self.input_pane.editor.toPlainText().encode("utf-8")

    def _set_mode(self, mode: str) -> None:
        self.mode = mode
        self._manual_btn.setChecked(mode == "manual")
        self._auto_btn.setChecked(mode == "auto")
        self._apply_mode_layout()
        self.schedule_bake()

    def _apply_chrome(self) -> None:
        app = QApplication.instance()
        if app is None:
            return
        chrome = "encode" if self.mode == "manual" else "decode"
        app.setStyleSheet(themed_stylesheet(app, chrome))

    def _apply_mode_layout(self) -> None:
        manual = self.mode == "manual"
        self._recipe_shell.setVisible(manual)
        self._track.setVisible(not manual)
        self._side.setVisible(manual)
        self._hero_title.setText(t(self.lang, "hero_manual" if manual else "hero_auto"))
        self._mode_hint.setText(
            t(self.lang, "mode_hint_manual" if manual else "mode_hint_auto")
        )
        self.input_pane.set_workspace(self.mode)
        self.output_pane.set_workspace(self.mode)
        self._apply_chrome()
        self._layout_key = None
        self._apply_responsive_layout()

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._apply_responsive_layout()

    def _apply_responsive_layout(self) -> None:
        if not hasattr(self, "_splitter"):
            return
        width = max(self.width(), 1)
        height = max(self.height(), 1)
        half = width < 860
        compact = width < 920 or height < 700
        manual = self.mode == "manual"
        orientation = Qt.Orientation.Vertical if half else Qt.Orientation.Horizontal
        key = (half, compact, manual, orientation, height < 700)
        if getattr(self, "_layout_key", None) == key:
            return
        self._layout_key = key
        self._offline.setVisible(width >= 1100 and not compact)
        self._brand_mark.setVisible(not compact)
        self._rail.setFixedWidth(124 if compact else 168)
        self._auto_btn.setMinimumHeight(44 if compact else 58)
        self._manual_btn.setMinimumHeight(44 if compact else 58)
        self._hero.setVisible(not compact)
        self._mode_hint.setVisible(not compact)
        self.cascade.set_compact(compact)
        self.input_pane.set_compact(compact)
        self.output_pane.set_compact(compact)
        self.recipe.set_compact(compact)
        self.catalog.set_compact(compact)
        if self._splitter.orientation() != orientation:
            self._splitter.setOrientation(orientation)
        if self._work_l.direction() != QBoxLayout.Direction.LeftToRight:
            self._work_l.setDirection(QBoxLayout.Direction.LeftToRight)
        recipe_layout = self._recipe_shell.layout()
        side_layout = self._side.layout()
        track_layout = self._track.layout()
        if recipe_layout is not None:
            recipe_layout.setContentsMargins(10, 8, 10, 8) if compact else recipe_layout.setContentsMargins(14, 12, 14, 12)
        if side_layout is not None:
            side_layout.setContentsMargins(10, 10, 10, 10) if compact else side_layout.setContentsMargins(14, 14, 14, 14)
        if track_layout is not None:
            track_layout.setContentsMargins(10, 8, 10, 8) if compact else track_layout.setContentsMargins(14, 12, 14, 12)
        self._side.setMaximumHeight(16777215)
        if manual:
            self._side.setMinimumWidth(160 if compact else 200)
            self._side.setMaximumWidth(210 if compact else 300)
        else:
            self._side.setMinimumWidth(0)
            self._side.setMaximumWidth(0)
        if half:
            self._splitter.setSizes([320, 320])
        else:
            self._splitter.setSizes([560, 560])

    def _set_lang(self, lang: str) -> None:
        self.lang = lang
        self._fr_btn.setChecked(lang == "fr")
        self._en_btn.setChecked(lang == "en")
        self.retranslate()
        self.bake()

    def _set_view(self, view: str) -> None:
        self.view_mode = view
        self._text_btn.setChecked(view == "text")
        self._hex_btn.setChecked(view == "hex")
        wrap = (
            QPlainTextEdit.LineWrapMode.NoWrap
            if view == "hex"
            else QPlainTextEdit.LineWrapMode.WidgetWidth
        )
        self.output_pane.editor.setLineWrapMode(wrap)
        if self._last:
            self._render_result(self._last)

    def schedule_bake(self) -> None:
        self._bake_timer.setInterval(220 if self.mode == "auto" else 80)
        self._bake_timer.start()

    def bake(self) -> None:
        raw = self._input_bytes()
        if len(raw) > MAX_MANUAL_BYTES:
            self._magic_nodes = []
            self.cascade.set_nodes([])
            self.output_pane.editor.clear()
            self.output_pane.set_path_caption(t(self.lang, "path_none"))
            self._error.setText(t(self.lang, "input_too_large"))
            self._status.clearMessage()
            return
        if not raw.strip():
            self._magic_nodes = []
            self.cascade.set_nodes([])
            self.output_pane.editor.clear()
            self.output_pane.set_path_caption(t(self.lang, "path_none"))
            self._error.setText("")
            self._status.clearMessage()
            return
        if self.mode == "auto":
            self._magic_gen += 1
            self._status.showMessage(t(self.lang, "analyzing"))
            self._error.setText("")
            job = _ExploreJob(self._magic_gen, raw, self._explore_signals)
            self._explore_pool.start(job)
            return
        self._bake_gen += 1
        self._status.showMessage(t(self.lang, "analyzing"))
        self._error.setText("")
        steps = [Step(step.op_id, dict(step.params)) for step in self.recipe.steps]
        job = _BakeJob(self._bake_gen, raw, steps, self.lang, self._bake_signals)
        self._bake_pool.start(job)

    def _on_bake_done(self, generation: int, payload: object) -> None:
        if generation != self._bake_gen or self.mode != "manual":
            return
        if isinstance(payload, DecodeError):
            raw = self._input_bytes()
            result = run_steps(raw, [], lang=self.lang)
            result.error = payload.localized(self.lang)
            self._last = result
            self.output_pane.set_path_caption(t(self.lang, "path_none"))
            self._render_result(result)
            return
        if isinstance(payload, Exception):
            self._error.setText(t(self.lang, "internal_error"))
            return
        if not isinstance(payload, BakeResult):
            self._error.setText(t(self.lang, "internal_error"))
            return
        self._last = payload
        path = format_path(self.recipe.steps, self.lang)
        if any(get_op(step.op_id).one_way for step in self.recipe.steps):
            notice = t(self.lang, "hash_in_pipeline")
            path = f"{path} — {notice}" if path else notice
        self.output_pane.set_path_caption(path or t(self.lang, "path_none"))
        self._render_result(payload)

    def _on_magic_done(self, generation: int, payload: object) -> None:
        if generation != self._magic_gen or self.mode != "auto":
            return
        raw = self._input_bytes()
        if isinstance(payload, DecodeError):
            self._magic_nodes = []
            self.cascade.set_nodes([])
            self._error.setText(payload.localized(self.lang))
            self.output_pane.set_path_caption(t(self.lang, "path_none"))
            result = run_steps(raw, [], lang=self.lang)
            self._last = result
            self._render_result(result)
            return
        if isinstance(payload, Exception):
            self._magic_nodes = []
            self.cascade.set_nodes([])
            self._error.setText(t(self.lang, "internal_error"))
            self.output_pane.set_path_caption(t(self.lang, "path_none"))
            result = run_steps(raw, [], lang=self.lang)
            self._last = result
            self._render_result(result)
            return
        nodes = payload if isinstance(payload, list) else []
        self._magic_nodes = nodes
        chosen = best_node(nodes)
        if chosen:
            self._show_magic_node(chosen)
        else:
            self.cascade.set_nodes([])
            self.output_pane.set_path_caption(t(self.lang, "path_none"))
            result = run_steps(raw, [], lang=self.lang)
            self._last = result
            self._render_result(result)

    def _set_cascade_nodes(self, selected: MagicNode | None) -> None:
        shown = top_nodes(self._magic_nodes, 3)
        if selected is not None and all(node.path != selected.path for node in shown):
            shown = [selected, *shown[:2]]
        self.cascade.set_nodes(shown, selected=selected)

    def _show_magic_node(self, node: MagicNode) -> None:
        if self.mode == "auto":
            self._set_cascade_nodes(node)
            path = format_path(node.path, self.lang)
            kind = hash_digest_kind(self._input_bytes())
            if kind and not node.path:
                path = t(self.lang, "hash_one_way").format(algo=kind)
            self.output_pane.set_path_caption(path or t(self.lang, "path_none"))
        text, utf8_ok = decode_utf8_view(node.data)
        result = BakeResult(
            data=node.data,
            utf8_text=text,
            utf8_ok=utf8_ok,
            hexdump=to_hexdump(node.data),
            byte_len=len(node.data),
            steps_ok=len(node.path),
        )
        self._last = result
        self._render_result(result)

    def _render_result(self, result: BakeResult) -> None:
        if self.view_mode == "hex":
            self.output_pane.editor.setPlainText(result.hexdump)
        else:
            self.output_pane.editor.setPlainText(result.utf8_text)
        utf = t(self.lang, "utf8_ok" if result.utf8_ok else "utf8_bad")
        self._status.showMessage(
            f"{result.byte_len} {t(self.lang, 'bytes')} · {utf} · "
            f"{result.steps_ok} {t(self.lang, 'steps')}"
        )
        self._error.setText(result.error or "")

    def copy_output(self) -> None:
        text = self.output_pane.editor.toPlainText()
        QGuiApplication.clipboard().setText(text)
        self._status.showMessage(t(self.lang, "copied"), 2000)

    def _save_output(self) -> None:
        data = self._last.data if self._last is not None else b""
        if not data:
            text = self.output_pane.editor.toPlainText()
            data = text.encode("utf-8")
        if not data:
            return
        path, _filter = QFileDialog.getSaveFileName(
            self,
            t(self.lang, "save_file"),
            "",
            t(self.lang, "save_filter"),
        )
        if not path:
            return
        try:
            with open(path, "wb") as handle:
                handle.write(data)
        except OSError:
            self._error.setText(t(self.lang, "save_failed"))
            return
        self._status.showMessage(t(self.lang, "saved"), 2000)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Cascade")
    app.setOrganizationName("Cascade")
    app.setStyle("Fusion")
    app.setStyleSheet(apply_app_fonts(app))
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
