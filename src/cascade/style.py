from __future__ import annotations

DECODE = {
    "BG": "#04151c",
    "SURFACE": "#0a2c38",
    "CARD": "#0d3646",
    "ACCENT": "#2ee6c7",
    "ACCENT_TEXT": "#04221c",
    "ACCENT2": "#7ee0ff",
    "TEXT": "#e7fffb",
    "MUTED": "#8ab8bc",
    "BORDER": "#1c5566",
    "DANGER": "#ff6b7a",
    "INPUT": "#062430",
    "HOVER": "#15485a",
    "CHIP": "#114050",
    "TILE": "#0f3f52",
    "RAIL": "#072430",
}

ENCODE = {
    "BG": "#1a0a10",
    "SURFACE": "#34141c",
    "CARD": "#3f1824",
    "ACCENT": "#ff6a45",
    "ACCENT_TEXT": "#2a0b08",
    "ACCENT2": "#ffc857",
    "TEXT": "#fff3ec",
    "MUTED": "#c49a90",
    "BORDER": "#6e3038",
    "DANGER": "#ff8aa0",
    "INPUT": "#241016",
    "HOVER": "#4c2230",
    "CHIP": "#4a2030",
    "TILE": "#451c2a",
    "RAIL": "#2a1016",
}

QSS = """
QMainWindow, QWidget#root {
    background: __BG__;
    color: __TEXT__;
    font-size: 13px;
    font-family: "__UI_FONT__";
}
QWidget {
    color: __TEXT__;
    font-size: 13px;
    font-family: "__UI_FONT__";
    background: transparent;
}
QScrollArea, QAbstractScrollArea {
    background: transparent;
    border: none;
}
QFrame#rail {
    background: __RAIL__;
    border: 2px solid __BORDER__;
    border-radius: 28px;
}
QLabel#brand {
    font-size: 15px;
    font-weight: 800;
    letter-spacing: 2px;
    color: __ACCENT__;
    padding: 4px 2px 0 2px;
}
QLabel#brandMark {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    color: __ACCENT2__;
}
QPushButton#modeDecode, QPushButton#modeEncode {
    min-height: 58px;
    border-radius: 16px;
    font-size: 14px;
    font-weight: 800;
    letter-spacing: 0.4px;
    padding: 8px 10px;
}
QPushButton#modeDecode {
    background: #0d3a44;
    color: #9fe8dc;
    border: 2px solid #2ee6c7;
}
QPushButton#modeDecode:hover {
    background: #155564;
}
QPushButton#modeDecode:checked {
    background: #2ee6c7;
    color: #042018;
    border-color: #2ee6c7;
}
QPushButton#modeEncode {
    background: #4a1c22;
    color: #ffb4a4;
    border: 2px solid #ff6a45;
}
QPushButton#modeEncode:hover {
    background: #5c2430;
}
QPushButton#modeEncode:checked {
    background: #ff6a45;
    color: #2a0c08;
    border-color: #ff6a45;
}
QFrame#hero {
    background: __CARD__;
    border: 2px solid __BORDER__;
    border-left: 8px solid __ACCENT__;
    border-radius: 20px;
}
QLabel#heroTitle {
    font-size: 18px;
    font-weight: 800;
    color: __ACCENT__;
    letter-spacing: 0.2px;
}
QLabel#heroSub {
    font-size: 13px;
    color: __MUTED__;
}
QFrame#sideCard, QFrame#trackCard, QFrame#recipeShell {
    background: __CARD__;
    border: 2px solid __BORDER__;
    border-radius: 22px;
}
QFrame#ioCard {
    background: __CARD__;
    border: 2px solid __BORDER__;
    border-left: 7px solid __ACCENT__;
    border-radius: 22px;
}
QFrame#seg {
    background: __INPUT__;
    border: 1px solid __BORDER__;
    border-radius: 12px;
}
QFrame#seg QPushButton {
    min-height: 28px;
    padding: 5px 10px;
    border: none;
    border-radius: 8px;
    background: transparent;
    font-weight: 700;
    font-size: 12px;
}
QFrame#seg QPushButton:hover {
    background: __HOVER__;
}
QFrame#seg QPushButton:checked {
    background: __ACCENT__;
    color: __ACCENT_TEXT__;
}
QLabel {
    background: transparent;
    color: __TEXT__;
}
QLabel#muted, QLabel[role="muted"] {
    color: __MUTED__;
    font-size: 12px;
}
QLabel#kicker {
    color: __ACCENT2__;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1px;
}
QLabel#title {
    font-size: 16px;
    font-weight: 700;
    color: __TEXT__;
}
QLabel#score {
    font-size: 12px;
    font-weight: 700;
    color: __ACCENT__;
}
QLabel#error {
    color: __DANGER__;
    padding: 0 4px;
    font-weight: 600;
}
QLineEdit, QPlainTextEdit, QSpinBox, QComboBox {
    background: __INPUT__;
    color: __TEXT__;
    border: 1px solid __BORDER__;
    border-radius: 12px;
    padding: 8px 11px;
    selection-background-color: __ACCENT__;
    selection-color: __ACCENT_TEXT__;
}
QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus {
    border-color: __ACCENT__;
}
QPlainTextEdit {
    font-family: "__MONO_FONT__";
    font-size: 13px;
    padding: 14px;
    border-radius: 16px;
}
QPushButton {
    background: __HOVER__;
    color: __TEXT__;
    border: 1px solid __BORDER__;
    border-radius: 11px;
    padding: 6px 12px;
    min-height: 28px;
}
QPushButton:hover {
    background: __SURFACE__;
    border-color: __ACCENT__;
}
QPushButton:pressed {
    background: __INPUT__;
}
QPushButton:checked {
    background: __ACCENT__;
    border-color: __ACCENT__;
    color: __ACCENT_TEXT__;
}
QPushButton#accent {
    background: __ACCENT__;
    border-color: __ACCENT__;
    color: __ACCENT_TEXT__;
    font-weight: 800;
}
QPushButton#accent:hover {
    background: __ACCENT2__;
    border-color: __ACCENT2__;
    color: __ACCENT_TEXT__;
}
QPushButton#ghost {
    background: transparent;
    border: 1px solid __BORDER__;
    color: __TEXT__;
}
QPushButton#ghost:hover {
    border-color: __ACCENT__;
    background: __HOVER__;
}
QPushButton#danger {
    background: transparent;
    border: 1px solid __DANGER__;
    color: __DANGER__;
}
QPushButton#danger:hover {
    background: __DANGER__;
    color: __ACCENT_TEXT__;
}
QPushButton#chip {
    background: __CHIP__;
    border: 1px solid __ACCENT__;
    color: __TEXT__;
    border-radius: 999px;
    padding: 6px 14px;
    font-weight: 800;
    min-height: 30px;
}
QPushButton#chip:hover {
    background: __ACCENT__;
    color: __ACCENT_TEXT__;
}
QFrame#recipeCard {
    background: __SURFACE__;
    border: 2px solid __ACCENT__;
    border-radius: 12px;
}
QPushButton#recipeChip {
    background: transparent;
    border: none;
    min-height: 26px;
    padding: 2px 8px;
    font-weight: 800;
    font-size: 12px;
}
QPushButton#recipeChip:checked {
    background: __ACCENT__;
    color: __ACCENT_TEXT__;
    border-radius: 8px;
}
QPushButton#encodeTile, QPushButton#transformTile, QPushButton#hashTile {
    min-width: 88px;
    min-height: 32px;
    padding: 4px 8px;
    border-radius: 10px;
    font-weight: 700;
    font-size: 12px;
}
QPushButton#encodeTile {
    background: __TILE__;
    border: 2px solid __ACCENT__;
    color: __TEXT__;
}
QPushButton#encodeTile:hover {
    background: __ACCENT__;
    color: __ACCENT_TEXT__;
}
QPushButton#transformTile {
    background: __CHIP__;
    border: 2px solid __ACCENT2__;
    color: __TEXT__;
}
QPushButton#transformTile:hover {
    background: __ACCENT2__;
    color: __ACCENT_TEXT__;
}
QPushButton#hashTile {
    background: __CHIP__;
    border: 2px dashed __ACCENT2__;
    color: __TEXT__;
}
QPushButton#hashTile:hover {
    background: __ACCENT2__;
    color: __ACCENT_TEXT__;
}
QListWidget {
    background: __INPUT__;
    border: 1px solid __BORDER__;
    border-radius: 12px;
    padding: 6px;
}
QListWidget::item {
    padding: 8px 10px;
    border-radius: 8px;
}
QListWidget::item:selected {
    background: __ACCENT__;
    color: __ACCENT_TEXT__;
}
QListWidget::item:hover {
    background: __HOVER__;
}
QScrollBar:vertical {
    background: __INPUT__;
    width: 10px;
    margin: 4px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: __ACCENT__;
    min-height: 28px;
    border-radius: 5px;
}
QScrollBar:horizontal {
    background: __INPUT__;
    height: 10px;
    margin: 4px;
    border-radius: 5px;
}
QScrollBar::handle:horizontal {
    background: __ACCENT__;
    min-width: 28px;
    border-radius: 5px;
}
QScrollBar::add-line, QScrollBar::sub-line {
    height: 0;
    width: 0;
}
QSplitter::handle {
    background: __BORDER__;
    width: 6px;
    height: 6px;
    border-radius: 3px;
    margin: 4px;
}
QStatusBar {
    background: __RAIL__;
    color: __MUTED__;
    border-top: 1px solid __BORDER__;
}
QStatusBar::item {
    border: none;
}
QFrame#rule {
    background: __ACCENT__;
    border: none;
    max-height: 2px;
}
QTabBar#pathTabs::tab {
    background: transparent;
    color: __MUTED__;
    padding: 7px 10px;
    margin-right: 3px;
    border: none;
    border-bottom: 3px solid transparent;
    min-width: 48px;
    max-width: 140px;
    font-weight: 700;
}
QTabBar#pathTabs::tab:hover {
    color: __TEXT__;
    background: __HOVER__;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
}
QTabBar#pathTabs::tab:selected {
    color: __ACCENT_TEXT__;
    background: __ACCENT__;
    border-bottom: 3px solid __ACCENT__;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
}
QTabBar#pathTabs::scroller {
    width: 28px;
}
QTabBar QToolButton {
    background: __HOVER__;
    border: 1px solid __BORDER__;
    border-radius: 6px;
    color: __TEXT__;
    padding: 2px;
}
QTabBar QToolButton:hover {
    border-color: __ACCENT__;
}
QToolTip {
    background: __SURFACE__;
    color: __TEXT__;
    border: 1px solid __ACCENT__;
    padding: 6px 8px;
}
QComboBox::drop-down {
    border: none;
    width: 22px;
}
QAbstractSpinBox::up-button, QAbstractSpinBox::down-button {
    background: __HOVER__;
    border: none;
    width: 18px;
}
"""


def _installed_family(candidates: tuple[str, ...]) -> str:
    from PySide6.QtGui import QFont, QFontDatabase

    available = {name.casefold() for name in QFontDatabase.families()}
    for name in candidates:
        if name.casefold() in available:
            return name
    return QFont().defaultFamily() or candidates[0]


def themed_stylesheet(app, mode: str) -> str:
    ui = str(app.property("cascadeUiFamily") or "Segoe UI")
    mono = str(app.property("cascadeMonoFamily") or "Consolas")
    tokens = ENCODE if mode == "encode" else DECODE
    qss = QSS.replace("__UI_FONT__", ui).replace("__MONO_FONT__", mono)
    for key, value in sorted(tokens.items(), key=lambda item: len(item[0]), reverse=True):
        qss = qss.replace(f"__{key}__", value)
    return qss


def apply_app_fonts(app) -> str:
    from PySide6.QtGui import QFont

    ui = _installed_family(("Segoe UI", "Arial", "Tahoma", "Verdana"))
    mono = _installed_family(
        ("Cascadia Mono", "Consolas", "Courier New", "Lucida Console")
    )
    font = QFont(ui, 10)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    font.setStyleStrategy(QFont.StyleStrategy.PreferOutline)
    app.setFont(font)
    app.setProperty("cascadeUiFamily", ui)
    app.setProperty("cascadeMonoFamily", mono)
    return themed_stylesheet(app, "decode")
