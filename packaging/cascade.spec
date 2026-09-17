# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

root = Path(SPECPATH).resolve().parent
src = root / "src"

a = Analysis(
    [str(src / "cascade" / "__main__.py")],
    pathex=[str(src)],
    binaries=[],
    datas=[],
    hiddenimports=[
        "cascade",
        "cascade.app",
        "cascade.engine",
        "Crypto.Cipher.AES",
        "Crypto.Cipher.DES",
        "Crypto.Cipher.DES3",
        "Crypto.Cipher.ARC4",
        "Crypto.Util.Padding",
        "PIL",
        "PIL.Image",
        "cv2",
        "numpy",
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "pytest",
        "PySide6.Qt3DAnimation",
        "PySide6.Qt3DCore",
        "PySide6.Qt3DRender",
        "PySide6.QtQuick",
        "PySide6.QtQml",
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtMultimedia",
        "PySide6.QtBluetooth",
        "PySide6.QtPdf",
        "PySide6.QtCharts",
        "Crypto.SelfTest",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Cascade",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)
