# -*- mode: python ; coding: utf-8 -*-
# Single-file icli binary: uv run --with pyinstaller pyinstaller icli.spec
#
# The binary is also the ida-nexus worker (see src/icli/cli/frozen.py), so it
# bundles everything the worker imports: the engine (loaded dynamically),
# ida-domain, ida-nexus, idapro, and the whole standard library, which IDA's
# own Python modules and `icli exec` code may use.
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata
from PyInstaller.depend.bindepend import get_python_library_path
import os
import sys
from pathlib import Path

artifact_name = os.environ.get("ARTIFACT_NAME", "icli")

_SKIP_STDLIB = {"antigravity", "idlelib", "lib2to3", "this", "tkinter", "turtle", "turtledemo"}
_TESTS = {"test", "tests", "idle_test"}

hiddenimports = []
for module in sorted(sys.stdlib_module_names):
    if module not in _SKIP_STDLIB and not module.startswith("_"):
        hiddenimports += collect_submodules(module, filter=lambda name: _TESTS.isdisjoint(name.split(".")))
# The engine's modules import IDA, so they are listed from the sources
# rather than found by importing them.
hiddenimports += sorted(
    ".".join(p.relative_to("src").with_suffix("").parts).removesuffix(".__init__")
    for p in Path("src/icli").rglob("*.py")
)
for package in ("ida_domain", "ida_nexus", "idapro"):
    hiddenimports += collect_submodules(package)

datas = []
for dist in ("icli", "ida-domain", "ida-nexus", "idapro"):
    datas += copy_metadata(dist)
datas += collect_data_files("icli")
datas += collect_data_files("ida_nexus")
# `icli ref` indexes ida-domain's sources and shipped examples.
datas += collect_data_files("ida_domain", include_py_files=True)
# `icli schema` reads the item kinds from their sources.
datas += [("src/icli/engine/kinds/*.py", "icli/engine/kinds")]

binaries = []
if sys.platform == "win32":
    python3_dll = os.path.join(os.path.dirname(get_python_library_path()), "python3.dll")
    assert os.path.exists(python3_dll), f"python3.dll not found next to the interpreter: {python3_dll}"
    binaries.append((python3_dll, "."))


a = Analysis(
    ['src/icli/__main__.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=sorted(_SKIP_STDLIB),
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=artifact_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
