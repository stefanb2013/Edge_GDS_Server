# PyInstaller spec for the Windows Service build of the Edge GDS Server.
# Build with:  pyinstaller windows_service.spec
#
# onedir (not onefile): a Windows Service needs a stable path to find its
# own files on every start, and onefile's per-run extraction to a fresh
# temp %TEMP% directory (sys._MEIPASS) is exactly the wrong shape for that
# -- onedir keeps everything in one folder next to the built .exe, which is
# also where gds/config.py looks for a `.env` file.

from PyInstaller.utils.hooks import collect_data_files

block_cipher = None

# asyncua ships its own bundled standard-address-space cache
# (binary_address_space.pickle) as package data, not Python code --
# PyInstaller's default import analysis won't pick that up on its own.
datas = [
    ('nodesets', 'nodesets'),
    ('web/templates', 'web/templates'),
    ('web/static', 'web/static'),
]
datas += collect_data_files('asyncua')

a = Analysis(
    ['windows_service.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'win32timezone',
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='EdgeGDSServer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='EdgeGDSServer',
)
