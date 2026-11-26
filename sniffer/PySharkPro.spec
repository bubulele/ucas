# -*- mode: python ; coding: utf-8 -*-
# 可选：使用 PyInstaller 打包为单文件 exe（目标机仍需安装 Npcap）
block_cipher = None
a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['scapy.layers.all', 'scapy.layers.tls.all'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [],
          name='PySharkPro', debug=False, bootloader_ignore_signals=False,
          strip=False, upx=True, console=False)
