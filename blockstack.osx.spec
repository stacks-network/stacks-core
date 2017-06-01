# -*- mode: python -*-

import os

block_cipher = None
# options = [('v', None, 'OPTION'), ('W ignore', None, 'OPTION')]

build_path_osx = os.path.dirname(SPECPATH)

build_path = build_path_osx

a = Analysis(['bin/blockstack', 'bin/blockstack-core'],
             pathex=[build_path],
             binaries=[],
             datas=[],
             hiddenimports=['blockstack_client.backend.drivers.disk', 
                            'blockstack_client.backend.drivers.s3', 
                            'blockstack_client.backend.drivers.dht', 
                            'blockstack_client.backend.drivers.blockstack_server', 
                            'blockstack_client.backend.drivers.blockstack_resolver', 
                            'blockstack_client.backend.drivers.http'],
             hookspath=['pkg/pyinstaller/hooks/'],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='blockstack',
          debug=False,
          strip=False,
          upx=True,
          console=True)

exe2 = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='blockstack-core',
          debug=False,
          strip=False,
          upx=True,
          console=True)

coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               name='blockstack',
               strip=False,
               upx=True)
