# -*- mode: python -*-

block_cipher = None


a = Analysis(['bin/blockstack'],
             pathex=['/home/debian/Desktop/research/git/blockstack-core'],
             binaries=[],
             datas=[],
             hiddenimports=['_scrypt', 'blockstack_client.backend.drivers.disk', 'blockstack_client.backend.drivers.blockstack_resolver', 'blockstack_client.backend.drivers.blockstack_server', 'blockstack_client.backend.drivers.dht', 'blockstack_client.backend.drivers.dropbox', 'blockstack_client.backend.drivers.gdrive', 'blockstack_client.backend.drivers.http', 'blockstack_client.backend.drivers.onedrive', 'blockstack_client.backend.drivers.s3'],
             hookspath=[],
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
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='blockstack')
