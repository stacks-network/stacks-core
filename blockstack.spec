# -*- mode: python -*-

block_cipher = None
# options = [('v', None, 'OPTION'), ('W ignore', None, 'OPTION')]

a = Analysis(['bin/blockstack'],
             pathex=['/home/jude/Desktop/research/git/blockstack-core'],
             binaries=[],
             datas=[],
             hiddenimports=['blockstack_client.backend.drivers.disk', 'blockstack_client.backend.drivers.s3', 'blockstack_client.backend.drivers.dht', 'blockstack_client.backend.drivers.blockstack_server', 'blockstack_client.backend.drivers.blockstack_resolver', 'blockstack_client.backend.drivers.http'],
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
          a.binaries,
          a.zipfiles,
          a.datas,
          name='blockstack',
          debug=False,
          strip=False,
          upx=True,
          console=True )
