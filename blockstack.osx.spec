# -*- mode: python -*-

block_cipher = None
# options = [('v', None, 'OPTION'), ('W ignore', None, 'OPTION')]

build_path_osx = '/Users/jude/blockstack/blockstack-core'

bitcoin_data_osx = [
    ('/usr/local/lib/python2.7/site-packages/bitcoin/english.txt', 'bitcoin/')
]

fastecdsa_data_osx = [
    ('/Users/jude/.python-eggs/fastecdsa-1.4.2-py2.7-macosx-10.11-x86_64.egg-tmp/fastecdsa/_ecdsa.so', 'fastecdsa/'),
    ('/Users/jude/.python-eggs/fastecdsa-1.4.2-py2.7-macosx-10.11-x86_64.egg-tmp/fastecdsa/curvemath.so', 'fastecdsa/'),
]

build_path = build_path_osx
datas = bitcoin_data_osx + fastecdsa_data_osx

a = Analysis(['bin/blockstack'],
             pathex=[build_path],
             binaries=[],
             datas=datas,
             hiddenimports=['scrypt', '_scrypt', 'fastecdsa', 'fastecdsa._ecdsa', 'fastecdsa.curvemath', 'blockstack_client.backend.drivers.disk', 'blockstack_client.backend.drivers.s3', 'blockstack_client.backend.drivers.dht', 'blockstack_client.backend.drivers.blockstack_server', 'blockstack_client.backend.drivers.blockstack_resolver', 'blockstack_client.backend.drivers.http'],
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
