# -*- mode: python -*-

import os

def script_name(script_fname):
    return script_fname.split('/')[-1]

block_cipher = None
# options = [('v', None, 'OPTION'), ('W ignore', None, 'OPTION')]

build_path_osx = os.path.dirname(SPECPATH)

build_path = build_path_osx

analysis_kwargs = {
    "pathex" : [build_path],
    "binaries" : [],
    "datas" : [],
    "hiddenimports" : ['blockstack_client.backend.drivers.disk', 
                       'blockstack_client.backend.drivers.s3', 
                       'blockstack_client.backend.drivers.dht', 
                       'blockstack_client.backend.drivers.blockstack_server', 
                       'blockstack_client.backend.drivers.blockstack_resolver', 
                       'blockstack_client.backend.drivers.http'],
    "hookspath" : ['pkg/pyinstaller/hooks/'],
    "runtime_hooks" : [],
    "excludes" : [],
    "win_no_prefer_redirects" : False,
    "win_private_assemblies" : False,
    "cipher" : block_cipher
}

exe_kwargs = {
    "exclude_binaries" : True,
    "debug" : False,
    "strip" : False,
    "upx" : True,
    "console" : True
}

scripts_all = ['bin/blockstack', 'bin/blockstack-core',
               'integration_tests/bin/blockstack-test-scenario']


a = Analysis(scripts_all, **analysis_kwargs)

analysis_others = []
for s in scripts_all[1:]:
    analysis_others.append(
        Analysis([s], **analysis_kwargs))

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz, a.scripts, name=script_name(scripts_all[0]), 
          **exe_kwargs)

exe_others = []
for script, analysis in zip(scripts_all[1:], analysis_others):
    exe_others.append(
        EXE(pyz,
            analysis.scripts,
            name = script_name(script),
            **exe_kwargs))

coll_args = [exe] + exe_others + [a.binaries, a.zipfiles, a.datas]
coll_kwargs = {name : 'blockstack',
               strip : False,
               upx : True} 
coll = COLLECT(*coll_args, **coll_kwargs)
