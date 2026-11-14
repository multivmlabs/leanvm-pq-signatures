#!/usr/bin/env python3
"""Refresh trial source/artifact identities, preserving exact upstream kernel blobs."""
from pathlib import Path
import hashlib,json,subprocess

BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[2]
blob_shas={'sdk/src/keccak.rs':'8c1a61b2d9c66721575b37f289db2b41b267eef0','sdk/src/keccak_rv64.S':'7502354a8ed6fc9e6dd5c359c189e9e3b3cc5f45'}
for name,sha in blob_shas.items():
 data=(BASE/name).read_bytes()
 assert hashlib.sha1(f'blob {len(data)}\0'.encode()+data).hexdigest()==sha,name
baseline=ROOT/'vendor/leanVM-riscv/sdk/src'
changes=[str(p.relative_to(baseline)) for p in baseline.rglob('*') if p.is_file() and p.read_bytes()!=(BASE/'sdk/src'/p.relative_to(baseline)).read_bytes()]
assert changes==['keccak.rs'],changes
files={str(p.relative_to(BASE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(BASE.rglob('*')) if p.is_file() and 'target' not in p.parts and not p.name.endswith('.log') and p.name!='build-manifest.json'}
manifest={'backend_revision':'06e5c9cd6981103786f9d0a17324241b559a50d3','backend_patch_state':subprocess.check_output(['git','-C',str(ROOT/'vendor/leanVM-riscv'),'status','--short'],text=True),'kernel_source':'https://github.com/leanEthereum/leanVM/pull/605','kernel_head':'c67701c037c11d229c563671419ccc48827b5c2d','kernel_merged':False,'official_blob_sha1':blob_shas,'changed_existing_sdk_sources':changes,'added_sdk_sources':['keccak_rv64.S'],'guest_compiler':subprocess.check_output(['rustc','+nightly-2026-10-03','--version','--verbose'],text=True),'source_and_artifact_sha256':files,'scope':'Same hashes/signatures/publicclaims/backendcap/verifier. Trials are execution+productionmeasure only unless a separate *.proof-result.json explicitly records proof generation.'}
(BASE/'build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(f'{len(files)} source/artifact hashes; official kernel blobs match')
