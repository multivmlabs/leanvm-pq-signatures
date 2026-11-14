#!/usr/bin/env python3
"""Build the isolated twiddle64 guest without modifying the baseline or vendor."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
PINS={'vendor/leanVM-riscv':'06e5c9cd6981103786f9d0a17324241b559a50d3','vendor/ETHDILITHIUM':'f9f4fe1d84e68304b425e054c273c276fe44ba11'}
def command(*args):return subprocess.check_output(args,text=True).strip()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 for directory,pin in PINS.items():
  assert command('git','-C',str(ROOT/directory),'rev-parse','HEAD')==pin
  assert command('git','-C',str(ROOT/directory),'status','--porcelain')==''
 ref=ROOT/'vendor/ETHDILITHIUM/c-ref';changed=[]
 for path in (HERE/'c-ref').iterdir():
  if path.read_bytes()!=(ref/path.name).read_bytes():changed.append(path.name)
 assert changed==['ntt.c'],changed
 original=(ref/'ntt.c').read_text()
 expected=original.replace('static const int32_t zetas[N]','static const int64_t zetas[N]').replace('  int32_t zeta, t;','  int64_t zeta;\n  int32_t t;').replace('  int32_t t, zeta;','  int32_t t;\n  int64_t zeta;')
 assert (HERE/'c-ref/ntt.c').read_text()==expected
 compiler=os.environ.get('MLDSA_CLANG','clang');version=command(compiler,'--version');resolved=shutil.which(compiler) or compiler
 env=os.environ.copy();env.setdefault('CARGO_HOME',str(ROOT/'.cache/riscv-cargo'))
 env['MLDSA_CLANG_FINGERPRINT']=hashlib.sha256((resolved+'\n'+version).encode()).hexdigest()
 subprocess.run(['cargo','+nightly-2026-10-03','build','--release','--offline','--locked'],cwd=HERE/'guest',env=env,check=True)
 target=HERE/'guest/target/riscv64im-unknown-none-elf/release/mldsa-twiddle64-guest';shutil.copy2(target,HERE/'twiddle64.elf')
 paths=[p for p in HERE.rglob('*') if p.is_file() and 'target' not in p.parts and p.suffix in ['.rs','.c','.h','.toml','.lock','.py','.patch']]
 paths+=[ROOT/'vendor/leanVM-riscv/sdk/src/keccak.rs']
 report={'pins':PINS,'scope':'Only fixed NTT twiddle table and local zeta widened; polynomial storage remains int32. Baseline SDK software Keccak, unchanged compact FIPS204 relation and commitment cap.',
 'elf_sha256':sha(target),'elf_bytes':target.stat().st_size,'clang':version,'clang_path':resolved,'compiler_fingerprint':env['MLDSA_CLANG_FINGERPRINT'],'rustc':command('rustc','+nightly-2026-10-03','--version','--verbose'),
 'changed_reference_files':changed,'patch_sha256':sha(HERE/'twiddle64.patch'),'sources':{str(p.relative_to(ROOT)):sha(p) for p in sorted(paths)}}
 (HERE/'build-manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(report['elf_sha256'])
if __name__=='__main__':main()
