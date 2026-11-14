#!/usr/bin/env python3
"""Build a concise results index without extrapolating capacity or performance."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LABEL = {'falcon': 'Falcon-512', 'mldsa': 'ML-DSA-44', 'fors': 'FORS'}


def main():
    summary = {'schema': 2, 'backend_revision': '06e5c9cd6981103786f9d0a17324241b559a50d3',
               'scope': 'Original deterministic fixture prefixes only; these counts are not universal maxima. Direct batches, eight threads, plain proofs, log inverse rate one.',
               'schemes': {}}
    lines = ['# RISC-V signature batch results', '',
             'Apple M4 Pro, 24 GiB RAM, eight total prover threads. One warmup and three measured fresh proofs per count.', '',
             '**These are original-corpus measurements, not universal capacity limits.** The [capacity recheck](reaudit/README.md) proves 33 Falcon signatures from a different valid corpus with the unchanged program, and seven ML-DSA signatures under a separately reviewed storage optimization. Original raw measurements remain unchanged.', '',
             'The proving and verification columns are medians. RSS is the whole-process resident high-water mark, including setup/warmup. Large-batch timing variability is retained in raw samples and figure range bars.', '',
             '| Scheme | Batch | Proving, s | Proof, KiB | Verification, ms | Peak RSS, GiB | Witness words |',
             '|---|---:|---:|---:|---:|---:|---:|']
    for scheme in LABEL:
        reports = []
        failed = []
        for path in sorted((ROOT/'risc-v/results/direct').glob(scheme+'-*.json'), key=lambda p:int(p.stem.split('-')[1])):
            d = json.loads(path.read_text())
            if d.get('status') == 'accepted':
                assert d.get('verified') and len(d['prove_s']) == 3 and len(set(d['proof_bytes_samples'])) == 1
                reports.append(d)
                lines.append(f"| {LABEL[scheme]} | {d['count']} | {d['prove_median_s']:.3f} | {d['proof_bytes']/1024:.2f} | {d['verify_median_s']*1000:.2f} | {d['peak_rss_bytes']/2**30:.2f} | {d['execution']['committed_words']:,} |")
            else:
                assert d['status'] == 'rejected' and d['prover_error'] == 'TooLong'
                failed.append(d)
        if not reports:
            continue
        maximum = max(reports, key=lambda d:d['count'])
        next_count = maximum['count']+1
        boundary = next((d for d in failed if d['count'] == next_count), None)
        assert boundary is not None, f'Missing actual prover rejection after {scheme} maximum'
        assert len({d['elf_sha256'] for d in reports+failed}) == 1
        summary['schemes'][scheme] = {'largest_verified_original_prefix': maximum['count'], 'next_prefix_rejected': next_count,
                                      'elf_sha256': maximum['elf_sha256'],
                                      'largest': {k:maximum[k] for k in ['prove_median_s','proof_bytes','verify_median_s','peak_rss_bytes','execution']},
                                      'reports': [str(p.relative_to(ROOT)) for p in sorted((ROOT/'risc-v/results/direct').glob(scheme+'-*.json'))]}
    new_falcon = ROOT/'risc-v/reviews/lattice-capacity-reaudit/results/falcon-33-start96-proved.json'
    new_mldsa = ROOT/'risc-v/experiments/mldsa-poly64/capacity-proof.json'
    summary['additional_verified_cases'] = {}
    if new_falcon.exists():
        d = json.loads(new_falcon.read_text())
        assert d['actual_proof']['verified']
        summary['additional_verified_cases']['falcon_same_guest_other_corpus'] = {
            'count': d['n'], 'signer_start': d['start'], 'elf_sha256': d['actual_proof']['elf_sha256'],
            'committed_words': d['final']['committed_words'], 'proof_bytes': d['actual_proof']['proof_bytes'],
            'source': str(new_falcon.relative_to(ROOT)), 'universal_maximum_established': False}
    if new_mldsa.exists():
        d = json.loads(new_mldsa.read_text())
        assert d['serialized_decoded_full_verify']
        summary['additional_verified_cases']['mldsa_reviewed_twiddle_storage_variant'] = {
            'count': d['count'], 'elf_sha256': d['guest_sha256'], 'baseline_elf_sha256': d['baseline_guest_sha256'],
            'committed_words': d['committed_words'], 'proof_bytes': d['proof_bytes'],
            'source': str(new_mldsa.relative_to(ROOT)), 'mixed_into_original_timing_series': False}
    (ROOT/'risc-v/results/summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    lines += ['', '## Capacity and verification evidence', '',
              'Each next-count failure was attempted through both Program::measure and Prover::prove. These are commitment-cap rejections, below the guests\' advice bounds. No failed proof size or time is extrapolated.', '',
              'All accepted files were serialized, decoded and checked through full Program::verify. Public-only mutation controls are in [consumer-controls.json](consumer-controls.json). Independently reviewed guest boundaries are in [ML-DSA](../reviews/mldsa-security.md) and [FORS](../reviews/fors-security.md).', '',
              'The points use one fixed deterministic corpus per scheme. Falcon uses the official same-message distinct-key corpus; the other two use distinct messages and keys. Fixture generation and signing are outside proving time. These workloads do not establish matched security levels, deployed wallet authorization, browser performance or EIP gas costs.', '',
              'The official branch and dependency pins are in [UPSTREAM.json](../UPSTREAM.json). Guest build manifests record compiler/source hashes. Initial and final native runner identities are in the environment JSON files. The backend vendor checkout is unmodified.', '']
    (ROOT/'risc-v/results/REPORT.md').write_text('\n'.join(lines))
    print({'original_prefixes': {s:d['largest_verified_original_prefix'] for s,d in summary['schemes'].items()},
           'additional_verified_cases': list(summary['additional_verified_cases'])})


if __name__ == '__main__':
    main()
