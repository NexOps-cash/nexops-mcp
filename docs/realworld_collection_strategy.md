# Real-World Contract Collection Strategy

**Workstream:** A.5  
**Output directory:** [`../audit_benchmark_realworld/`](../audit_benchmark_realworld/)

## Goal

Collect **non-synthetic** BCH/CashScript contracts worth more than generated examples. Classify each as `safe`, `unsafe`, or `unknown` for audit benchmark seeding.

---

## Why Real-World First

Synthetic benchmarks prove pipeline mechanics. Real-world contracts prove **ecosystem relevance**:

- Messy naming, incomplete comments, production edge cases
- CashToken category choices developers actually make
- Covenant patterns not in generation YAML

Target: **20–30 indexed contracts** in phase 1; expand to 50+ over 6 months.

---

## Collection Sources

| Priority | Source | Location | Expected yield |
|----------|--------|----------|----------------|
| P0 | NexOps golden templates | `knowledge/golden/patterns/*.cash` | 10 |
| P0 | Anti-pattern knowledge | `knowledge/anti_pattern/*.cash` | 9 (unsafe) |
| P0 | CashTokens detector fixtures | `tests/fixtures/cashtokens_invalid/` | 16 (8 pairs) |
| P1 | Benchmark converged code | `benchmark/results/*.json` | 20–40 |
| P1 | Classification matrix fixtures | `tests/audit_classification_matrix/scenarios.py` | 10 |
| P2 | BCH hackathon / Chipnet repos | External (manual harvest) | 5–10 |
| P2 | Community CashTokens examples | cashtokens.org, GitHub | 5–10 |
| P3 | Production deployments | Partner/consent required | TBD |

---

## Classification Criteria

### `safe`

- Compiles with `cashc`
- Passes Tier 1 audit with declared intent
- No CRITICAL/HIGH vulnerability findings
- Known auth + value conservation for family

### `unsafe`

- Known flaw documented (anti-pattern file, vulnerable fixture side)
- OR fails Tier 1 with expected vulnerability finding
- OR historical exploit / disclosed issue

### `unknown`

- Compiles but intent unclear
- Mixed signals (some paths secure, others not reviewed)
- Pending human review

---

## Index Schema

See [`../audit_benchmark_realworld/index.json`](../audit_benchmark_realworld/index.json).

```json
{
  "id": "rw_escrow_golden_001",
  "filename": "contracts/escrow_2of3_nft.cash",
  "family": "escrow",
  "classification": "safe",
  "source": "nexops_golden",
  "provenance": "knowledge/golden/patterns/escrow_2of3_nft.cash",
  "known_issues": [],
  "audit_status": "never_audited",
  "benchmark_slot": "bench_realworld_012"
}
```

---

## Harvest Procedure

1. **Inventory** — List candidate files with SHA256 of source
2. **Normalize** — Ensure `pragma cashscript` present; record compiler version
3. **Intent draft** — Write minimal intent string for invariant verification
4. **Tier 1 run** — Record findings (manual or script)
5. **Classify** — Apply safe/unsafe/unknown rules
6. **Link** — Map to `bench_realworld_*` slot in benchmark registry
7. **Review** — Security engineer sign-off for `unknown` → final class

---

## Integration with Workstream A

| Real-world ID | Benchmark slot | Role |
|---------------|----------------|------|
| `rw_*` safe | `bench_realworld_NNN` | Tier 3 E2E — expect clean audit |
| `rw_*` unsafe | `bench_realworld_NNN` | Tier 1 — expect specific detector hit |
| `rw_*` unknown | Hold | Do not promote to CI until classified |

---

## External Collection (Phase 2)

### BCH Hackathon / Chipnet

Search targets: `cashscript`, `cashtokens`, `chipnet`, `covenant` on GitHub.

Requirements for inclusion:
- License permitting test use
- Compiles or documented compile fix
- README describing intended behavior

### Production Contracts

Requires:
- Explicit permission
- Redacted keys/addresses if needed
- Snapshot date (contracts may be upgraded)

---

## Maintenance

- Re-classify when detectors add coverage for previously `unknown`
- Bump `audit_status` after each NexOps version audit
- Never delete — deprecate with `superseded_by` field
