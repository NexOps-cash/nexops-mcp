# Cashtokens Nft

## Pattern Purpose

Immutable (0x00+commitment), mutable (0x01), minting (0x02) NFT flows.

## Security Model

Capability category correct; mint authority covenant-bound; commitment preserved on immutable.

## Required Invariants

| Invariant ID | Tier | Must hold |
|--------------|------|-----------|
| `token_category_preservation` | security/business | ENFORCED on spend |
| `auth_gate` | security/business | ENFORCED on spend |

## Common Vulnerabilities

- authority_leak
- commitment loss
- mutable without re-anchor
- unrestricted transfer

## Audit Checklist

- [ ] authority_leak
- [ ] nft_commitment_loss
- [ ] mutable_capability_leak
- [ ] capability_unrestricted_nft_transfer

## Known NexOps Gaps

Soulbound intent vs detector

See [`coverage_gap_analysis.md`](../coverage_gap_analysis.md).

## Reference Contracts

ct_nft_*, ct_mint_*, detector fixtures

## Related Knowledge

- Generation rules: `src/services/knowledge_structured/nft_rules.yaml`
- Benchmark entries: [`benchmark_registry.json`](../benchmark_registry.json)
