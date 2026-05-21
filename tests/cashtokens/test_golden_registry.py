"""CashTokens golden patterns load without invariant anchor errors."""
from knowledge.golden.registry import GoldenRegistry


def test_cashtokens_goldens_load():
    reg = GoldenRegistry()
    for pid, fname in [
        ("ft_transfer", "ft_transfer.cash"),
        ("nft_transfer_immutable", "nft_transfer_immutable.cash"),
        ("nft_mutable_state_update", "nft_mutable_state_update.cash"),
        ("nft_minting_authority", "nft_minting_authority.cash"),
        ("stablecoin_minter_sidecar", "stablecoin_minter_sidecar.cash"),
    ]:
        reg.load_pattern(pid, fname)
        assert pid in reg.patterns
