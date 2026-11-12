# Project 07 · A Toy UTXO Blockchain

**Team 2 — Óbuda University (Introduction to Blockchain Programming)**
- **Role A (Transactions):** Muhammad Asfer Anwer
- **Role B (UTXO Set):** Aizhan Khalikova
- **Role C (Chain & Consensus):** Kanan Huseynov

## Overview
Bitcoin's design in miniature: signed UTXO transactions using secp256k1 ECDSA (RFC 6979 deterministic nonces + low-s canonicalisation), a UTXO set with deterministic block undo records, and a proof-of-work blockchain with heaviest-work fork choice and multi-block reorganisations.

## Quickstart & Verification

```bash
# Install dependencies (or run directly with python3 -m pytest)
uv sync

# Run all part, integration, and acceptance tests
uv run pytest -v

# Run the full 100-block + partition/heal demo
uv run python -m utxochain.c_chain
```

## Repository Structure
- `src/utxochain/crypto.py`: Pure-Python secp256k1 elliptic curve arithmetic, RFC 6979 deterministic ECDSA, DER encoding, and HASH160.
- `src/utxochain/a_tx.py`: Canonical transaction serialisation (witness excluded from `txid`), amount-committing sighash, signing, and UTXO wallet (`A1–A3`).
- `src/utxochain/b_utxo.py`: UTXO state validation, coinbase reward & maturity rules, and reversible block `apply_block` / `undo_block` (`B1–B3`).
- `src/utxochain/c_chain.py`: Proof-of-work block header, heaviest-work fork choice, deep reorg with UTXO undo/replay, and multi-node gossip simulation (`C1–C3`).
- `tests/parts/`: Unit tests (`test_A1` … `test_C3`) proving each part's *Done when* criteria.
- `tests/integration/`: Pairwise integration tests (`test_I1` … `test_I4`).
- `tests/acceptance/`: End-to-end acceptance test suite (`test_acceptance.py`).
- `docs/`: `interfaces.md`, `report.docx`, and `slides.pptx`.
