# Interface Contract (`m0-contract`)

## 1. Transaction & Sighash (`A -> B`)
- **Functions:**
  - `encode_tx(tx: Tx, include_witness: bool = False) -> bytes`
  - `decode_tx(raw: bytes) -> Tx`
  - `txid(tx: Tx) -> str` (64-char hex of `sha256d(encode_tx(tx, include_witness=False))`)
  - `sighash(tx: Tx, input_index: int, spent_amounts: list[int]) -> bytes` (32-byte digest committing to version, all inputs, all spent output amounts, and all outputs)
- **Fixture:** `fixtures/tx_vectors.json`

## 2. UTXO Set Apply / Undo (`B -> C`)
- **Data Structures:**
  - `OutPoint(txid: str, vout: int)`
  - `UTXO(amount: int, pubkey_hash: bytes, height: int, is_coinbase: bool)`
  - `UndoBlock(height: int, spent: list[tuple[OutPoint, UTXO]], created: list[OutPoint])`
- **Functions:**
  - `apply_block(utxo_set: UTXOSet, block: Block, height: int, subsidy: int = 5000, maturity: int = 10) -> UndoBlock`
  - `undo_block(utxo_set: UTXOSet, undo: UndoBlock) -> None`
- **Fixture:** `fixtures/utxo_small.json`

## 3. Block & Chain Interface (`C -> B`)
- **Data Structure:**
  - `BlockHeader(version: int, prev_hash: str, merkle_root: str, timestamp: int, target: int, nonce: int)`
  - `Block(header: BlockHeader, txs: list[Tx])`
- **Fixture:** `fixtures/block_sample.json`
