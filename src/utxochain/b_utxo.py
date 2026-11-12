"""Role B (Aizhan Khalikova): UTXO state validation, coinbase maturity, and block apply/undo."""
from __future__ import annotations
from dataclasses import dataclass
from .a_tx import Tx, verify_tx_signatures
from .crypto import sha256


class ConsensusError(Exception):
    """Raised when a transaction or block violates UTXO consensus rules."""


@dataclass(frozen=True)
class OutPoint:
    txid: str
    vout: int


@dataclass(frozen=True)
class UTXO:
    amount: int
    pubkey_hash: bytes
    height: int
    is_coinbase: bool


@dataclass(frozen=True)
class UndoBlock:
    height: int
    spent: list[tuple[OutPoint, UTXO]]
    created: list[OutPoint]


class UTXOSet:
    def __init__(self, initial: dict[OutPoint, UTXO] | None = None) -> None:
        self._utxos: dict[OutPoint, UTXO] = dict(initial) if initial else {}

    def get(self, op: OutPoint) -> UTXO | None:
        return self._utxos.get(op)

    def __contains__(self, op: OutPoint) -> bool:
        return op in self._utxos

    def __len__(self) -> int:
        return len(self._utxos)

    def items(self):
        return self._utxos.items()

    def balance_of(self, pubkey_hash: bytes) -> int:
        return sum(u.amount for u in self._utxos.values() if u.pubkey_hash == pubkey_hash)

    def utxos_for(
        self,
        pubkey_hash: bytes,
        current_height: int | None = None,
        maturity: int = 10,
    ) -> list[tuple[str, int, int]]:
        res = []
        for op, u in sorted(self._utxos.items(), key=lambda kv: (kv[0].txid, kv[0].vout)):
            if u.pubkey_hash != pubkey_hash:
                continue
            if current_height is not None and u.is_coinbase and (current_height - u.height) < maturity:
                continue
            res.append((op.txid, op.vout, u.amount))
        return res

    def state_hash(self) -> str:
        """Deterministic cryptographic commitment to the entire UTXO set."""
        entries = sorted(
            (
                op.txid,
                op.vout,
                u.amount,
                u.pubkey_hash.hex(),
                u.height,
                int(u.is_coinbase),
            )
            for op, u in self._utxos.items()
        )
        raw = "|".join(f"{t}:{v}:{a}:{p}:{h}:{c}" for t, v, a, p, h, c in entries).encode()
        return sha256(raw).hex()

    def clone(self) -> UTXOSet:
        return UTXOSet(self._utxos)


def validate_transaction(
    tx: Tx,
    utxo_set: UTXOSet,
    current_height: int,
    maturity: int = 10,
    already_spent_in_block: set[OutPoint] | None = None,
) -> int:
    """B1: Validate a non-coinbase transaction and return its fee (sum_in - sum_out)."""
    if tx.is_coinbase:
        raise ConsensusError("Unexpected coinbase transaction")
    if not tx.inputs:
        raise ConsensusError("Transaction has no inputs")
    if not tx.outputs:
        raise ConsensusError("Transaction has no outputs")
    if any(o.amount <= 0 for o in tx.outputs):
        raise ConsensusError("Output amount must be positive")

    seen: set[OutPoint] = set()
    spent_amounts: list[int] = []
    expected_pkhs: list[bytes] = []

    for txin in tx.inputs:
        op = OutPoint(txin.prev_txid, txin.prev_vout)
        if op in seen or (already_spent_in_block is not None and op in already_spent_in_block):
            raise ConsensusError(f"Duplicate spend of {op}")
        seen.add(op)
        utxo = utxo_set.get(op)
        if utxo is None:
            raise ConsensusError(f"Missing UTXO {op}")
        if utxo.is_coinbase and (current_height - utxo.height) < maturity:
            raise ConsensusError(
                f"Immature coinbase spend at height {current_height} (created at {utxo.height}, maturity {maturity})"
            )
        spent_amounts.append(utxo.amount)
        expected_pkhs.append(utxo.pubkey_hash)

    sum_in = sum(spent_amounts)
    sum_out = sum(o.amount for o in tx.outputs)
    if sum_in < sum_out:
        raise ConsensusError(f"Inputs ({sum_in}) < outputs ({sum_out})")

    if not verify_tx_signatures(tx, spent_amounts, expected_pkhs):
        raise ConsensusError("Invalid ECDSA witness signature or pubkey hash mismatch")

    return sum_in - sum_out


def apply_block(
    utxo_set: UTXOSet,
    txs: list[Tx],
    height: int,
    subsidy: int = 5000,
    maturity: int = 10,
) -> UndoBlock:
    """B1 + B2 + B3: Validate all txs in a block, mutate utxo_set atomically, and return UndoBlock."""
    if not txs or not txs[0].is_coinbase:
        raise ConsensusError("First transaction in block must be coinbase")
    if any(t.is_coinbase for t in txs[1:]):
        raise ConsensusError("Multiple coinbase transactions in block")

    spent_in_block: set[OutPoint] = set()
    total_fees = 0
    for tx in txs[1:]:
        fee = validate_transaction(
            tx,
            utxo_set,
            current_height=height,
            maturity=maturity,
            already_spent_in_block=spent_in_block,
        )
        total_fees += fee
        for txin in tx.inputs:
            spent_in_block.add(OutPoint(txin.prev_txid, txin.prev_vout))

    cb = txs[0]
    if not cb.outputs or any(o.amount <= 0 for o in cb.outputs):
        raise ConsensusError("Invalid coinbase outputs")
    cb_total = sum(o.amount for o in cb.outputs)
    if cb_total > subsidy + total_fees:
        raise ConsensusError(f"Coinbase claims {cb_total} > max allowed {subsidy + total_fees}")

    spent_records: list[tuple[OutPoint, UTXO]] = []
    created_records: list[OutPoint] = []

    for tx in txs[1:]:
        for txin in tx.inputs:
            op = OutPoint(txin.prev_txid, txin.prev_vout)
            prev_u = utxo_set._utxos.pop(op)
            spent_records.append((op, prev_u))

    for tx_idx, tx in enumerate(txs):
        tid = tx.txid()
        is_cb = tx_idx == 0
        for vout, txout in enumerate(tx.outputs):
            op = OutPoint(tid, vout)
            if op in utxo_set._utxos:
                raise ConsensusError(f"Duplicate txid collision {op}")
            utxo_set._utxos[op] = UTXO(
                amount=txout.amount,
                pubkey_hash=txout.pubkey_hash,
                height=height,
                is_coinbase=is_cb,
            )
            created_records.append(op)

    return UndoBlock(height=height, spent=spent_records, created=created_records)


def undo_block(utxo_set: UTXOSet, undo: UndoBlock) -> None:
    """B3: Deterministically revert a block using its UndoBlock."""
    for op in reversed(undo.created):
        if op not in utxo_set._utxos:
            raise ConsensusError(f"Cannot undo: created UTXO {op} missing")
        del utxo_set._utxos[op]
    for op, prev_u in reversed(undo.spent):
        if op in utxo_set._utxos:
            raise ConsensusError(f"Cannot undo: spent UTXO {op} already exists")
        utxo_set._utxos[op] = prev_u
