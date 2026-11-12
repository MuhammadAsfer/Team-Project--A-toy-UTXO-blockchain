"""Role A (Muhammad Asfer Anwer): Canonical UTXO transactions, sighash, signing, and wallet."""
from __future__ import annotations
from dataclasses import dataclass, field
import struct
from .crypto import sha256d, hash160, privkey_to_pubkey, ecdsa_sign, ecdsa_verify


@dataclass(frozen=True)
class TxIn:
    prev_txid: str  # 64-char hex (display order)
    prev_vout: int

    def to_dict(self) -> dict:
        return {"prev_txid": self.prev_txid, "prev_vout": self.prev_vout}

    @classmethod
    def from_dict(cls, d: dict) -> TxIn:
        return cls(prev_txid=d["prev_txid"], prev_vout=int(d["prev_vout"]))


@dataclass(frozen=True)
class TxOut:
    amount: int
    pubkey_hash: bytes  # 20 bytes

    def to_dict(self) -> dict:
        return {"amount": self.amount, "pubkey_hash": self.pubkey_hash.hex()}

    @classmethod
    def from_dict(cls, d: dict) -> TxOut:
        return cls(amount=int(d["amount"]), pubkey_hash=bytes.fromhex(d["pubkey_hash"]))


@dataclass(frozen=True)
class WitnessItem:
    sig: bytes     # DER signature
    pubkey: bytes  # 33-byte compressed SEC1 pubkey

    def to_dict(self) -> dict:
        return {"sig": self.sig.hex(), "pubkey": self.pubkey.hex()}

    @classmethod
    def from_dict(cls, d: dict) -> WitnessItem:
        return cls(sig=bytes.fromhex(d["sig"]), pubkey=bytes.fromhex(d["pubkey"]))


@dataclass
class Tx:
    version: int
    inputs: list[TxIn]
    outputs: list[TxOut]
    witnesses: list[WitnessItem] = field(default_factory=list)
    locktime: int = 0

    @property
    def is_coinbase(self) -> bool:
        return len(self.inputs) == 1 and self.inputs[0].prev_txid == ("00" * 32) and self.inputs[0].prev_vout == 0xFFFFFFFF

    def txid(self) -> str:
        """Witness-segregated txid: signatures do NOT alter txid."""
        return sha256d(encode_tx(self, include_witness=False))[::-1].hex()

    def wtxid(self) -> str:
        return sha256d(encode_tx(self, include_witness=True))[::-1].hex()

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "inputs": [i.to_dict() for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs],
            "witnesses": [w.to_dict() for w in self.witnesses],
            "locktime": self.locktime,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Tx:
        return cls(
            version=int(d["version"]),
            inputs=[TxIn.from_dict(x) for x in d["inputs"]],
            outputs=[TxOut.from_dict(x) for x in d["outputs"]],
            witnesses=[WitnessItem.from_dict(x) for x in d.get("witnesses", [])],
            locktime=int(d.get("locktime", 0)),
        )


def encode_tx(tx: Tx, include_witness: bool = False) -> bytes:
    """A1: Canonical binary serialisation."""
    buf = bytearray()
    buf += struct.pack("<I", tx.version)
    if include_witness:
        buf += b"\x00\x01"
    buf += struct.pack("<H", len(tx.inputs))
    for txin in tx.inputs:
        raw_prev = bytes.fromhex(txin.prev_txid)
        if len(raw_prev) != 32:
            raise ValueError("prev_txid must be 32 bytes")
        buf += raw_prev[::-1]
        buf += struct.pack("<I", txin.prev_vout)
    buf += struct.pack("<H", len(tx.outputs))
    for txout in tx.outputs:
        if txout.amount < 0:
            raise ValueError("Negative output amount")
        if len(txout.pubkey_hash) != 20:
            raise ValueError("pubkey_hash must be 20 bytes")
        buf += struct.pack("<Q", txout.amount)
        buf += txout.pubkey_hash
    if include_witness:
        buf += struct.pack("<H", len(tx.witnesses))
        for w in tx.witnesses:
            buf += struct.pack("<B", len(w.sig)) + w.sig
            buf += struct.pack("<B", len(w.pubkey)) + w.pubkey
    buf += struct.pack("<I", tx.locktime)
    return bytes(buf)


def decode_tx(raw: bytes) -> Tx:
    """A1: Canonical binary deserialisation."""
    pos = 0
    if len(raw) < 12:
        raise ValueError("Transaction too short")
    (version,) = struct.unpack_from("<I", raw, pos)
    pos += 4
    has_witness = False
    if raw[pos : pos + 2] == b"\x00\x01":
        has_witness = True
        pos += 2
    (n_in,) = struct.unpack_from("<H", raw, pos)
    pos += 2
    inputs: list[TxIn] = []
    for _ in range(n_in):
        if pos + 36 > len(raw):
            raise ValueError("Truncated input")
        prev_txid = raw[pos : pos + 32][::-1].hex()
        pos += 32
        (prev_vout,) = struct.unpack_from("<I", raw, pos)
        pos += 4
        inputs.append(TxIn(prev_txid=prev_txid, prev_vout=prev_vout))
    if pos + 2 > len(raw):
        raise ValueError("Truncated output count")
    (n_out,) = struct.unpack_from("<H", raw, pos)
    pos += 2
    outputs: list[TxOut] = []
    for _ in range(n_out):
        if pos + 28 > len(raw):
            raise ValueError("Truncated output")
        (amount,) = struct.unpack_from("<Q", raw, pos)
        pos += 8
        pkh = raw[pos : pos + 20]
        pos += 20
        outputs.append(TxOut(amount=amount, pubkey_hash=pkh))
    witnesses: list[WitnessItem] = []
    if has_witness:
        if pos + 2 > len(raw):
            raise ValueError("Truncated witness count")
        (n_wit,) = struct.unpack_from("<H", raw, pos)
        pos += 2
        for _ in range(n_wit):
            if pos >= len(raw):
                raise ValueError("Truncated witness sig len")
            sig_len = raw[pos]
            pos += 1
            sig = raw[pos : pos + sig_len]
            pos += sig_len
            if pos >= len(raw):
                raise ValueError("Truncated witness pubkey len")
            pk_len = raw[pos]
            pos += 1
            pk = raw[pos : pos + pk_len]
            pos += pk_len
            witnesses.append(WitnessItem(sig=sig, pubkey=pk))
    if pos + 4 != len(raw):
        raise ValueError("Trailing or missing locktime bytes")
    (locktime,) = struct.unpack_from("<I", raw, pos)
    return Tx(version=version, inputs=inputs, outputs=outputs, witnesses=witnesses, locktime=locktime)


def sighash(tx: Tx, input_index: int, spent_amounts: list[int]) -> bytes:
    """A2: Amount-committing BIP-143-inspired sighash digest."""
    if not (0 <= input_index < len(tx.inputs)):
        raise IndexError("input_index out of range")
    if len(spent_amounts) != len(tx.inputs):
        raise ValueError("spent_amounts must match number of inputs")
    prevouts_bytes = b"".join(
        bytes.fromhex(i.prev_txid)[::-1] + struct.pack("<I", i.prev_vout) for i in tx.inputs
    )
    amounts_bytes = b"".join(struct.pack("<Q", a) for a in spent_amounts)
    outputs_bytes = b"".join(
        struct.pack("<Q", o.amount) + o.pubkey_hash for o in tx.outputs
    )
    preimage = (
        struct.pack("<I", tx.version)
        + sha256d(prevouts_bytes)
        + sha256d(amounts_bytes)
        + struct.pack("<I", input_index)
        + struct.pack("<Q", spent_amounts[input_index])
        + sha256d(outputs_bytes)
        + struct.pack("<I", tx.locktime)
    )
    return sha256d(preimage)


def sign_tx(tx: Tx, privkeys: list[int], spent_amounts: list[int]) -> Tx:
    """A2: Sign every input of a transaction with RFC 6979 low-s ECDSA."""
    if len(privkeys) != len(tx.inputs):
        raise ValueError("privkeys length must match inputs")
    witnesses: list[WitnessItem] = []
    for idx, sk in enumerate(privkeys):
        z = sighash(tx, idx, spent_amounts)
        sig = ecdsa_sign(sk, z)
        pk = privkey_to_pubkey(sk)
        witnesses.append(WitnessItem(sig=sig, pubkey=pk))
    return Tx(
        version=tx.version,
        inputs=list(tx.inputs),
        outputs=list(tx.outputs),
        witnesses=witnesses,
        locktime=tx.locktime,
    )


def verify_tx_signatures(tx: Tx, spent_amounts: list[int], expected_pkhs: list[bytes]) -> bool:
    """Verify witness count, pubkey hash commitment, and low-s ECDSA signature for all inputs."""
    if len(tx.witnesses) != len(tx.inputs) or len(expected_pkhs) != len(tx.inputs):
        return False
    for idx, wit in enumerate(tx.witnesses):
        if hash160(wit.pubkey) != expected_pkhs[idx]:
            return False
        z = sighash(tx, idx, spent_amounts)
        if not ecdsa_verify(wit.pubkey, z, wit.sig, enforce_low_s=True):
            return False
    return True


class Wallet:
    """A3: UTXO wallet with coin selection, explicit change output, and fee-as-remainder."""

    def __init__(self, privkey: int, name: str = "wallet") -> None:
        self.privkey = privkey
        self.pubkey = privkey_to_pubkey(privkey)
        self.pubkey_hash = hash160(self.pubkey)
        self.name = name

    def create_payment(
        self,
        utxos: list[tuple[str, int, int]],  # (txid, vout, amount)
        recipient_pkh: bytes,
        amount: int,
        fee: int,
        include_change: bool = True,
    ) -> Tx:
        if amount <= 0 or fee < 0:
            raise ValueError("Invalid payment amount or fee")
        selected: list[tuple[str, int, int]] = []
        total_in = 0
        for u in sorted(utxos, key=lambda x: x[2]):
            selected.append(u)
            total_in += u[2]
            if total_in >= amount + fee:
                break
        if total_in < amount + fee:
            raise ValueError(f"Insufficient funds: have {total_in}, need {amount + fee}")
        outputs = [TxOut(amount=amount, pubkey_hash=recipient_pkh)]
        change = total_in - amount - fee
        if include_change and change > 0:
            outputs.append(TxOut(amount=change, pubkey_hash=self.pubkey_hash))
        unsigned = Tx(
            version=1,
            inputs=[TxIn(prev_txid=u[0], prev_vout=u[1]) for u in selected],
            outputs=outputs,
        )
        return sign_tx(
            unsigned,
            privkeys=[self.privkey] * len(selected),
            spent_amounts=[u[2] for u in selected],
        )
