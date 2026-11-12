"""Role C (Kanan Huseynov): Proof-of-Work chain, heaviest-work fork choice, deep reorgs with undo, and gossip network."""
from __future__ import annotations
from dataclasses import dataclass
import json
import struct
import random
from .crypto import sha256d
from .a_tx import Tx, TxIn, TxOut, Wallet
from .b_utxo import OutPoint, UTXOSet, UndoBlock, apply_block, undo_block, validate_transaction, ConsensusError

DEFAULT_TARGET = (1 << 252) - 1  # Fast deterministic PoW (~16 hashes per block)
MAX_TARGET = (1 << 256) - 1


def compute_merkle_root(txids: list[str]) -> str:
    if not txids:
        return "00" * 32
    layer = [bytes.fromhex(t)[::-1] for t in txids]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(sha256d(layer[i] + layer[i + 1]))
        layer = next_layer
    return layer[0][::-1].hex()


@dataclass(frozen=True)
class BlockHeader:
    version: int
    prev_hash: str
    merkle_root: str
    timestamp: int
    target: int
    nonce: int

    def serialise(self) -> bytes:
        return (
            struct.pack("<I", self.version)
            + bytes.fromhex(self.prev_hash)[::-1]
            + bytes.fromhex(self.merkle_root)[::-1]
            + struct.pack("<I", self.timestamp)
            + self.target.to_bytes(32, "big")
            + struct.pack("<I", self.nonce)
        )

    def block_hash(self) -> str:
        return sha256d(self.serialise())[::-1].hex()

    def hash_int(self) -> int:
        return int.from_bytes(sha256d(self.serialise())[::-1], "big")

    def work(self) -> int:
        return MAX_TARGET // (self.target + 1)


@dataclass
class Block:
    header: BlockHeader
    txs: list[Tx]

    @property
    def hash(self) -> str:
        return self.header.block_hash()


@dataclass
class ChainNode:
    block: Block
    height: int
    cum_work: int


def make_coinbase(height: int, miner_pkh: bytes, reward: int, extra_nonce: int = 0) -> Tx:
    return Tx(
        version=1,
        inputs=[TxIn(prev_txid="00" * 32, prev_vout=0xFFFFFFFF)],
        outputs=[TxOut(amount=reward, pubkey_hash=miner_pkh)],
        locktime=(height << 8) | (extra_nonce & 0xFF),
    )


def mine_block(
    prev_hash: str,
    height: int,
    txs: list[Tx],
    timestamp: int,
    target: int = DEFAULT_TARGET,
    start_nonce: int = 0,
) -> Block:
    """C1: Proof-of-Work nonce search."""
    mroot = compute_merkle_root([t.txid() for t in txs])
    nonce = start_nonce
    while True:
        hdr = BlockHeader(
            version=1,
            prev_hash=prev_hash,
            merkle_root=mroot,
            timestamp=timestamp,
            target=target,
            nonce=nonce,
        )
        if hdr.hash_int() <= target:
            return Block(header=hdr, txs=txs)
        nonce += 1


class Blockchain:
    """C1 + C2: Block tree with heaviest-work fork choice and atomic UTXO reorgs via UndoBlock."""

    def __init__(self, genesis_block: Block, subsidy: int = 5000, maturity: int = 10) -> None:
        self.subsidy = subsidy
        self.maturity = maturity
        self.blocks: dict[str, ChainNode] = {}
        self.active_chain: list[str] = []
        self.undo_stack: dict[str, UndoBlock] = {}
        self.utxo_set = UTXOSet()
        self.mempool: dict[str, Tx] = {}

        if genesis_block.header.hash_int() > genesis_block.header.target:
            raise ConsensusError("Genesis block fails PoW")
        if compute_merkle_root([t.txid() for t in genesis_block.txs]) != genesis_block.header.merkle_root:
            raise ConsensusError("Genesis Merkle root mismatch")

        undo = apply_block(self.utxo_set, genesis_block.txs, height=0, subsidy=self.subsidy, maturity=self.maturity)
        ghash = genesis_block.hash
        self.blocks[ghash] = ChainNode(block=genesis_block, height=0, cum_work=genesis_block.header.work())
        self.undo_stack[ghash] = undo
        self.active_chain = [ghash]

    @property
    def tip(self) -> ChainNode:
        return self.blocks[self.active_chain[-1]]

    def submit_tx(self, tx: Tx) -> bool:
        tid = tx.txid()
        if tid in self.mempool:
            return False
        validate_transaction(tx, self.utxo_set, current_height=self.tip.height + 1, maturity=self.maturity)
        self.mempool[tid] = tx
        return True

    def add_block(self, block: Block) -> bool:
        bhash = block.hash
        if bhash in self.blocks:
            return False
        prev_hash = block.header.prev_hash
        if prev_hash not in self.blocks:
            raise ConsensusError(f"Unknown parent block {prev_hash}")
        if block.header.hash_int() > block.header.target:
            raise ConsensusError("Block hash exceeds target (PoW failure)")
        expected_root = compute_merkle_root([t.txid() for t in block.txs])
        if expected_root != block.header.merkle_root:
            raise ConsensusError("Block Merkle root mismatch")

        parent_node = self.blocks[prev_hash]
        new_height = parent_node.height + 1
        new_work = parent_node.cum_work + block.header.work()
        new_node = ChainNode(block=block, height=new_height, cum_work=new_work)

        if prev_hash == self.active_chain[-1]:
            undo = apply_block(self.utxo_set, block.txs, height=new_height, subsidy=self.subsidy, maturity=self.maturity)
            self.blocks[bhash] = new_node
            self.undo_stack[bhash] = undo
            self.active_chain.append(bhash)
            for tx in block.txs[1:]:
                self.mempool.pop(tx.txid(), None)
            return True

        self.blocks[bhash] = new_node

        if new_work > self.tip.cum_work:
            self._reorg_to(bhash)
            return True
        return False

    def _reorg_to(self, new_tip_hash: str) -> None:
        """C2: Roll back old branch via undo_block, validate & apply new branch, restore valid mempool txs."""
        new_path: list[str] = []
        curr = new_tip_hash
        active_set = set(self.active_chain)
        while curr not in active_set:
            new_path.append(curr)
            curr = self.blocks[curr].block.header.prev_hash
        fork_hash = curr
        new_path.reverse()

        fork_idx = self.active_chain.index(fork_hash)
        disconnected_hashes = self.active_chain[fork_idx + 1 :]

        backup_utxo = self.utxo_set.clone()
        backup_chain = list(self.active_chain)
        orphaned_txs: list[Tx] = []

        try:
            for h in reversed(disconnected_hashes):
                undo_block(self.utxo_set, self.undo_stack[h])
                for tx in self.blocks[h].block.txs[1:]:
                    orphaned_txs.append(tx)

            self.active_chain = self.active_chain[: fork_idx + 1]

            for h in new_path:
                node = self.blocks[h]
                undo = apply_block(
                    self.utxo_set,
                    node.block.txs,
                    height=node.height,
                    subsidy=self.subsidy,
                    maturity=self.maturity,
                )
                self.undo_stack[h] = undo
                self.active_chain.append(h)
                for tx in node.block.txs[1:]:
                    self.mempool.pop(tx.txid(), None)

            for tx in orphaned_txs:
                tid = tx.txid()
                if tid not in self.mempool:
                    try:
                        validate_transaction(tx, self.utxo_set, current_height=self.tip.height + 1, maturity=self.maturity)
                        self.mempool[tid] = tx
                    except ConsensusError:
                        pass
        except ConsensusError:
            self.utxo_set = backup_utxo
            self.active_chain = backup_chain
            raise


class GossipNetwork:
    """C3: Multi-node gossip network supporting network partitions and healing."""

    def __init__(self, genesis: Block, num_nodes: int = 3, subsidy: int = 5000, maturity: int = 10) -> None:
        self.nodes: list[Blockchain] = [
            Blockchain(genesis, subsidy=subsidy, maturity=maturity) for _ in range(num_nodes)
        ]
        self.partitions: list[set[int]] = [set(range(num_nodes))]

    def partition(self, groups: list[set[int]]) -> None:
        self.partitions = groups

    def heal(self) -> None:
        all_ids = set(range(len(self.nodes)))
        self.partitions = [all_ids]
        all_blocks: dict[str, ChainNode] = {}
        for node in self.nodes:
            for h, cn in node.blocks.items():
                all_blocks[h] = cn
        ordered = sorted(all_blocks.values(), key=lambda cn: cn.height)
        for cn in ordered:
            if cn.height == 0:
                continue
            for node in self.nodes:
                try:
                    node.add_block(cn.block)
                except ConsensusError:
                    pass

    def _peers_of(self, node_id: int) -> set[int]:
        for grp in self.partitions:
            if node_id in grp:
                return grp
        return {node_id}

    def broadcast_tx(self, origin_id: int, tx: Tx) -> None:
        for pid in self._peers_of(origin_id):
            try:
                self.nodes[pid].submit_tx(tx)
            except ConsensusError:
                pass

    def broadcast_block(self, origin_id: int, block: Block) -> None:
        for pid in self._peers_of(origin_id):
            try:
                self.nodes[pid].add_block(block)
            except ConsensusError:
                pass


def run_demo() -> dict:
    """C3: 100-block demo with 3 miners, 2 wallets, payments, partition and heal."""
    rng = random.Random(42)
    miners = [Wallet(100 + i, name=f"Miner-{i}") for i in range(3)]
    alice = Wallet(201, name="Alice")
    bob = Wallet(202, name="Bob")

    genesis_cb = make_coinbase(0, miners[0].pubkey_hash, 5000, extra_nonce=0)
    genesis = mine_block("00" * 32, 0, [genesis_cb], timestamp=1700000000)

    net = GossipNetwork(genesis, num_nodes=3, subsidy=5000, maturity=10)
    tx_count = 0
    step = 0

    while net.nodes[0].tip.height < 100:
        step += 1
        if step == 60:
            net.partition([{0, 1}, {2}])
        elif step == 65:
            net.heal()

        miner_idx = step % 3
        node = net.nodes[miner_idx]
        next_h = node.tip.height + 1

        if step > 12 and step % 4 == 0:
            m_utxos = node.utxo_set.utxos_for(miners[miner_idx].pubkey_hash, current_height=next_h, maturity=10)
            if m_utxos:
                try:
                    tx = miners[miner_idx].create_payment(m_utxos[:1], alice.pubkey_hash, amount=1000, fee=50)
                    net.broadcast_tx(miner_idx, tx)
                    tx_count += 1
                except Exception:
                    pass

        if step > 20 and step % 7 == 0:
            a_utxos = node.utxo_set.utxos_for(alice.pubkey_hash, current_height=next_h, maturity=10)
            if a_utxos:
                try:
                    tx = alice.create_payment(a_utxos[:1], bob.pubkey_hash, amount=400, fee=25)
                    net.broadcast_tx(miner_idx, tx)
                    tx_count += 1
                except Exception:
                    pass

        pending = list(node.mempool.values())
        fees = 0
        valid_txs: list[Tx] = []
        spent_seen = set()
        for ptx in pending:
            try:
                f = validate_transaction(ptx, node.utxo_set, current_height=next_h, maturity=10, already_spent_in_block=spent_seen)
                fees += f
                valid_txs.append(ptx)
                for ti in ptx.inputs:
                    spent_seen.add(OutPoint(ti.prev_txid, ti.prev_vout))
            except ConsensusError:
                pass

        cb = make_coinbase(next_h, miners[miner_idx].pubkey_hash, 5000 + fees, extra_nonce=miner_idx)
        blk = mine_block(
            node.tip.block.hash,
            next_h,
            [cb] + valid_txs,
            timestamp=1700000000 + step * 10,
            start_nonce=rng.randint(0, 1000),
        )
        net.broadcast_block(miner_idx, blk)

    net.heal()
    hashes = [n.utxo_set.state_hash() for n in net.nodes]
    assert len(set(hashes)) == 1, "Nodes diverged after heal!"
    return {
        "final_height": net.nodes[0].tip.height,
        "tip_hash": net.nodes[0].tip.block.hash,
        "utxo_state_hash": hashes[0],
        "payments_sent": tx_count,
        "alice_balance": net.nodes[0].utxo_set.balance_of(alice.pubkey_hash),
        "bob_balance": net.nodes[0].utxo_set.balance_of(bob.pubkey_hash),
    }


if __name__ == "__main__":
    res = run_demo()
    print("Demo completed successfully:", json.dumps(res, indent=2))
