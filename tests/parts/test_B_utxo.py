import unittest
from utxochain.a_tx import Tx, TxIn, TxOut, Wallet
from utxochain.b_utxo import OutPoint, UTXO, UTXOSet, ConsensusError, validate_transaction, apply_block, undo_block
from utxochain.c_chain import make_coinbase


class TestRoleBUTXO(unittest.TestCase):
    def test_B1_utxo_validation_rules(self):
        alice = Wallet(21)
        bob = Wallet(22)
        op = OutPoint("11" * 32, 0)
        uset = UTXOSet({op: UTXO(amount=1000, pubkey_hash=alice.pubkey_hash, height=0, is_coinbase=False)})

        tx = alice.create_payment([("11" * 32, 0, 1000)], bob.pubkey_hash, amount=900, fee=100)
        self.assertEqual(validate_transaction(tx, uset, current_height=1), 100)

        bad_over = Tx(1, [TxIn("11" * 32, 0)], [TxOut(1001, bob.pubkey_hash)], witnesses=tx.witnesses)
        with self.assertRaises(ConsensusError):
            validate_transaction(bad_over, uset, current_height=1)

        dup_in = Tx(1, [TxIn("11" * 32, 0), TxIn("11" * 32, 0)], [TxOut(500, bob.pubkey_hash)], witnesses=tx.witnesses * 2)
        with self.assertRaises(ConsensusError):
            validate_transaction(dup_in, uset, current_height=1)

    def test_B2_coinbase_reward_and_maturity(self):
        miner = Wallet(31)
        bob = Wallet(32)
        uset = UTXOSet()
        cb0 = make_coinbase(0, miner.pubkey_hash, 5000)
        apply_block(uset, [cb0], height=0, subsidy=5000, maturity=10)

        spend = miner.create_payment([(cb0.txid(), 0, 5000)], bob.pubkey_hash, amount=4900, fee=100)
        with self.assertRaises(ConsensusError):
            validate_transaction(spend, uset, current_height=9, maturity=10)
        self.assertEqual(validate_transaction(spend, uset, current_height=10, maturity=10), 100)

        greedy_cb = make_coinbase(1, miner.pubkey_hash, 5001)
        with self.assertRaises(ConsensusError):
            apply_block(uset, [greedy_cb], height=1, subsidy=5000, maturity=10)

    def test_B3_apply_and_undo_identity_over_100_blocks(self):
        wallets = [Wallet(40 + i) for i in range(4)]
        uset = UTXOSet()
        undos = []
        hashes = [uset.state_hash()]

        for h in range(100):
            w = wallets[h % 4]
            txs = []
            if h >= 12:
                avail = uset.utxos_for(w.pubkey_hash, current_height=h, maturity=10)
                if avail:
                    chosen = avail[0]
                    rcpt = wallets[(h + 1) % 4]
                    txs.append(w.create_payment([chosen], rcpt.pubkey_hash, amount=chosen[2] - 10, fee=10))
            cb = make_coinbase(h, w.pubkey_hash, 5000 + 10 * len(txs), extra_nonce=h)
            u = apply_block(uset, [cb] + txs, height=h, subsidy=5000, maturity=10)
            undos.append(u)
            hashes.append(uset.state_hash())

        for h in reversed(range(100)):
            undo_block(uset, undos[h])
            self.assertEqual(uset.state_hash(), hashes[h])
