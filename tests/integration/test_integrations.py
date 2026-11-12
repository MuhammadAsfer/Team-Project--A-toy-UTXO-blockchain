import unittest
from utxochain.a_tx import Wallet
from utxochain.b_utxo import OutPoint, UTXO, UTXOSet, ConsensusError, validate_transaction, apply_block
from utxochain.c_chain import Blockchain, GossipNetwork, make_coinbase, mine_block


class TestIntegrations(unittest.TestCase):
    def test_I1_first_valid_spend(self):
        """I1 (Leader: Muhammad Asfer Anwer | Reviewer: Aizhan Khalikova): A2 signing meets B1 validation."""
        alice = Wallet(61)
        bob = Wallet(62)
        op = OutPoint("aa" * 32, 0)
        uset = UTXOSet({op: UTXO(1000, alice.pubkey_hash, height=0, is_coinbase=False)})
        tx = alice.create_payment([("aa" * 32, 0, 1000)], bob.pubkey_hash, amount=700, fee=30)
        self.assertEqual(validate_transaction(tx, uset, current_height=1), 30)

    def test_I2_wallet_meets_coinbase_rules(self):
        """I2 (Leader: Aizhan Khalikova | Reviewer: Muhammad Asfer Anwer): A3 wallet + B2 coinbase maturity & change."""
        miner = Wallet(71)
        bob = Wallet(72)
        uset = UTXOSet()
        cb = make_coinbase(0, miner.pubkey_hash, 5000)
        apply_block(uset, [cb], height=0, subsidy=5000, maturity=5)

        tx = miner.create_payment([(cb.txid(), 0, 5000)], bob.pubkey_hash, amount=1500, fee=50)
        with self.assertRaises(ConsensusError):
            validate_transaction(tx, uset, current_height=4, maturity=5)
        self.assertEqual(validate_transaction(tx, uset, current_height=5, maturity=5), 50)

    def test_I3_blocks_carry_transactions(self):
        """I3 (Leader: Kanan Huseynov | Reviewer: Aizhan Khalikova): B3 apply/undo + C1 PoW blocks."""
        miner = Wallet(81)
        bob = Wallet(82)
        gen_cb = make_coinbase(0, miner.pubkey_hash, 5000)
        genesis = mine_block("00" * 32, 0, [gen_cb], timestamp=2000)
        chain = Blockchain(genesis, subsidy=5000, maturity=1)

        tx = miner.create_payment([(gen_cb.txid(), 0, 5000)], bob.pubkey_hash, amount=2000, fee=100)
        cb1 = make_coinbase(1, miner.pubkey_hash, 5100)
        b1 = mine_block(genesis.hash, 1, [cb1, tx], timestamp=2010)
        chain.add_block(b1)

        self.assertEqual(chain.utxo_set.balance_of(bob.pubkey_hash), 2000)
        self.assertEqual(chain.utxo_set.balance_of(miner.pubkey_hash), 2900 + 5100)

    def test_I4_reorg_drops_conflicting_orphaned_tx(self):
        """I4 (Leader: Muhammad Asfer Anwer | Reviewer: Kanan Huseynov): C2 reorg + B3 undo invalidates double-spent tx."""
        miner = Wallet(91)
        bob = Wallet(92)
        charlie = Wallet(93)

        gen_cb = make_coinbase(0, miner.pubkey_hash, 5000)
        genesis = mine_block("00" * 32, 0, [gen_cb], timestamp=3000)
        net = GossipNetwork(genesis, num_nodes=2, subsidy=5000, maturity=1)

        net.partition([{0}, {1}])

        tx_to_bob = miner.create_payment([(gen_cb.txid(), 0, 5000)], bob.pubkey_hash, amount=4000, fee=100)
        b1_0 = mine_block(genesis.hash, 1, [make_coinbase(1, miner.pubkey_hash, 5100, 1), tx_to_bob], timestamp=3010)
        net.broadcast_block(0, b1_0)

        tx_to_charlie = miner.create_payment([(gen_cb.txid(), 0, 5000)], charlie.pubkey_hash, amount=4500, fee=100)
        b1_1 = mine_block(genesis.hash, 1, [make_coinbase(1, miner.pubkey_hash, 5100, 2), tx_to_charlie], timestamp=3015)
        net.broadcast_block(1, b1_1)
        b2_1 = mine_block(b1_1.hash, 2, [make_coinbase(2, miner.pubkey_hash, 5000, 3)], timestamp=3025)
        net.broadcast_block(1, b2_1)

        net.heal()
        self.assertEqual(net.nodes[0].utxo_set.state_hash(), net.nodes[1].utxo_set.state_hash())
        self.assertEqual(net.nodes[0].utxo_set.balance_of(charlie.pubkey_hash), 4500)
        self.assertEqual(net.nodes[0].utxo_set.balance_of(bob.pubkey_hash), 0)
        self.assertNotIn(tx_to_bob.txid(), net.nodes[0].mempool)
