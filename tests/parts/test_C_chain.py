import unittest
from utxochain.a_tx import Wallet
from utxochain.c_chain import Blockchain, make_coinbase, mine_block, run_demo


class TestRoleCChain(unittest.TestCase):
    def test_C1_and_C2_pow_and_depth3_reorg_matches_genesis_replay(self):
        miner_a = Wallet(51)
        miner_b = Wallet(52)

        gen_cb = make_coinbase(0, miner_a.pubkey_hash, 5000)
        genesis = mine_block("00" * 32, 0, [gen_cb], timestamp=1000)
        chain = Blockchain(genesis, subsidy=5000, maturity=2)

        b1_a = mine_block(genesis.hash, 1, [make_coinbase(1, miner_a.pubkey_hash, 5000, 1)], timestamp=1010)
        chain.add_block(b1_a)
        b2_a = mine_block(b1_a.hash, 2, [make_coinbase(2, miner_a.pubkey_hash, 5000, 2)], timestamp=1020)
        chain.add_block(b2_a)
        self.assertEqual(chain.tip.block.hash, b2_a.hash)

        b1_b = mine_block(genesis.hash, 1, [make_coinbase(1, miner_b.pubkey_hash, 5000, 11)], timestamp=1015)
        b2_b = mine_block(b1_b.hash, 2, [make_coinbase(2, miner_b.pubkey_hash, 5000, 12)], timestamp=1025)
        b3_b = mine_block(b2_b.hash, 3, [make_coinbase(3, miner_b.pubkey_hash, 5000, 13)], timestamp=1035)
        chain.add_block(b1_b)
        chain.add_block(b2_b)
        self.assertEqual(chain.tip.block.hash, b2_a.hash)
        chain.add_block(b3_b)
        self.assertEqual(chain.tip.block.hash, b3_b.hash)

        replay = Blockchain(genesis, subsidy=5000, maturity=2)
        for b in (b1_b, b2_b, b3_b):
            replay.add_block(b)
        self.assertEqual(chain.utxo_set.state_hash(), replay.utxo_set.state_hash())

    def test_C3_demo_network_100_blocks(self):
        summary = run_demo()
        self.assertEqual(summary["final_height"], 100)
        self.assertGreater(summary["payments_sent"], 0)
