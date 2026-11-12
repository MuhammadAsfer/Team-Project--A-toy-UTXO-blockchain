import unittest
from utxochain.a_tx import Tx, TxIn, TxOut, Wallet, encode_tx, decode_tx, sign_tx, verify_tx_signatures
from utxochain.crypto import decode_der, N


class TestRoleATransactions(unittest.TestCase):
    def test_A1_canonical_encoding_and_witness_segregated_txid(self):
        w1 = Wallet(1)
        w2 = Wallet(2)
        tx1 = w1.create_payment([("aa" * 32, 0, 1000)], w2.pubkey_hash, amount=800, fee=50)
        tx2 = sign_tx(tx1, [3], [1000])
        self.assertEqual(tx1.txid(), tx2.txid())
        self.assertNotEqual(tx1.wtxid(), tx2.wtxid())

        raw_wit = encode_tx(tx1, include_witness=True)
        decoded = decode_tx(raw_wit)
        self.assertEqual(decoded.txid(), tx1.txid())
        self.assertEqual(decoded.witnesses, tx1.witnesses)

    def test_A2_sighash_commits_to_amounts_and_low_s(self):
        w1 = Wallet(7)
        w2 = Wallet(8)
        tx = w1.create_payment([("bb" * 32, 1, 5000)], w2.pubkey_hash, amount=4000, fee=100)
        self.assertTrue(verify_tx_signatures(tx, [5000], [w1.pubkey_hash]))
        self.assertFalse(verify_tx_signatures(tx, [4999], [w1.pubkey_hash]))
        r, s = decode_der(tx.witnesses[0].sig)
        self.assertTrue(1 <= s <= N // 2)

    def test_A3_wallet_change_and_forgotten_change_demo(self):
        alice = Wallet(11)
        bob = Wallet(12)
        tx_normal = alice.create_payment([("cc" * 32, 0, 50)], bob.pubkey_hash, amount=10, fee=1, include_change=True)
        self.assertEqual(len(tx_normal.outputs), 2)
        self.assertEqual(tx_normal.outputs[0].amount, 10)
        self.assertEqual(tx_normal.outputs[1].amount, 39)

        tx_no_change = alice.create_payment([("cc" * 32, 0, 50)], bob.pubkey_hash, amount=10, fee=1, include_change=False)
        self.assertEqual(len(tx_no_change.outputs), 1)
        self.assertEqual(50 - sum(o.amount for o in tx_no_change.outputs), 40)
