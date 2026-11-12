import unittest
import json
from pathlib import Path
from utxochain.c_chain import run_demo


class TestAcceptance(unittest.TestCase):
    def test_acceptance_end_to_end_and_fixtures(self):
        fixtures_dir = Path(__file__).resolve().parents[2] / "fixtures"
        tx_vec = json.loads((fixtures_dir / "tx_vectors.json").read_text())
        self.assertEqual(len(tx_vec["txid"]), 64)

        summary = run_demo()
        self.assertEqual(summary["final_height"], 100)
        self.assertEqual(len(summary["utxo_state_hash"]), 64)
