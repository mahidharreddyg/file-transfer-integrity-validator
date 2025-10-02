import unittest, os, json
from src import chain_logger

class ChainTests(unittest.TestCase):
    def setUp(self):
        os.makedirs("logs", exist_ok=True)
        if os.path.exists("logs/chain.log"):
            os.remove("logs/chain.log")

    def test_append_and_verify(self):
        chain_logger.append_event("INFO", "event1")
        chain_logger.append_event("INFO", "event2")
        self.assertTrue(chain_logger.verify_chain())

        # Tamper with chain
        with open("logs/chain.log", "r") as f:
            lines = f.readlines()
        tampered = json.loads(lines[-1])
        tampered["msg"] = "tampered"
        lines[-1] = json.dumps(tampered) + "\n"
        with open("logs/chain.log", "w") as f:
            f.writelines(lines)
        self.assertFalse(chain_logger.verify_chain())
