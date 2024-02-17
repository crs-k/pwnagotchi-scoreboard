import unittest
from src.functions.utils import rssi_to_human

class TestRssiToHuman(unittest.TestCase):
    def test_rssi_to_human(self):
        self.assertEqual(rssi_to_human(-49), "▁▃▄▅▆▇")
        self.assertEqual(rssi_to_human(-50), "▁▃▄▅▆▇")
        self.assertEqual(rssi_to_human(-59), "▁▃▄▅▆ ")
        self.assertEqual(rssi_to_human(-60), "▁▃▄▅▆ ")
        self.assertEqual(rssi_to_human(-69), "▁▃▄▅  ")
        self.assertEqual(rssi_to_human(-70), "▁▃▄▅  ")
        self.assertEqual(rssi_to_human(-79), "▁▃▄   ")
        self.assertEqual(rssi_to_human(-80), "▁▃▄   ")
        self.assertEqual(rssi_to_human(-81), "▁▃    ")

if __name__ == '__main__':
    unittest.main()