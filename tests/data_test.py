import json
import unittest
from unittest.mock import patch, mock_open
from scapy.all import Dot11Beacon, RadioTap, Dot11Elt
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, RadioTap
from scapy.packet import Packet
from unittest.mock import call

class TestDataFunctions(unittest.TestCase):
    def setUp(self):
        self.data = {
            "test_name": {
                "face": "test_face",
                "name": "test_name",
                "pwnd_run": 1,
                "last": "?",
                "timestamp": "01/01/21 @ 12:00 AM",
                "rssi": -90,
            }
        }

    def test_save_data(self):
        from src.functions import data  # Move the import here
        with patch("builtins.open", mock_open()) as mocked_open:
            data.save_data(self.data)
            mocked_open.assert_called_once_with("data.json", "w")
            mocked_open().write.assert_called()

    def test_load_data(self):
        from src.functions import data  # Move the import here
        with patch("builtins.open", mock_open(read_data=json.dumps(self.data))) as mocked_open:
            result = data.load_data()
            self.assertEqual(result, self.data)
            mocked_open.assert_called_once_with("data.json", "r")

        with patch("builtins.open", mock_open()) as mocked_open:
            mocked_open.side_effect = FileNotFoundError
            result = data.load_data()
            self.assertEqual(result, {})

    def test_handle_packet(self):
        from src.functions import data  # Move the import here
        packet = RadioTap(dBm_AntSignal=-90)/Dot11Beacon()/Dot11Elt(ID=222, info=b'{"face":"test_face","name":"test_name","pwnd_run":1}')

        result = data.handle_packet(packet, self.data)
        self.assertIn("test_name", result)
        self.assertEqual(result["test_name"]["face"], "test_face")
        self.assertEqual(result["test_name"]["name"], "test_name")
        self.assertEqual(result["test_name"]["pwnd_run"], 1)

        packet = RadioTap(dBm_AntSignal=-90)/Dot11Beacon()/Dot11Elt(ID=222, info=b'{"face":"new_face","name":"new_name","pwnd_run":2}')

        result = data.handle_packet(packet, self.data)
        self.assertIn("new_name", result)
        self.assertEqual(result["new_name"]["face"], "new_face")
        self.assertEqual(result["new_name"]["name"], "new_name")
        self.assertEqual(result["new_name"]["pwnd_run"], 2)

if __name__ == "__main__":
    unittest.main()