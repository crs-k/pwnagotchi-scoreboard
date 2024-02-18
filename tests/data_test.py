import unittest
from unittest.mock import patch, mock_open
from scapy.all import Dot11Beacon, RadioTap, Dot11Elt
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, RadioTap
from datetime import datetime, timedelta


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
        result = self.data
        now = datetime.now()
        timestamp_str = self.data['test_name'].get('timestamp', now.strftime("%m/%d/%y @ %I:%M %p"))
        last_time = datetime.strptime(timestamp_str, "%m/%d/%y @ %I:%M %p")
        time_diff = now - last_time

        # Round the time difference
        if time_diff < timedelta(minutes=1):
            time_diff_str = "0 s"
        elif time_diff < timedelta(hours=1):
            minutes = round(time_diff.total_seconds() / 60)
            time_diff_str = f"{minutes} m"
        elif time_diff < timedelta(days=1):
            hours = round(time_diff.total_seconds() / 3600)
            time_diff_str = f"{hours} h"
        else:
            days = round(time_diff.total_seconds() / 86400)
            time_diff_str = f"{days} d"

        self.data['test_name']['last'] = time_diff_str

        self.assertEqual(result, self.data)

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