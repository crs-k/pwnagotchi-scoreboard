import unittest
from unittest.mock import patch, MagicMock
from src.functions.network import channel_hopper, start_monitor_mode

class TestNetwork(unittest.TestCase):
    @patch('src.functions.network.subprocess.run')
    @patch('src.functions.network.time.sleep')
    def test_channel_hopper(self, mock_sleep, mock_run):
        # Arrange
        interface = "test_interface"
        loop_count = 1

        # Act
        channel_hopper(interface, loop_count)

        # Assert
        self.assertEqual(mock_run.call_count, 46)  # 13 channels for 2.4GHz and 13 channels for 5GHz
        self.assertEqual(mock_sleep.call_count, 46)

    @patch('src.functions.network.subprocess.Popen')
    @patch('src.functions.network.logging')
    def test_start_monitor_mode(self, mock_logging, mock_popen):
        # Arrange
        interface = "test_interface"
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = (b"stdout", b"stderr")
        mock_popen.return_value = mock_process

        # Act
        result = start_monitor_mode(interface)

        # Assert
        self.assertTrue(result)
        mock_logging.info.assert_called()

if __name__ == '__main__':
    unittest.main()