# Pwnagotchi Scoreboard

Creates a scoreboard of Pwnagotchis in range of the WiFi interface running in monitor mode.

## Usage

This project is a Python script that listens for beacon frames from a specific MAC address (`de:ad:be:ef:de:ad`) on a wireless interface (`wlan1` by default). When a beacon frame is received, it's processed, saved, and displayed on a 3.5 inch Waveshare e-Paper display.

To run the script, use the following command:

```bash
python3 main.py
```

## How it works

The script starts by setting the wireless interface to monitor mode and loading any previously saved data. It then starts a thread to hop between wireless channels.

The script uses the Scapy library to sniff for beacon frames from the specified MAC address. When a beacon frame is received, it's passed to the `PacketHandler` function.

The `PacketHandler` function processes the packet, saves the updated data, and updates the display. If an error occurs while updating the display, it's logged and the script continues running. If a KeyboardInterrupt (Ctrl+C) is detected, the script cleans up and exits.

## License

This project is licensed under the MIT License.