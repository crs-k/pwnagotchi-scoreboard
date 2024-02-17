[![CI](https://github.com/crs-k/pwnagotchi-scoreboard/actions/workflows/ci.yml/badge.svg)](https://github.com/crs-k/pwnagotchi-scoreboard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/crs-k/pwnagotchi-scoreboard/actions/workflows/codeql.yml/badge.svg)](https://github.com/crs-k/pwnagotchi-scoreboard/actions/workflows/codeql.yml)
# Pwnagotchi Scoreboard

Creates a scoreboard of Pwnagotchis in range of the WiFi interface running in monitor mode.

## Usage

This project is a Python script that listens for beacon frames from a specific MAC address (`de:ad:be:ef:de:ad`) on a wireless interface (`wlan1` by default). When a beacon frame is received, it's processed, saved, and displayed on a 3.5 inch Waveshare e-Paper display.

To run the script, use the following command:

```bash
pip install -r requirements.txt
python3 main.py
```

## License

This project is licensed under the MIT License.
