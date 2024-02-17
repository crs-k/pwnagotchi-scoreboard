import subprocess
import time
import logging


def channel_hopper(interface, loop_count=float('inf')):
    count = 0
    while count != loop_count:
        for channel in range(1, 14):  # 2.4GHz channels
            subprocess.run(["sudo", "iwconfig", interface, "channel", str(channel)])
            time.sleep(0.5)
        for channel in range(36, 165, 4):  # 5GHz channels
            subprocess.run(["sudo", "iwconfig", interface, "channel", str(channel)])
            time.sleep(0.5)
        count += 1


def start_monitor_mode(interface):
    command = ["sudo", "airmon-ng", "start", interface]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        logging.error(
            f"Failed to start monitor mode on {interface}: {stderr.decode().strip()}"
        )
        return False

    logging.info(f"Started monitor mode on {interface}: {stdout.decode().strip()}")
    return True
