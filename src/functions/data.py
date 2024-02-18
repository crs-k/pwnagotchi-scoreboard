import json
from scapy.all import Dot11Beacon, RadioTap, Dot11Elt
import re
from datetime import datetime, timedelta
import logging


def save_data(data):
    with open("data.json", "w") as f:
        json.dump(data, f)


def load_data():
    try:
        with open("data.json", "r") as f:
            data = json.load(f)
            now = datetime.now()
            for key, value in data.items():
                timestamp_str = value.get("timestamp", now.strftime("%m/%d/%y @ %I:%M %p"))
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

                value["last"] = time_diff_str
            return data
    except FileNotFoundError:
        return {}


def handle_packet(packet, data):
    # Iterate over the IEs in the beacon frame
    info_str = ""
    elt = packet[Dot11Beacon].getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        if elt.ID == 222:
            info_str += elt.info.decode("utf-8")
        elt = elt.payload
    # logging.info(f"{info_str}")
    now = datetime.now()
    if packet[RadioTap].dBm_AntSignal is not None:
        rssi = int(packet[RadioTap].dBm_AntSignal)
    else:
        rssi = -100
    # Use regular expressions to extract the values
    face = re.search(r'"face":"(.*?)"', info_str)
    name = re.search(r'"name":"(.*?)"', info_str)
    pwnd_run = re.search(r'"pwnd_run":(\d+)', info_str)

    face = face.group(1) if face else None
    name = name.group(1) if name else None
    pwnd_run = int(pwnd_run.group(1)) if pwnd_run else None
    last = "?"

    timestamp_str = now.strftime("%m/%d/%y @ %I:%M %p")
    
    # Check if the name already exists in the data dictionary
    items = list(data.items())
    for key, value in items:
        if value.get("name") == name:
            # Calculate the time difference
            timestamp_str = value.get("timestamp", now.strftime("%m/%d/%y @ %I:%M %p"))
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

            value["time_diff"] = time_diff_str
            last = time_diff_str
            value["last"] = last
            # Update the face, pwnd_run, and last fields
            value["face"] = face
            value["pwnd_run"] = pwnd_run
            value["rssi"] = rssi
            value["timestamp"] = now.strftime("%m/%d/%y @ %I:%M %p")
            logging.info("Updated existing entry for name: %s" % name)
            break
    else:
        # If the name was not found, add a new entry to the data dictionary
        data[name] = {
            "face": face,
            "name": name,
            "pwnd_run": pwnd_run,
            "last": timestamp_str,
            "timestamp": timestamp_str,
            "rssi": -90,
        }
        logging.info("Added new entry for name: %s" % name)
    return data
