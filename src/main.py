#!/usr/bin/env python
from functions.display import display_image, update_display
from functions.data import handle_packet, load_data, save_data
from epd import epd3in52    
import threading
import logging
import sys
from scapy.all import Dot11Beacon, sniff

from functions.network import channel_hopper, start_monitor_mode

logging.basicConfig(level=logging.DEBUG)

SNIFF_FILTER_STRING = "type mgt subtype beacon and ether src de:ad:be:ef:de:ad"
SPLASH_IMAGE_PATH = "/home/ck/Pictures/logo.jpg"
INTERFACE = "wlan1"
data = None

def PacketHandler(packet):
    global data
    if packet.addr2 == "de:ad:be:ef:de:ad":
        if packet.haslayer(Dot11Beacon):
            logging.info("Packet is Beacon")
            # packet.show()
            data = handle_packet(packet, data)
            save_data(data)
            try:
                update_display(data, INTERFACE)
            except IOError:
                logging.error("IOError occurred")
            except KeyboardInterrupt:
                logging.info("ctrl + c detected, exiting program")
                epd3in52.epdconfig.module_exit(cleanup=True)
                exit()


logging.info("Starting")
if not start_monitor_mode(INTERFACE):
    sys.exit(1)
data = load_data()
channel_hopper_thread = threading.Thread(target=channel_hopper, args=(INTERFACE,))
channel_hopper_thread.daemon = True
channel_hopper_thread.start()
epd = epd3in52.EPD()
epd.init()
epd.lut_GC()
epd.Clear()
display_image(SPLASH_IMAGE_PATH)
update_display(data, INTERFACE)

sniff(iface=INTERFACE, prn=PacketHandler, filter=SNIFF_FILTER_STRING, monitor=True)
logging.info("Stopping")
