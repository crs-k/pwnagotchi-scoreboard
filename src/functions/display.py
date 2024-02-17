import logging
import psutil
from PIL import Image, ImageDraw, ImageFont
from epd.epd3in52 import EPD
from functions.utils import rssi_to_human

font24 = ImageFont.truetype("DejaVuSansMono", size=24)
font18 = ImageFont.truetype("DejaVuSansMono", size=18)
font14 = ImageFont.truetype("DejaVuSansMono", size=14)

dropped_packets = 1
packets_recv = 1

epd = EPD()
epd.init()
epd.lut_GC()
epd.Clear()

def update_display(data, interface):
    # Convert the data to a table string
    table = ""
    for key, value in data.items():
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                table += f"{key}.{sub_key}: {sub_value}\n"
        else:
            table += f"{key}: {value}\n"

    # Create a new image
    Himage = Image.new("1", (360, 240), 0)  # 255: clear the frame
    draw = ImageDraw.Draw(Himage)

    # Get system info
    cpu_usage = psutil.cpu_percent()
    memory_info = psutil.virtual_memory()
    memory_usage = memory_info.percent
    temperature = psutil.sensors_temperatures()["cpu_thermal"][0].current

    # Get network info
    network_info = psutil.net_io_counters(pernic=True).get(interface)

    if network_info is not None:
        packets_recv = round(network_info.packets_recv / 1000000, 2)
        dropped_packets = round(network_info.dropin / 1000000, 2)
    else:
        logging.info(f"The '{interface}' interface could not be found.")

    # Draw system info
    system_info = f"CPU: {cpu_usage}%   Mem: {memory_usage}%   Temp: {temperature}C"
    draw.text((10, 220), system_info, font=font14, fill=255)

    # Draw network info
    if packets_recv == 0:
        dropped_percentage = 0
    else:
        dropped_percentage = round((dropped_packets / packets_recv) * 100)

    network_info = f"Received: {packets_recv}M   Dropped: {dropped_percentage}%"
    draw.text((10, 200), network_info, font=font14, fill=255)

    # Draw the title
    title = "Scoreboard"
    title_bbox = draw.textbbox((0, 0), title, font=font24)
    title_width = title_bbox[2] - title_bbox[0]
    title_start = (epd.width - title_width) // 1
    draw.text((title_start, 10), title, font=font24, fill=255)

    sorted_data = dict(
        sorted(
            data.items(),
            key=lambda item: (item[1]["pwnd_run"] is not None, item[1]["pwnd_run"]),
            reverse=True,
        )
    )

    # Draw the header
    header = "{:<16}{:^5}{:^5}{:>5}".format("Name", "Caps", "Last", "Pwr")
    draw.text((10, 50), header, font=font18, fill=255)

    # Draw the data rows
    y = 70
    for key, value in sorted_data.items():
        name_face = value["name"] if value["name"] else "?"
        rssi = int(value["rssi"]) if value["rssi"] is not None else None
        pwnd_run = value["pwnd_run"] if value["pwnd_run"] is not None else 0
        ascii_bar = rssi_to_human(rssi) if rssi is not None else "▁▃"
        last = value["last"] if value["last"] is not None else "?"

        # Calculate the number of spaces to add
        spaces = " " * (20 - len(name_face))

        row = "{}{}{:>5}{:>7}{:>9}".format(name_face, spaces, pwnd_run, last, ascii_bar)
        draw.text((10, y), row, font=font14, fill=255)
        y += 20

    # Rotate and display the image
    Himage = Himage.rotate(180)
    epd.display(epd.getbuffer(Himage))
    epd.refresh()

def display_image(path):
    image = Image.new("1", (epd.height, epd.width), 0)
    jpg = Image.open(path)
    jpg = jpg.resize((240, 240))
    jpg = jpg.convert("1")
    jpg = jpg.rotate(180)

    # Calculate the center coordinates
    x = (epd.height - jpg.width) // 2
    y = (epd.width - jpg.height) // 2
    image.paste(jpg, (x, y))

    epd.display(epd.getbuffer(image))
    epd.lut_GC()
    epd.refresh()