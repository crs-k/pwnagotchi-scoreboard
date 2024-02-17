def rssi_to_human(rssi):
    if rssi >= -50:
        return "▁▃▄▅▆▇"
    elif rssi >= -60:
        return "▁▃▄▅▆ "
    elif rssi >= -70:
        return "▁▃▄▅  "
    elif rssi >= -80:
        return "▁▃▄   "
    else:
        return "▁▃    "
