from scapy.all import sniff, ARP
from tabulate import tabulate
from datetime import datetime
from vendor_lookup import get_vendor, load_oui_file
import threading
import time

ip_mac_history = {} # Tracks original IP -> first seen MAC
devices = {} # Global table of devices: IP -> MAC
alerts = [] # Stores spoof warnings
last_seen = {} # IP -> timestamp
oui_dict = load_oui_file() # Loads offline vendor data

def handle_arp(packet):
  if packet.haslayer(ARP):
    arp = packet[ARP]
    ip = arp.psrc
    mac = arp.hwsrc

    # Record the device if new
    if ip not in devices:
      devices[ip] = mac

    # Update last seen
    last_seen[ip] = datetime.now().strftime("%Y-%m-%d %Hh:%Mm:%Ss")

    # Detection: if IP is known, but MAC changed
    if ip in ip_mac_history:
      original_mac = ip_mac_history[ip]
      if mac != original_mac:
        alert = f"Possible ARP Spoofing Detected! IP {ip} changed from {original_mac} to {mac} (lol)"
        if alert not in alerts: # To avoid duplicates
          alerts.append(alert)
          print(alert)
    else:
      ip_mac_history[ip] = mac # Store the original MAC

def print_table():
  while True:
    if devices:
      table = []
      for ip, mac in devices.items():
        vendor = get_vendor(mac, oui_dict)
        seen = last_seen.get(ip, "Unknown")
        table.append((ip, mac, vendor, seen))

      print("\nActive Devices on Local Network:")
      print(tabulate(table, headers=["IP", "MAC", "Vendor", "Last Seen"], tablefmt="fancy_grid"))
    time.sleep(5)

if __name__ == "__main__":
  print("ARP Explorer running... Press Ctrl+C to stop.\n")

  # Start table printer in background
  printer_thread = threading.Thread(target=print_table, daemon=True)
  printer_thread.start()

  # Start sniffing (Requires root)
  sniff(filter="arp", prn=handle_arp, store=0)
