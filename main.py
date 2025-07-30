from scapy.all import sniff, ARP
from tabulate import tabulate
from datetime import datetime
from vendor_lookup import get_vendor, load_oui_file
import threading
import time
import csv
import os
import subprocess

ip_mac_history = {} # Tracks original IP -> first seen MAC
devices = {} # Global table of devices: IP -> MAC
alerts = [] # Stores spoof warnings
last_seen = {} # IP -> timestamp
oui_dict = load_oui_file() # Loads offline vendor data


def get_ttl(ip):
  """This is TTL (Time to Live), which is the the number of hops allowed before the packet 
  is discarded. Because in a local network the number of hops are very less, therefore 
  we can use this to get the OS involve - since different OS allows different TTL"""

  try:
    # send 1 ping with 1 second timeout
    result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True)
    output = result.stdout

    # We look for "ttl=xxx" in output
    for line in output.splitlines():
      if "ttl=" in line.lower():
        parts = line.split()
        for part in parts:
          if "ttl=" in part.lower():
            return int(part.lower().split("ttl=")[-1])
  except Exception:
    pass
  return None


def guess_os(ttl):
  if ttl is None:
    return "Unknown"
  if ttl <= 64:
    return "Linux/macOS"
  elif ttl <= 128:
    return "Windows"
  elif ttl <= 255:
    return "Router/Other"
  return "Unknown"


def log_alert_to_csv(ip, old_mac, new_mac):
  filename = "alerts.csv"
  file_exists = os.path.isfile(filename)

  with open(filename, mode="a", newline="") as csvfile:
    writer = csv.writer(csvfile)
    if not file_exists:
      writer.writerow(["Timestamp", "IP", "Original MAC", "New MAC"])
    timestamp = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    writer.writerow([timestamp, ip, old_mac, new_mac])


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
          log_alert_to_csv(ip, original_mac, mac)
    else:
      ip_mac_history[ip] = mac # Store the original MAC


def print_table():
  while True:
    if devices:
      table = []
      for ip, mac in devices.items():
        vendor = get_vendor(mac, oui_dict)
        seen = last_seen.get(ip, "Unknown")
        ttl = get_ttl(ip)
        os_guess = guess_os(ttl)
        table.append((ip, mac, vendor, os_guess, seen))

      print("\nActive Devices on Local Network:")
      print(tabulate(
        table, 
        headers=["IP", "MAC", "Vendor", "OS (Guess)", "Last Seen"], 
        tablefmt="fancy_grid"
      ))
    time.sleep(5)


if __name__ == "__main__":
  print("ARP Explorer running... Press Ctrl+C to stop.\n")

  # Start table printer in background
  printer_thread = threading.Thread(target=print_table, daemon=True)
  printer_thread.start()

  # Start sniffing (Requires root)
  sniff(filter="arp", prn=handle_arp, store=0)
