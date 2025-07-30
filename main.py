from scapy.all import sniff, ARP, IP
from tabulate import tabulate
from datetime import datetime
from vendor_lookup import get_vendor, load_oui_file
import threading
import time
import csv
import os
import subprocess
import json


ip_mac_history = {} # Tracks original IP -> first seen MAC
devices = {} # Global table of devices: IP -> MAC
alerts = [] # Stores spoof warnings
last_seen = {} # IP -> timestamp
oui_dict = load_oui_file() # Loads offline vendor data
ip_packet_count = {} # IP -> count of packets seen
first_seen = {}      # IP -> first timestamp
offline_devices = {} # IP -> last confirmed offline time
ip_traffic_bytes = {}  # IP -> total bytes


def handle_traffic(packet):
  if IP in packet:
    ip = packet[IP].src
    ip_traffic_bytes[ip] = ip_traffic_bytes.get(ip, 0) + len(packet)


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

    if ip in ip_packet_count:
      ip_packet_count[ip] += 1
    else:
      ip_packet_count[ip] = 1

    # Record the device if new
    if ip not in devices:
      devices[ip] = mac

    # Update last seen
    last_seen[ip] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Only lists the first time - will be later used
    if ip not in first_seen:
      first_seen[ip] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # If previously offline, mark as online again
    if ip in offline_devices:
      del offline_devices[ip]

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


def save_lan_snapshot_json():
  snapshot = []
  for ip, mac in devices.items():
    traffic = ip_traffic_bytes.get(ip, 0)
    vendor = get_vendor(mac, oui_dict)
    os_guess = guess_os(get_ttl(ip))
    first = first_seen.get(ip, "Unknown")
    last = last_seen.get(ip, "Unknown")
    count = ip_packet_count.get(ip, 0)
    status = "Offline" if ip in offline_devices else "Online"
    snapshot.append({
      "ip": ip,
      "mac": mac,
      "vendor": vendor,
      "os": os_guess,
      "first": first,
      "last": last,
      "pkts": count,
      "status": status,
      "traffic": traffic
    })
  with open("lan_snapshot.json", "w") as f:
    json.dump(snapshot, f, indent=2)


def print_table():
  while True:
    if devices:
      table = []
      for ip, mac in devices.items():
        vendor = get_vendor(mac, oui_dict)
        seen = last_seen.get(ip, "Unknown")
        os_guess = guess_os(get_ttl(ip))
        count = ip_packet_count.get(ip, 0)
        first = first_seen.get(ip, "Unknown")
        traffic = ip_traffic_bytes.get(ip, 0)
        status = "Offline" if ip in offline_devices else "Online"
        table.append((ip, mac, vendor, os_guess, first, seen, count, status, f"{traffic//1024} KB"))

      print("\nActive Devices on Local Network:")
      print(tabulate(
        table, 
        headers=["IP", "MAC", "Vendor", "OS (Guess)", "First Seen", "Last Seen", "Pkts", "Status", "Traffic"], 
        tablefmt="fancy_grid"
      ))
    save_lan_snapshot_json()
    time.sleep(5)


def check_for_offline_devices(timeout=60):
  while True:
    now = datetime.now()
    for ip, last in list(last_seen.items()):
      last_time = datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
      if (now - last_time).total_seconds() > timeout and ip not in offline_devices:
        offline_devices[ip] = now.strftime("%Y-%m-%d %H:%M:%S")
        print(f"Devices offline: {ip} last seen at {last}")
    time.sleep(10)


if __name__ == "__main__":
  print("ARP Explorer running... Press Ctrl+C to stop.\n")

  # Start table printer
  printer_thread = threading.Thread(target=print_table, daemon=True)
  printer_thread.start()

  # Start offline checker
  offline_thread = threading.Thread(target=check_for_offline_devices, daemon=True)
  offline_thread.start()

  # Start ARP sniffer in background
  arp_sniffer = threading.Thread(
    target=lambda: sniff(filter="arp", prn=handle_arp, store=0),
    daemon=True
  )
  arp_sniffer.start()

  # Start IP traffic sniffer in background
  traffic_sniffer = threading.Thread(
    target=lambda: sniff(filter="ip", prn=handle_traffic, store=False),
    daemon=True
)
  traffic_sniffer.start()

  # Keep main thread alive
  while True:
    time.sleep(1)
