import nmap
from dotenv import load_dotenv
import os

load_dotenv()

network_range = os.getenv("NETWORK_IP")

def warden_scan(network_range):
    nm = nmap.PortScanner()

    nm.scan(hosts=network_range, arguments="-sn")

    devices = []
    for host in nm.all_hosts():
        device_info = {
            'IP': host,
            'Hostnames': nm[host].hostname(),
            'Status': nm[host].state(),
            'Protocols': nm[host].all_protocols(),
        }
        devices.append(device_info)
    
    return devices

devices = warden_scan(network_range)

# Print out the collected data
for device in devices:
    print(f"IP Address: {device['IP']}")
    print(f"Hostname: {device['Hostnames']}")
    print(f"Status: {device['Status']}")
    print(f"Protocols: {device['Protocols']}")
    print('-' * 40)
