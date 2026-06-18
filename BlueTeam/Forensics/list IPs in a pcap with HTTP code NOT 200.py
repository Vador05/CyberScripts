#!/usr/bin/env python3

from scapy.all import *
import os

def list_ips(pcap_file):
    ips = {}

    packets = rdpcap(pcap_file)
    for packet in packets:
        if IP in packet and packet.haslayer(TCP) and packet.haslayer(HTTP):
            http = packet[HTTP]
            if http.ResponseCode != 200:
                ip = packet[IP].src
                if ip in ips:
                    ips[ip]["count"] += 1
                else:
                    ips[ip] = {"count": 1}

                if "location" not in ips[ip]:
                    ips[ip]["location"] = os.popen("geoiplookup " + ip).read()

    for ip in ips:
        print("IP:", ip)
        print("Count:", ips[ip]["count"])
        print("Location:", ips[ip]["location"])
        print("")

if __name__ == '__main__':
    pcap_file = input("Enter the path to the PCAP file: ")
    list_ips(pcap_file)
