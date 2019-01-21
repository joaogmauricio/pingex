#!/usr/bin/python

from scapy.all import *
import sys
import os

# tos = 1: filename ; tos = 0: payload ; tos = 2: EOF
last_tos = 0

filename = ""
payload = ""

def process_packet(packet):
	global last_tos
	global filename
	global payload

	transfered_bytes = 0

	if last_tos == 0 and packet.tos == 1:
		filename = packet[ICMP].load[-len(packet[ICMP].load):]
	elif last_tos == 1 and packet.tos == 1:
		filename += packet[ICMP].load[-len(packet[ICMP].load):]
	elif last_tos == 1 and packet.tos == 0:
		filename = os.path.splitext(os.path.basename(filename).rstrip())[0] + "_" + str(packet[IP].src) + "_" + datetime.now().strftime('%Y%m%d%H%M%S') + os.path.splitext(os.path.basename(filename).rstrip())[1]
		print("Receiving file {}".format(filename))
		payload = packet[ICMP].load[-len(packet[ICMP].load):]
		transfered_bytes += len(payload)
		print("{} bytes transfered".format(transfered_bytes)),
	elif last_tos == 0 and packet.tos == 0:
		payload += packet[ICMP].load[-len(packet[ICMP].load):]
		transfered_bytes += len(payload)
		print("\r{} bytes transfered".format(transfered_bytes)),

	sys.stdout.flush()

	last_tos = packet.tos

	if packet.tos == 2:
		print("\r\nWriting payload to file ({})...".format(filename)),
		fh = open(filename,"w+")
		fh.write(payload)
		fh.close()
		print("done!")
		last_tos = 0


if len(sys.argv) == 1:
        print("Sniffing on all interfaces.")
else:
        if sys.argv[1] == "-h":
                print("Usage: {0} [<iface>]. Example: {0} eth0".format(sys.argv[0]))
                exit()
        else:
                print("Sniffing interface: {}.".format(sys.argv[1]))

sniff(filter="inbound and icmp[icmptype] == 8", prn=process_packet)
