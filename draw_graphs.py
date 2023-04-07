"""
This script is used to draw the graphs using captured pcap files
"""

import os
import argparse
from operator import itemgetter
from scapy.all import *

import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Bitmasks for checking the flags of a TCP packet.
SYN = 0x02
ACK = 0x10
FIN = 0x01

def load_pcap(filename):
    """Loads in a pcap file and returns a pair of lists - one of acks and one of data packets.
    Each of these lists contains pairs of the format (time, segment number). The lists are
    normalized to the smallest time and the initial sequence number."""
    cap = rdpcap(filename)

    acks, data, initial_seqno = [], [], None

    for packet in cap:
        # Get TCP packet
        if not isinstance(packet, Ether): continue
        if not isinstance(packet.payload, IP): continue
        if not isinstance(packet.payload.payload, TCP): continue
        tcp = packet.payload.payload

        if tcp.flags & SYN and tcp.flags & ACK: initial_seqno = tcp.seq
        if not tcp.payload and tcp.flags & ACK and not tcp.flags & SYN and not tcp.flags & FIN:
            acks.append((packet.time, tcp.ack))
        if tcp.payload:
            data.append((packet.time, tcp.seq + len(tcp.payload)))

    min_time = min(min(ack[0] for ack in acks), min(d[0] for d in data))
    acks = [(time - min_time, num - initial_seqno - 1) for (time, num) in acks]
    data = [(time - min_time, num - initial_seqno - 1) for (time, num) in data]

    # Remove retransmits for a cleaner graph.
    seen_seqnos, deduped_data = set(), []
    for (time, seqno) in data:
        if seqno in seen_seqnos: continue
        seen_seqnos.add(seqno)
        deduped_data.append((time, seqno))

    return acks, deduped_data

def create_graph(title, output, graphs):
    colors = [('red', 'blue'), ('green', 'yellow')]

    plt.figure(figsize=(8, 8))
    plt.title(title)

    for i, (filename, ack_label, data_label) in enumerate(graphs):
        acks, data = load_pcap(filename)
        plt.scatter(map(itemgetter(0), acks), map(itemgetter(1), acks), c=colors[i][0], marker='x', label=ack_label)
        plt.scatter(map(itemgetter(0), data), map(itemgetter(1), data), c=colors[i][1], label=data_label)
    
    plt.xlabel("Time (sec)")
    plt.ylabel("Sequence Number (bytes)")
    plt.legend(loc='lower right', fontsize=10)
    
    plt.savefig(output)

if __name__ == "__main__":
    os.system("mkdir -p graphs")
    
    # Test the LWIP stack against a normal client, as well as attackers.

    create_graph("LWIP with Normal TCP Client", "graphs/kernel-lwip-vanilla.png",
        [("captures/kernel-lwip-vanilla.pcap", 'ACKs', 'Data Segments')])

    create_graph("LWIP Stack vs. ACK Division Attacker", "graphs/ack-division-lwip-vanilla.png", [
        ("captures/kernel-lwip-vanilla.pcap", 'ACKs (Normal)', 'Data Segments (Normal)'),
        ("captures/ack-division-lwip-vanilla.pcap", 'ACKs (Ack Division)', 'Data Segments (Ack Division)')
        ])

    create_graph("LWIP Stack vs. Opt Ack Attacker", "graphs/opt-ack-lwip-vanilla.png", [
        ("captures/kernel-lwip-vanilla.pcap", 'ACKs (Normal)', 'Data Segments (Normal)'),
        ("captures/opt-ack-lwip-vanilla.pcap", 'ACKs (Optimistic Ack)', 'Data Segments (Optimistic Ack)')
        ])
    
    create_graph("LWIP Stack vs. Dup Ack Attacker", "graphs/dup-ack-lwip-vanilla.png", [
        ("captures/kernel-lwip-vanilla.pcap", 'ACKs (Normal)', 'Data Segments (Normal)'),
        ("captures/dup-ack-lwip-vanilla.pcap", 'ACKs (Duplicate Ack)', 'Data Segments (Duplicate Ack)')
        ])
    
    # Test our defended LWIP stack against various clients.

    create_graph("Defended LWIP Stack with Normal (Kernel) TCP Client", "graphs/kernel-lwip-defense.png",
        [("captures/kernel-lwip-defense.pcap", 'ACKs', 'Data Segments')])

    create_graph("Defended LWIP Stack vs. ACK Division Attacker", "graphs/ack-division-lwip-defense.png", [
        ("captures/kernel-lwip-defense.pcap", 'ACKs (Normal)', 'Data Segments (Normal)'),
        ("captures/ack-division-lwip-defense.pcap", 'ACKs (Ack Division)', 'Data Segments (Ack Division)')
        ])

    create_graph("Defended LWIP Stack vs. Opt Ack Attacker", "graphs/opt-ack-lwip-defense.png", [
        ("captures/kernel-lwip-defense.pcap", 'ACKs (Normal)', 'Data Segments (Normal)'),
        ("captures/opt-ack-lwip-defense.pcap", 'ACKs (Optimistic Ack)', 'Data Segments (Optimistic Ack)')
        ])

    create_graph("Defended LWIP Stack vs. Duplicate ACK Attacker", "graphs/dup-ack-lwip-defense.png", [
        ("captures/kernel-lwip-defense.pcap", 'ACKs (Normal)', 'Data Segments (Normal)'),
        ("captures/dup-ack-lwip-defense.pcap", 'ACKs (Duplicate ACK)', 'Data Segments (Duplicate ACK)')
        ])

