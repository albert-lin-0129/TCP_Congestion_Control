#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]
  then echo "Please run with sudo!"
  exit
fi

echo "Building LWIP stacks..."
(cd lwip-tap-vanilla; ./configure; make)
(cd lwip-tap-defense; ./configure; make)

echo "Destroying existing mininet topology..."
mn -c

echo "Generating network environment..."

# Run the kernel server against various attackers.
python mininet.py --server=kernel --client=kernel
python mininet.py --server=kernel --client=opt-ack
python mininet.py --server=kernel --client=dup-ack
python mininet.py --server=kernel --client=ack-division

# Run the vanilla LWIP server against various attackers.
python mininet.py --server=lwip --client=kernel
python mininet.py --server=lwip --client=opt-ack
python mininet.py --server=lwip --client=dup-ack
python mininet.py --server=lwip --client=ack-division

# Run the defended LWIP server against the attackers.
python mininet.py --server=lwip-defense --client=kernel
python mininet.py --server=lwip-defense --client=opt-ack
python mininet.py --server=lwip-defense --client=ack-division
python mininet.py --server=lwip-defense --client=dup-ack

echo "Creating graphs..."
python create_graphs.py
