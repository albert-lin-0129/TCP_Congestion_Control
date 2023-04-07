#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]
  then echo "Please run with sudo!"
  exit
fi

echo "Building LWIP stacks..."
(cd lwip-tap-vanilla; ./configure; make)
(cd lwip-tap-defense; ./configure; make)

echo "Destroying existing network topology..."
mn -c

echo "Generating network environment..."

# Run the vanilla LWIP server against various attackers.
python network.py --server=lwip-vanilla --client=kernel
python network.py --server=lwip-vanilla --client=opt-ack
python network.py --server=lwip-vanilla --client=dup-ack
python network.py --server=lwip-vanilla --client=ack-division

# Run the defended LWIP server against the attackers.
python network.py --server=lwip-defense --client=kernel
python network.py --server=lwip-defense --client=opt-ack
python network.py --server=lwip-defense --client=ack-division
python network.py --server=lwip-defense --client=dup-ack

echo "Creating graphs..."
python create_graphs.py
