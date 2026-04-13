#! /usr/bin/env python3

"""
Sample client for NAT

This program sends a series of pre-crafted logical UDP/IPv4 packets to a NAT
implementation running on localhost. It is intended to assist with initial
testing of your NAT system.

Usage:
    python3 sample_client.py <nat_real_internal_port>

Arguments:
    <nat_real_internal_port>  UDP port on localhost where NAT is listening.

Requirements:
    - logical_packets.py must be in the same directory and define an
      iterable `packets`, which contains the pre-crafted packets.

Notes:
    - This client only sends packets; it does not listen for replies.
    - Students are strongly encouraged to develop their own client programs
      and their own logical packets, or extend these, in order to exercise
      all required NAT behaviours and edge cases.

Version: 1.0
"""

import argparse
import socket
import sys
import time

from logical_packets import packets


def parse_args():
    """Parse command-line arguments and validate the NAT port number."""
    parser = argparse.ArgumentParser(description="Send sample logical packets to NAT")
    parser.add_argument(
        "port", type=int, help="UDP port where NAT is listening (1024-65535)"
    )
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Port must be between 1024 and 65535")
    return args.port


def send_packets(
    nat_address: tuple[str, int], packets: list[bytes], delay: float = 1.0
):
    """
    Send a series of pre-crafted packets to a NAT at the specified address.

    Each packet in `packets` is sent in order, with an optional delay
    between sends. This function prints the packet number and length
    for monitoring.

    Args:
        nat_address (tuple[str, int]): (IP, port) of the NAT's client-side listener.
        packets (iterable[bytes]): Iterable of bytes objects representing packets.
        delay (float, optional): Time in seconds to wait between sending packets.
                                 Defaults to 1.0.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for i, pkt in enumerate(packets, start=1):
            try:
                print(f"Sending packet {i} to {nat_address} ({len(pkt)} bytes)...")
                sock.sendto(pkt, nat_address)
                time.sleep(delay)
            except OSError as e:
                print(f"Failed to send packet {i}: {e}", file=sys.stderr)
            except Exception as e:  # just in case
                print(f"Unexpected error sending packet {i}: {e}", file=sys.stderr)


def main():
    """Main function to parse arguments and send packets to the NAT."""
    port = parse_args()
    nat_address = ("127.0.0.1", port)
    send_packets(nat_address, packets, delay=0.5)


if __name__ == "__main__":
    main()
