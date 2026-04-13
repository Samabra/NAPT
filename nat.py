import socket
import sys
import ipaddress
import random
import selectors
import struct
import time



LOCALHOST = '127.0.0.0.1'
NAT_TABLE = {}
REV_NAT_TABLE = {}
USED_PORTS = set()
LOGICAL_TO_REAL_PORT = {}
TIME_MAP = {}
REASSEMBLE_PACKET = []
# IP address validator
def validate_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False
# Check if address is in private block
def is_in_private_block(address):
    try:
        ip = ipaddress.ip_address(address)
        private_network = ipaddress.ip_network('10.0.0.0/8')
        return ip in private_network
    except ValueError:
        return False


# Calculate the IP checksum
def calculate_internet_checksum(data: bytes):
    if len(data) % 2 != 0:
        data += b'\x00'
    
    checksum = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    while (checksum >> 16) > 0:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    return ~checksum & 0xFFFF

def calculate_udp_checksum(packet: bytes):
    ihl = (packet[0] & 0x0F) * 4
    udp_segment = packet[ihl:]
    src_addr = packet[12:16]
    dest_addr = packet[16:20]
    zero_and_protocol = b'\x00\x11'
    udp_length = udp_segment[4:6]
    clean_udp_segment = bytearray(udp_segment)
    clean_udp_segment[6:8] = b'\x00\x00'
    pseudo_header = src_addr + dest_addr + zero_and_protocol + udp_length
    pseudo_packet = pseudo_header + clean_udp_segment

    checksum = calculate_internet_checksum(pseudo_packet)
    if checksum == b'\x00\x00':
        checksum = 0xFFFF
    return checksum

def is_ip_checksum_valid(packet: bytes):
    ihl = (packet[0] & 0x0F) * 4
    ip_header = packet[0:ihl]
    return calculate_internet_checksum(ip_header) == 0


def is_udp_checksum_valid(packet: bytes):
    ihl = (packet[0] & 0x0F) * 4
    udp_segment = packet[ihl:]
    udp_checksum = packet[6:8]
    if udp_checksum == b'\x00\x00':
        return True
    src_addr = packet[12:16]
    dest_addr = packet[16:20]
    zero_and_protocol = b'\x00\x11'
    udp_length = udp_segment[4:6]

    pseudo_header = src_addr + dest_addr + zero_and_protocol + udp_length
    verify_packet = pseudo_header + udp_segment

    return calculate_internet_checksum(verify_packet) == 0

def valid_TTL(packet: bytes):
    return packet[8] > 1

def df_is_set(packet:bytes):
    flags = packet[6]
    df_flag = flags & 0x40
    return df_flag != 0

def mf_is_set(packet:bytes):
    flags = packet[6]
    mf_flag = flags & 0x20
    return mf_flag != 0

def fragment(packet: bytes, mtu: int):
    ihl = (packet[0] & 0x0F) * 4
    packet_header = packet[:ihl]
    packet_payload = packet[ihl:]

    fragments = []
    max_payload_bytes = ((mtu - ihl) // 8) * 8

    current_byte_offset = 0
    while current_byte_offset < len(packet_payload):
        fragment = packet_payload[current_byte_offset: current_byte_offset + max_payload_bytes]
        last_fragment = (current_byte_offset + len(fragment)) >= len(packet_payload)

        clone_packet_header = bytearray(packet_header)

        fragment_len = ihl + len(fragment)
        clone_packet_header[2:4] = struct.pack("!H", fragment_len)

        flag_and_offset = current_byte_offset // 8

        if not last_fragment:
            flag_and_offset = flag_and_offset | 0x2000
        
        clone_packet_header[6:8] = struct.pack("!H", flag_and_offset)
        clone_packet_header[10:12] = b'\x00\x00'
        new_ip_checksum = calculate_internet_checksum(clone_packet_header)
        clone_packet_header[10:12] = struct.pack("!H", new_ip_checksum)
        final_fragment = bytes(clone_packet_header) + fragment
        fragments.append(final_fragment)
        current_byte_offset += len(fragment)
    return fragments

def reassemble_packet(packets: list):
    
# Error checking for all arguments
if len(sys.argv) != 7:
    print("Usage: python3 nat.py <external_ip> <num_external_ports> <timeout> <mtu> <real_internal_port> <real_next_hop_port", file=sys.stderr)
    sys.exit(1)

external_ip = sys.argv[1]
num_external_ports = int(sys.argv[2])
timeout = float(sys.argv[3])
mtu = float(sys.argv[4])
real_internal_port = int(sys.argv[5])
real_next_hop_port = int(sys.argv[6])

if not validate_ip(external_ip) or is_in_private_block(external_ip):
    print("Invalid external IP address. Address must be a valid IP address and not within the private network 10.0.0.0/8", file=sys.stderr)
    sys.exit(1)

if num_external_ports < 1 or num_external_ports > 65535:
    print("Invalid size of external port pool. Must be within 1 - 65535 ports.", file=sys.stderr)
    sys.exit(1)

if timeout < 1:
    print("Timeout must be a positive non-zero value.")
    sys.exit(1)

if mtu < 64 or mtu > 1024:
    print("Maximum transmission unit has to be between 64 - 1024 bytes.", file=sys.stderr)
    sys.exit(1)

if real_internal_port < 1 or real_internal_port > 65535:
    print("Internal port range must be between 1 - 65535 inclusive", file=sys.stderr)
    sys.exit(1)

if real_next_hop_port < 1 or real_next_hop_port > 65535:
    print("Next hop port range must be between 1 - 65535 inclusive", file=sys.stderr)
    sys.exit(1)


# Using selector for event driven I/O
selector = selectors.DefaultSelector()

# Creating UDP socket for internal network and binding it to local host and internal port
# that NAT is listening at in the internal network
internal_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
internal_udp_sock.bind(LOCALHOST, real_internal_port)
internal_udp_sock.setblocking(False)

# Creating UDP socket for external network and binding it to local host and 
# OS assigned port
external_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
external_udp_sock.bind(LOCALHOST, 0)

# Register both sockets to the selector to allow for asynchronicity
selector.register(internal_udp_sock, selectors.EVENT_READ, data="LAN")
selector.register(external_udp_sock, selectors.EVENT_READ, data="WAN")


# Translating internal IP and port to external IP and port and vice versa 
def address_port_translate(ip_address: str, port: int, outbound: bool):
    current_time = time.time()
    if outbound:
        internal_key = (ip_address, port)
        if internal_key not in NAT_TABLE:
            external_port = random.randint(1, num_external_ports)
            while external_port in USED_PORTS:
                external_port = random.randint(1, num_external_ports)
            USED_PORTS.add(external_port)
            external_key = (external_ip, external_port)
            NAT_TABLE[internal_key] = [external_key]
            TIME_MAP[external_key] = current_time
            REV_NAT_TABLE[external_key] = [internal_key]
        else:
            external_key = NAT_TABLE[internal_key]
            TIME_MAP[external_key] = current_time
        return external_key
    else:
        external_key = (ip_address, port)
        if external_key in REV_NAT_TABLE:
            internal_key = REV_NAT_TABLE[external_key]
            TIME_MAP[external_key] = current_time
            return internal_key
        else:
            return None, None



def del_idle_maps():
    current_time = time.time()
    idle_keys = []
    for external_key, last_active in TIME_MAP.items():
        if (current_time - last_active) > timeout:
            idle_keys.append(external_key)
        
        for external_key in idle_keys:
            internal_key = REV_NAT_TABLE[external_key]

            if internal_key:
                del NAT_TABLE[internal_key]
            del REV_NAT_TABLE[external_key]
            del TIME_MAP[external_key]

            USED_PORTS.discard(external_key[1])


reassembly = False
try:
# This is where the program actually listens for incoming packets
# from either the internal or external network
    while True:
        events = selector.select(timeout=0.5)
        for key, mask in events:
            sock = key.fileobj
            interface = key.data

            # Packets coming from internal network -> timeoutoutbound packets
            if interface == "LAN":
                payload, internal_address = sock.recvfrom(4096)
                _, real_client_port = internal_address
                if is_ip_checksum_valid(payload) and is_udp_checksum_valid(payload) and valid_TTL(payload) :
                    internal_ip = payload[12:16]
                    internal_port = payload[20:22]

                    internal_ip_string = socket.inet_ntoa(internal_ip)
                    internal_port_int = struct.unpack("!H", internal_port)[0]
                    if internal_ip_string not in LOGICAL_TO_REAL_PORT:
                        LOGICAL_TO_REAL_PORT[internal_ip_string] = real_client_port
                    
                    translated_ip, translated_port = address_port_translate(internal_ip, internal_port, True)
                    packet = bytearray(payload)
                    packet[8] -= 1
                    packet[12:16] = socket.inet_aton(translated_ip)
                    packet[20:22] = struct.pack("!H", translated_port)
                    packet[10:12] = b'\x00\x00'
                    new_ip_checksum = calculate_internet_checksum(packet[0:20])
                    new_udp_checksum = calculate_udp_checksum(packet)
                    packet[10:12] = struct.pack("!H", new_ip_checksum)
                    packet[26:28] = struct.pack("!H", new_udp_checksum)
                    if len(packet) > mtu and not df_is_set(packet):
                        mod_payloads = fragment(packet, mtu)
                        for chunks in mod_payloads:
                            external_udp_sock.sendto(chunks, (LOCALHOST, real_next_hop_port))
                    elif len(packet) < mtu:
                        mod_payload = bytes(packet)
                        external_udp_sock.sendto(mod_payload, (LOCALHOST, real_next_hop_port))
            
            # Packets coming from external network -> inbound packets
            if interface == "WAN":
                payload,_ = sock.recvfrom(4096)
                if is_ip_checksum_valid(payload) and is_udp_checksum_valid(payload) and valid_TTL(payload):
                    incoming_ip = payload[16:20]
                    incoming_port = payload[22:24]
                    incoming_ip_string = socket.inet_ntoa(incoming_ip)
                    incoming_port_int = struct.unpack("!H", incoming_port)[0]
                    translated_ip, translated_port = address_port_translate(incoming_ip, incoming_port, False)
                    if not translated_ip:
                        continue

                    real_to_send_port = LOGICAL_TO_REAL_PORT[translated_ip]
                    packet = bytearray(payload)
                    packet[8] -= 1
                    packet[16:20] = socket.inet_aton(translated_ip)
                    packet[22:24] = struct.pack("!H", translated_port)
                    packet[10:12] = b'\x00\x00'
                    new_ip_checksum = calculate_internet_checksum(packet[0:20])
                    new_udp_checksum = calculate_udp_checksum(packet)
                    packet[10:12] = struct.pack("!H", new_ip_checksum)
                    packet[26:28] = struct.pack("!H", new_udp_checksum)
                    if mf_is_set(packet):
                        reassembly = True
                        REASSEMBLE_PACKET.append(packet)

                    else:
                        if reassembly:
                            REASSEMBLE_PACKET.append(packet)

                    if REASSEMBLE_PACKET:
                        mod_payload = reassemble_packet(REASSEMBLE_PACKET)

                    mod_payload = bytes(packet)
                    internal_udp_sock.sendto(mod_payload, (LOCALHOST, real_to_send_port))
        del_idle_maps()
except KeyboardInterrupt:
    print("Shutting down")
finally:
    selector.close()
