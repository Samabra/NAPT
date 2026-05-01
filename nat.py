import socket
import sys
import ipaddress
import random
import selectors
import struct
import time
from datetime import datetime

# IP address that is used to actually send packets
LOCALHOST = '127.0.0.1'

# A map for outbound address and port translation
# Uses a tuple as the key (internal_ip, internal_port)
NAT_TABLE = {}

# A map for inbound address and port translation
# Uses a tuple as the key (external_ip, external_port)
REV_NAT_TABLE = {}

# A set to keep track of external ports that are used
USED_PORTS = set()

# A map to keep track of the real port internal client sent packets to NAT
LOGICAL_TO_REAL_PORT = {}

# A map to keep timestamps of when a mapping in the NAT_TABLE/REV_NAT_TABLE has been used.
# Ensures that when mapping has been idle for too long, the mapping is deleted
# Uses a tuple (external_ip, external_port) as the key
TIME_MAP = {}

# A buffer to collect fragments of a packet
# Fragments of a packet are identified with the unique ID of a packet in each fragment
# Hence the key used is the ID stored in the fragment, which is the ID of the entire packet
# It has 5 fields for each ID
#   'fragments': {} a map, which maps the byte offset of the fragment to the payload of fragment
#   'base_header': stores the header from the fragment with byte offset 0
#   'expected_length': the expected length of packet, set after last fragment has arrived
#   'current_bytes': a counter for how many bytes has been collected so far 
#   'last_received': a timestamp for the most recent time a fragment of the same ID has arrived 
REASSEMBLE_BUFFER = {}

# A global counter for ID of ICMP messages
ICMP_ID_COUNTER = 1


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

    # Pad the data with an empty zero byte to ensure the number of bytes are even, if not even
    if len(data) % 2 != 0:
        data += b'\x00'
    
    # Goes through 2 bytes at a time
    # Left shift the first 8 bits and add the second 8 bits to create a 16 bit integer
    # Sum over all 16 bit integers
    checksum = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))

    # If sum is greater than 16 bits, carry around the extra bits and add it to the bottom end
    while (checksum >> 16) > 0:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # Take the ones complement
    # Since Python interprets 16 bit integers as signed, we need to mask it with 0xFFFF
    # to ensure that it is not signed and only positive 16 bit integers
    return ~checksum & 0xFFFF


# Calculate the UDP checksum
def calculate_udp_checksum(packet: bytes):

    # Take the payload without the IP address
    # Take source IP and destination IP address
    udp_segment = packet[20:]
    src_addr = packet[12:16]
    dest_addr = packet[16:20]

    # Protocol is always at 17. Zero is zero
    zero_and_protocol = b'\x00\x11'

    # Get length of the UDP header and payload
    udp_length = udp_segment[4:6]
    clean_udp_segment = bytearray(udp_segment)
    clean_udp_segment[6:8] = b'\x00\x00'

    # Create the pseudo packet as specified
    pseudo_header = src_addr + dest_addr + zero_and_protocol + udp_length
    pseudo_packet = pseudo_header + clean_udp_segment

    # Calculate UDP checksum over the entire pseudo packet
    checksum = calculate_internet_checksum(pseudo_packet)

    # If checksum is 0, then set it as 0xFFFF to show that a checksum is present
    if checksum == 0:
        checksum = 0xFFFF
    return checksum

# Checks validity of IP checksum
def is_ip_checksum_valid(packet: bytes):
    ip_header = packet[0:20]
    return calculate_internet_checksum(ip_header) == 0


# Checks validity of UDP checksum
# Creates a pseudo packet as specified by assignment specs for UDP checksum
# If checksum is 0, then it is automatically regarded as a valid UDP checksum
def is_udp_checksum_valid(packet: bytes):
    udp_segment = packet[20:]
    udp_checksum = udp_segment[6:8]
    if udp_checksum == b'\x00\x00':
        return True
    src_addr = packet[12:16]
    dest_addr = packet[16:20]
    zero_and_protocol = b'\x00\x11'
    udp_length = udp_segment[4:6]

    pseudo_header = src_addr + dest_addr + zero_and_protocol + udp_length
    verify_packet = pseudo_header + udp_segment

    return calculate_internet_checksum(verify_packet) == 0


# Check if TTL is greater than 1, as our NAT would decrement TTL to 0
def valid_TTL(packet: bytes):
    return packet[8] > 1

# Check if DF (Don't Fragment) flag is set
def df_is_set(packet:bytes):
    flags = packet[6]
    df_flag = flags & 0x40
    return df_flag != 0

# Check if MF (More Fragments) flag is set
# Useful to check if a received packet is a fragment of a much larger packet
def mf_is_set(packet:bytes):
    flags = packet[6]
    mf_flag = flags & 0x20
    return mf_flag != 0


# Checks if a fragment is not the first fragment
# Checks if Flag Offset is greater than 0
# Semantically called is_last_fragment because it is only used to check for the last fragment
# Used in conjunction with mf_is_set to check for last fragment
def is_last_fragment(packet:bytes):
    flag_and_offset = struct.unpack("!H", packet[6:8])[0]
    return (flag_and_offset & 0x1FFF) > 0


# Fragment packets > mtu
def fragment(packet: bytes, mtu: int):

    # Take packet header and packet payload separately
    packet_header = packet[:20]
    packet_payload = packet[20:]

    # List to collect fragments
    fragments = []

    # Get size of maximum payload size in bytes
    # Makes sure that the fragment size is a multiple of 8 bytes
    max_payload_bytes = ((mtu - 20) // 8) * 8

    current_byte_offset = 0
    while current_byte_offset < len(packet_payload):

        # Take fragment from payload.
        fragment = packet_payload[current_byte_offset: current_byte_offset + max_payload_bytes]

        # Check if the fragment is the last fragment
        last_fragment = (current_byte_offset + len(fragment)) >= len(packet_payload)
        
        # Make a clone of the header collected from original packet
        clone_packet_header = bytearray(packet_header)

        # Calculate actual length of fragment
        fragment_len = 20 + len(fragment)

        # Update packet header with length of the fragment
        clone_packet_header[2:4] = struct.pack("!H", fragment_len)
        

        # Calculates the byte offset of the fragment in multiples of 8 bytes
        flag_and_offset = current_byte_offset // 8

        # Set MF = 0 if it is the last fragment
        if not last_fragment:
            flag_and_offset = flag_and_offset | 0x2000
        
        # Calculate new IP checksum of fragment
        clone_packet_header[6:8] = struct.pack("!H", flag_and_offset)
        clone_packet_header[10:12] = b'\x00\x00'
        new_ip_checksum = calculate_internet_checksum(clone_packet_header)
        print(f"After fragmenting, this is the new IP checksum of this particular fragment: 0x{new_ip_checksum:04x}\n")
        clone_packet_header[10:12] = struct.pack("!H", new_ip_checksum)
        if len(fragment) % 8 == 0:
            print("This fragment is a multiple of 8 bytes.\n")

        # Construct the final fragment
        final_fragment = bytes(clone_packet_header) + fragment
        fragments.append(final_fragment)
        current_byte_offset += len(fragment)
    return fragments

# Function that takes in a fragment and stores it inside REASSEMBLE_BUFFER
def assemble_fragments(packet:bytes, is_last: bool, last_received_time: float):

    # Exctract header, payload, ID of fragment
    fragment_header = packet[:20]
    fragment_payload = packet[20:]
    identity_ip = packet[4:6]

    # Extract the byte offset and convert it into actual number of byte offsets
    # Not in multiples of 8 bytes
    flags_and_offset = struct.unpack("!H", packet[6:8])[0]
    byte_offset = (flags_and_offset & 0x1FFF) * 8

    # Create new entry for fragment if it is a fragment with a new ID
    if identity_ip not in REASSEMBLE_BUFFER:
        REASSEMBLE_BUFFER[identity_ip] = {
            'fragments': {},
            'base_header': None,
            'expected_length': -1,
            'current_bytes': 0,
            'last_received': last_received_time
        }

    # Store header of fragment with byte offset 0
    if byte_offset == 0:
        REASSEMBLE_BUFFER[identity_ip]['base_header'] = fragment_header
    REASSEMBLE_BUFFER[identity_ip]['fragments'][byte_offset] = fragment_payload
    REASSEMBLE_BUFFER[identity_ip]['current_bytes'] += len(fragment_payload)

    # Calculate expected length of packet when last packet is received
    if is_last:
        REASSEMBLE_BUFFER[identity_ip]['expected_length'] = byte_offset + len(fragment_payload)
    
    # Delete reassembly buffer for fragments with this specific ID, when a new fragment comes in
    if last_received_time - REASSEMBLE_BUFFER[identity_ip]['last_received'] > timeout:
        print(f"Fragment reassembly timed out for ID: {identity_ip}\n")
        print(f"Removing fragment buffer for ID: {identity_ip}\n")

        # If fragment with byte offset 0 is in the buffer, then send an ICMP error
        if 0 in REASSEMBLE_BUFFER[identity_ip]['fragments']:
            first_frag_header = REASSEMBLE_BUFFER[identity_ip]['base_header']
            first_frag_load = REASSEMBLE_BUFFER[identity_ip]['fragments'][0]
            error_packet = first_frag_header + first_frag_load
            ICMP_packet = ICMP_Error(11, 1, error_packet[0:28])
            print(f"Sending ICMP error for timed out fragment reassembly with ID: {identity_ip}")
            external_udp_sock.sendto(ICMP_packet, (LOCALHOST, real_next_hop_port))
        del REASSEMBLE_BUFFER[identity_ip]
        return None
    
    # Update the timestamp for the reassembly buffer for this ID, if not greater than timeout
    REASSEMBLE_BUFFER[identity_ip]['last_received'] = last_received_time

    # If we have collected all fragments, then reassemble fragments into final packet
    buffer_entry = REASSEMBLE_BUFFER[identity_ip]
    if buffer_entry['expected_length'] != -1 and buffer_entry['expected_length'] == buffer_entry['current_bytes']:
        sorted_offsets = sorted(buffer_entry['fragments'].keys())

        ordered_fragments = [buffer_entry['fragments'][offset] for offset in sorted_offsets]
        assembled_payload = b"".join(ordered_fragments)

        base_header = bytearray(buffer_entry['base_header'])

        total_length = len(base_header) + len(assembled_payload)
        base_header[2:4] = struct.pack("!H", total_length)

        base_header[6:8] = b'\x00\x00'
        
        # Calculate new IP checksum 
        base_header[10:12] = b'\x00\x00'
        new_ip_checksum = calculate_internet_checksum(base_header)
        base_header[10:12] = struct.pack("!H", new_ip_checksum)
        final_packet = bytes(base_header) + assembled_payload
        print(f"Length of final packet is: {len(final_packet)}\n")

        # Delete the entry for this ID, since we have now reassembled the packet
        del REASSEMBLE_BUFFER[identity_ip]
        return final_packet
    return None

    
# Error checking for all arguments
if len(sys.argv) != 7:
    print("Usage: python3 nat.py <external_ip> <num_external_ports> <timeout> <mtu> <real_internal_port> <real_next_hop_port>", file=sys.stderr)
    sys.exit(1)

external_ip = sys.argv[1]
num_external_ports = int(sys.argv[2])
timeout = float(sys.argv[3])
mtu = int(sys.argv[4])
real_internal_port = int(sys.argv[5])
real_next_hop_port = int(sys.argv[6])

if not validate_ip(external_ip) or is_in_private_block(external_ip):
    print("Invalid external IP address. Address must be a valid IP address and not within the private network 10.0.0.0/8", file=sys.stderr)
    sys.exit(1)

if num_external_ports < 1 or num_external_ports > 65535:
    print("Invalid size of external port pool. Must be within 1 - 65535 ports.", file=sys.stderr)
    sys.exit(1)

if timeout < 1:
    print("Timeout must be a positive non-zero value.", file=sys.stderr)
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
internal_udp_sock.bind((LOCALHOST, real_internal_port))
internal_udp_sock.setblocking(False)

# Creating UDP socket for external network and binding it to local host and 
# OS assigned port
external_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
external_udp_sock.bind((LOCALHOST, 0))
external_udp_sock.setblocking(False)

# Register both sockets to the selector to allow for asynchronicity
selector.register(internal_udp_sock, selectors.EVENT_READ, data="LAN")
selector.register(external_udp_sock, selectors.EVENT_READ, data="WAN")


# Translating internal IP and port to external IP and port and vice versa 
def address_port_translate(ip_address: str, port: int, outbound: bool):
    current_time = time.time()
    external_key = None

    # If packet is outbound, then either create a new mapping or get IP and port
    # from existing mapping
    if outbound:
        internal_key = (ip_address, port)
        if internal_key not in NAT_TABLE:

            # Randomise external port used instead of simply incrementing port
            external_port = random.randint(1, num_external_ports)

            # If ports are not exhausted, keep looking for a external port number
            # until an unused external port is found.
            # Else, no suitable external port found for an external flow
            if len(USED_PORTS) != num_external_ports:
                while external_port in USED_PORTS:
                    external_port = random.randint(1, num_external_ports)
            else:
                return None, None
            
            # If external port found, add to USED_PORTS
            # Put mapping in both outbound NAT table and inbound NAT table
            # Keep timestamp of when this mapping is used
            USED_PORTS.add(external_port)
            external_key = (external_ip, external_port)
            NAT_TABLE[internal_key] = external_key
            TIME_MAP[external_key] = current_time
            REV_NAT_TABLE[external_key] = internal_key
        else:

            # Timestamp of when mapping is used and and retrieve external ip and port from existing mapping
            external_key = NAT_TABLE[internal_key]
            TIME_MAP[external_key] = current_time
        return external_key
    else:

        # For inbound packets, retrieve existing mapping.
        # If mapping deleted or unsolicited packets are received from external side
        # Then returns None, None, as no suitable internal IP address or port was found
        # to translate to.
        # Keeps a timestamp since the mapping is used
        external_key = (ip_address, port)
        if external_key in REV_NAT_TABLE:
            internal_key = REV_NAT_TABLE[external_key]
            TIME_MAP[external_key] = current_time
            return internal_key
        else:
            return None, None


# Delete any idle mappings
def del_idle_maps():
    current_time = time.time()
    idle_keys = []
    
    # Checks all mappings to see if any mapping has been idle for too long
    for external_key, last_active in TIME_MAP.items():
        if (current_time - last_active) > timeout:
            idle_keys.append(external_key)

    # Deletes all mappings that have found to be timed out    
    for external_key in idle_keys:
        internal_key = REV_NAT_TABLE[external_key]
        if internal_key:
            del NAT_TABLE[internal_key]
        print(f"Deleting mapping for: {internal_key} and {external_key}\n")
        del REV_NAT_TABLE[external_key]
        del TIME_MAP[external_key]

        # Delete external port from used ports, to free up a port for use
        USED_PORTS.discard(external_key[1])

# Function to create the ICMP error message
def ICMP_Error(type_error: int, code: int, data: bytes):

    # Global ICMP_ID counter, to form ID of ICMP error messages
    global ICMP_ID_COUNTER

    # Extract IP header and the IP and UDP header for ICMP error message
    ip_header = bytearray(data[:20])
    ip_udp_header = data

    # Create the empty ICMP header 
    dummy_icmp_header = struct.pack('!BBHI', type_error, code, 0, 0)


    # Calculate checksum over the created header and the IP and UDP header
    checksum_data = dummy_icmp_header + ip_udp_header
    icmp_checksum = calculate_internet_checksum(checksum_data)

    # Actual ICMP header now has the checksum
    real_icmp_header = struct.pack('!BBHI', type_error, code, icmp_checksum, 0)

    # Length of total ICMP error message in main IP header
    ip_header[2:4] = struct.pack('!H', 56)

    # Update IP header with the ID of ICMP error message
    ip_header[4:6] = struct.pack("!H", ICMP_ID_COUNTER)

    # Update ID for ICMP
    ICMP_ID_COUNTER = (ICMP_ID_COUNTER + 1) % 65535
    if ICMP_ID_COUNTER == 0:
        ICMP_ID_COUNTER = 1
    
    # Set all flags and offset to 0
    ip_header[6:8] = b'\x00\x00'

    # Set TTL to 64 and protocol to 1
    ip_header[8] = 64
    ip_header[9] = 1

    # Swap source and dest IP around
    # Source IP set to LOCALHOST as I didn't know what else to set it to
    original_src_ip = ip_header[12:16]
    ip_header[12:16] = socket.inet_aton(LOCALHOST)
    ip_header[16:20] = original_src_ip

    # Calculate IP checksum
    ip_header[10:12] = b'\x00\x00'
    ip_checksum = calculate_internet_checksum(ip_header)
    ip_header[10:12] = struct.pack('!H', ip_checksum)
    # Create the ICMP error packet
    icmp_packet = bytes(ip_header) + real_icmp_header + ip_udp_header 

    return icmp_packet


# A function that periodically deletes any reassembly buffers that have timed out
# This is for when no fragments have arrived since the last fragment
def del_timed_out_fragments():
    current_time = time.time()
    dead_packets = []

    # Find any reassembly buffers that have timed out
    for identity_ip, data in REASSEMBLE_BUFFER.items():
        if (current_time - data['last_received']) > timeout:
            dead_packets.append(identity_ip)

    # Delete reassembly buffers that have timed out
    # If fragment with byte offset 0 exists in a specific buffer
    # Then send ICMP error message
    for id_ip in dead_packets:
        print(f"Deleting timed out fragments for ID: {id_ip}\n")
        if 0 in REASSEMBLE_BUFFER[id_ip]['fragments']:
            print(f"Deleting timed out fragment for ID {id_ip} and sending ICMP error\n")
            first_frag_header = REASSEMBLE_BUFFER[id_ip]['base_header']
            first_frag_load = REASSEMBLE_BUFFER[id_ip]['fragments'][0]
            error_packet = first_frag_header + first_frag_load
            ICMP_packet = ICMP_Error(11, 1, error_packet[0:28])
            print("ICMP error should be timed out during reassembly of fragments\n")
            external_udp_sock.sendto(ICMP_packet, (LOCALHOST, real_next_hop_port))

        del REASSEMBLE_BUFFER[id_ip]


try:
# This is where the program actually listens for incoming packets
# from either the internal or external network
    print(f"NAT now listening ...")

    while True:

        # Use selectors for event-driven I/O
        events = selector.select(timeout=0.5)
        for key, mask in events:
            sock = key.fileobj
            interface = key.data

            # Packets coming from internal network -> outbound packets
            if interface == "LAN":
                now = datetime.now()
                timestamp = now.strftime("%H:%M:%S.%f")[:-3]
                payload, internal_address = sock.recvfrom(4096)
                _, real_client_port = internal_address
                print(f"Outbound Packet coming from internal host at time: {timestamp}\n")
                # Only process outbound packets if IP checksum, UDP checksum are valid and TTL > 1
                if is_ip_checksum_valid(payload) and is_udp_checksum_valid(payload) and valid_TTL(payload) :
                    # Grab source IP and source port of the internal client
                    internal_ip = payload[12:16]
                    internal_port = payload[20:22]
                    internal_ip_string = socket.inet_ntoa(internal_ip)
                    internal_port_int = struct.unpack("!H", internal_port)[0]
                    curr_ip_checksum = struct.unpack("!H", payload[10:12])[0]
                    curr_udp_checksum = struct.unpack("!H", payload[26:28])[0]


                    print("This is the IP for the outbound packet before translation: " + internal_ip_string + " \n")
                    print("This is the port number for the outbound packet before translation: " + str(internal_port_int) + " \n")
                    print(f"This is the original IP checksum before translation for outbound packet: 0x{curr_ip_checksum:04x}\n")
                    print(f"This is the original UDP checksum before translation for outbound packet: 0x{curr_udp_checksum:04x}\n")

                    # This table is store the real source port and not the logical source port
                    if internal_ip_string not in LOGICAL_TO_REAL_PORT:
                        LOGICAL_TO_REAL_PORT[internal_ip_string] = real_client_port
                    
                    # For outbound direction, either find or create a new entry in NAT table. Return translated address and port
                    translated_ip, translated_port = address_port_translate(internal_ip_string, internal_port_int, True)

                    # This means that there is no valid port. Send ICMP error message back to internal client and move on to next packet
                    if not translated_port:
                        print("No available external ports for a new flow\n")
                        ICMP_packet = ICMP_Error(3, 13, payload[0:28])
                        print(f"Send ICMP error message back to internal host {internal_ip_string} on port {internal_port_int}, with type 3 and code 13\n")
                        internal_udp_sock.sendto(ICMP_packet, (LOCALHOST, real_client_port))
                        continue

                    print("This is the new IP for the outbound packet: " + translated_ip + " \n")
                    print("This is the new port for the outbound packet: " + str(translated_port) + " \n")
                    packet = bytearray(payload)

                    print("This is the TTL of the packet before changing it: " + str(packet[8]) + " \n")
                    # Decrement TTL by 1
                    packet[8] -= 1
                    print("This is the TTL of the packet after changing it: " + str(packet[8]) + " \n")

                    # Change to new IPv4 address
                    packet[12:16] = socket.inet_aton(translated_ip)

                    # Change to new port
                    packet[20:22] = struct.pack("!H", translated_port)

                    # Zero out the checksum before making a new checksum
                    packet[10:12] = b'\x00\x00'

                    # Calculate new checksum
                    new_ip_checksum = calculate_internet_checksum(packet[0:20])
                    print(f"New IP checksum for outbound packet: 0x{new_ip_checksum:04x}\n")
                    
                    # Calculate new UDP checksum
                    new_udp_checksum = calculate_udp_checksum(packet)
                    print(f"New UDP checksum for outbound packet: 0x{new_udp_checksum:04x}\n")
                    # Update both checksums
                    packet[10:12] = struct.pack("!H", new_ip_checksum)
                    packet[26:28] = struct.pack("!H", new_udp_checksum)

                    # Fragment packets larger than MTU, that do not have their DF flag set
                    if len(packet) > mtu and not df_is_set(packet):
                        print("This packet is " + str(len(packet)) + " bytes long, compared to MTU: " + str(mtu) + " \n")
                        mod_payloads = fragment(packet, mtu)
                        print("There are " + str(len(mod_payloads)) + " fragments\n")

                        # Send fragments one by one to next hop
                        for chunks in mod_payloads:
                            print("Sending a fragment to next hop\n")
                            external_udp_sock.sendto(chunks, (LOCALHOST, real_next_hop_port))

                    # Otherwise, send the packets to the real next hop port
                    elif len(packet) <= mtu:
                        print("This packet is " + str(len(packet)) + " bytes long, shorter or just about equal to MTU: " + str(mtu) + " \n")
                        mod_payload = bytes(packet)
                        print("Sending intact packet to next hop\n")
                        external_udp_sock.sendto(mod_payload, (LOCALHOST, real_next_hop_port))

                    
                    # When packet is greater than MTU and DF is set
                    # Set ICMP error message and send it back to internal client
                    elif len(packet) > mtu and df_is_set(packet):
                        print("Packet is larger than MTU but DF is set\n")
                        ICMP_packet = ICMP_Error(3, 4, payload[0:28])
                        print("Sending ICMP error to internal host. Packet requires fragmentation but cannot fragment as DF is set\n")
                        internal_udp_sock.sendto(ICMP_packet, (LOCALHOST, real_client_port))
                

                if not is_ip_checksum_valid(payload):
                    print("Invalid IP checksum for outbound packet, packet dropped\n")
                    continue
                if not is_udp_checksum_valid(payload):
                    print("Invalid UDP checksum for outbound packet, packet dropped\n")
                    continue
                # Send ICMP error message to internal client if TTL expired
                if not valid_TTL(payload):
                    print(f"TTL expired, sending ICMP error back to internal host\n")
                    ICMP_packet = ICMP_Error(11, 0, payload[0:28])
                    internal_udp_sock.sendto(ICMP_packet, (LOCALHOST, real_client_port))
                    continue
            
            # Packets coming from external network -> inbound packets
            if interface == "WAN":
                now = datetime.now()
                timestamp = now.strftime("%H:%M:%S.%f")[:-3]
                print(f"Inbound packet coming from external network at time: {timestamp}\n")
                payload,external_address = sock.recvfrom(4096)
                _, external_port = external_address
                port_external = external_port

                # Check if IP checksum is valid
                if not is_ip_checksum_valid(payload):
                    print("IP checksum for inbound packet is not valid, dropping packet\n")
                    continue

                # Check if it is a fragment
                # We try to get the whole reassembled payload if possible. If not then
                # we move onto next packet received
                if mf_is_set(payload):
                    print("This is a fragment, requires reassembly\n")
                    payload = assemble_fragments(payload, False, time.time())
                    if not payload:
                        continue
                # Check if MF is not set and if the fragment has a non-zero byte offset. This means it is the last fragment
                elif not mf_is_set(payload) and is_last_fragment(payload):
                    print("This is the last fragment, requires reassembly\n")
                    payload = assemble_fragments(payload, True, time.time())
                    if not payload:
                        continue   
                # Only consider packets with valid IP, UDP checksums and TTL > 1
                if is_udp_checksum_valid(payload) and valid_TTL(payload):
                    # Grab destination IP and destination port for inbound packet
                    incoming_ip = payload[16:20]
                    incoming_port = payload[22:24]
                    incoming_ip_string = socket.inet_ntoa(incoming_ip)
                    incoming_port_int = struct.unpack("!H", incoming_port)[0]


                    curr_ip_checksum = struct.unpack("!H", payload[10:12])[0]
                    curr_udp_checksum = struct.unpack("!H", payload[26:28])[0]

                    print("This is an inbound packet. IP address before translation: " + incoming_ip_string + " \n")
                    print("This is an inbound packet, its port before translation is: " + str(incoming_port_int) + " \n")

                    print(f"IP checksum for inbound packet before translation: 0x{curr_ip_checksum:04x}\n")
                    print(f"UDP checksum for inbound packet before translation: 0x{curr_udp_checksum:04x}\n")

                    # Get the actual destination IP and port by doing a reverse translation
                    translated_ip, translated_port = address_port_translate(incoming_ip_string, incoming_port_int, False)

                    # If mapping has been idle for too long or doesn't exist, then discard packet
                    # We prevent any unsolicited packets from going in
                    # Also ignore any mappings that are idle so we don't have port exhaustion
                    if not translated_ip:
                        print("Mapping deleted or unsolicited packet arrived, dropping packet\n")
                        continue


                    print("Our translated IP address for our inbound packet is " + translated_ip + " \n")
                    print("Our translated port for our inbound packet is " + str(translated_port) + " \n")

                    # Assuming that logical port is not the real port used by client
                    # We retrieve the real port
                    real_to_send_port = LOGICAL_TO_REAL_PORT[translated_ip]
                    print("Just checking the real port to send to. It is " + str(real_to_send_port) + " \n")
                    
                    packet = bytearray(payload)

                    print("TTL before reduction: " + str(packet[8]) + " \n")
                    # Decrement TTL of packet
                    packet[8] -= 1

                    print("TTL after reduction: " + str(packet[8])+ " \n")

                    # Update the IP and port of the inbound packet
                    packet[16:20] = socket.inet_aton(translated_ip)
                    packet[22:24] = struct.pack("!H", translated_port)

                    # Zero out the IP checksum
                    packet[10:12] = b'\x00\x00'

                    # Calculate new IP and UDP checksum
                    new_ip_checksum = calculate_internet_checksum(packet[0:20])

                    new_udp_checksum = calculate_udp_checksum(packet)

                    print(f"New IP checksum after translation: 0x{new_ip_checksum:04x}\n")
                    print(f"New UDP checksum after translation: 0x{new_udp_checksum:04x}\n")
                    # Set the new checksums
                    packet[10:12] = struct.pack("!H", new_ip_checksum)
                    packet[26:28] = struct.pack("!H", new_udp_checksum)

                    mod_payload = bytes(packet)

                    # Send the inbound packet to proper internal client

                    print(f"Sending inbound packet to internal host {translated_ip} on port {translated_port}\n")
                    internal_udp_sock.sendto(mod_payload, (LOCALHOST, real_to_send_port))

                # Drop packet if UDP checksum not valid
                if not is_udp_checksum_valid(payload):
                    print("UDP checksum for inbound packet not valid, dropping packet\n")
                    continue
                # Send ICMP error message if TTL expired back to next hop
                if not valid_TTL(payload):
                    print("Not valid TTL, send an error back.\n")
                    ICMP_packet = ICMP_Error(11, 0, payload[0:28])
                    external_udp_sock.sendto(ICMP_packet, (LOCALHOST, external_port))
                    continue
                

        # Poll these delete functions to delete any idle mappings and timed out fragments
        # Ensures that we don't only rely on incoming packets to then deleted timed out 
        # mappings or fragments            
        del_idle_maps()
        del_timed_out_fragments()
except KeyboardInterrupt:
    print("Shutting down")
finally:
    selector.close()