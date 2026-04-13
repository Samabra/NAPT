"""
Pre-crafted logical UDP/IPv4 packets for NAT testing.

Version: 1.0
"""

# Disable autopep8/black auto-formatting to keep comment alignment.
# fmt: off
packets = [
    # 10.0.0.2:5001 â†’ 203.0.113.1:80  payload=b'A'
    (
        # --- IPv4 header (20 bytes) ---
        b'\x45'                 # Version=4, IHL=5
        b'\x00'                 # DSCP/ECN
        b'\x00\x1d'             # Total Length = 29
        b'\x00\x01'             # Identification = 1
        b'\x00\x00'             # Flags: R=0, DF=0, MF=0; Offset=0
        b'\x40'                 # TTL = 64
        b'\x11'                 # Protocol = 17 (UDP)
        b'\x34\xcc'             # Header checksum = 0x34cc
        b'\x0a\x00\x00\x02'     # Source IP = 10.0.0.2
        b'\xcb\x00\x71\x01'     # Dest IP   = 203.0.113.1

        # --- UDP header (8 bytes) ---
        b'\x13\x89'             # Source port = 5001
        b'\x00\x50'             # Dest port   = 80
        b'\x00\x09'             # Length = 9
        b'\x64\xff'             # Checksum = 0x64ff

        # --- Payload (1 byte) ---
        b'\x41'                 # b'A'
    )
    ,
    # 10.0.0.2:5001 â†’ 203.0.113.1:80  payload=b'B'
    (
        # --- IPv4 header (20 bytes) ---
        b'\x45'                 # Version=4, IHL=5
        b'\x00'                 # DSCP/ECN
        b'\x00\x1d'             # Total Length = 29
        b'\x00\x02'             # Identification = 2
        b'\x00\x00'             # Flags: R=0, DF=0, MF=0; Offset=0
        b'\x40'                 # TTL = 64
        b'\x11'                 # Protocol = 17 (UDP)
        b'\x34\xcb'             # Header checksum = 0x34cb
        b'\x0a\x00\x00\x02'     # Source IP = 10.0.0.2
        b'\xcb\x00\x71\x01'     # Dest IP   = 203.0.113.1

        # --- UDP header (8 bytes) ---
        b'\x13\x89'             # Source port = 5001
        b'\x00\x50'             # Dest port   = 80
        b'\x00\x09'             # Length = 9
        b'\x63\xff'             # Checksum = 0x63ff

        # --- Payload (1 byte) ---
        b'\x42'                 # b'B'
    )
    ,
    # 10.0.0.2:5002 â†’ 203.0.113.1:80  payload=b'C'
    (
        # --- IPv4 header (20 bytes) ---
        b'\x45'                 # Version=4, IHL=5
        b'\x00'                 # DSCP/ECN
        b'\x00\x1d'             # Total Length = 29
        b'\x00\x03'             # Identification = 3
        b'\x00\x00'             # Flags: R=0, DF=0, MF=0; Offset=0
        b'\x40'                 # TTL = 64
        b'\x11'                 # Protocol = 17 (UDP)
        b'\x34\xca'             # Header checksum = 0x34ca
        b'\x0a\x00\x00\x02'     # Source IP = 10.0.0.2
        b'\xcb\x00\x71\x01'     # Dest IP   = 203.0.113.1

        # --- UDP header (8 bytes) ---
        b'\x13\x8a'             # Source port = 5002
        b'\x00\x50'             # Dest port   = 80
        b'\x00\x09'             # Length = 9
        b'\x62\xfe'             # Checksum = 0x62fe

        # --- Payload (1 byte) ---
        b'\x43'                 # b'C'
    )
    ,
    # 10.0.0.3:5001 â†’ 203.0.113.1:80  payload=b'D'
    (
        # --- IPv4 header (20 bytes) ---
        b'\x45'                 # Version=4, IHL=5
        b'\x00'                 # DSCP/ECN
        b'\x00\x1d'             # Total Length = 29
        b'\x00\x04'             # Identification = 4
        b'\x00\x00'             # Flags: R=0, DF=0, MF=0; Offset=0
        b'\x40'                 # TTL = 64
        b'\x11'                 # Protocol = 17 (UDP)
        b'\x34\xc8'             # Header checksum = 0x34c8
        b'\x0a\x00\x00\x03'     # Source IP = 10.0.0.3
        b'\xcb\x00\x71\x01'     # Dest IP   = 203.0.113.1

        # --- UDP header (8 bytes) ---
        b'\x13\x89'             # Source port = 5001
        b'\x00\x50'             # Dest port   = 80
        b'\x00\x09'             # Length = 9
        b'\x61\xfe'             # Checksum = 0x61fe

        # --- Payload (1 byte) ---
        b'\x44'                 # b'D'
    )
    ,
    # 10.0.0.2:1234 â†’ 1.1.1.1:53  payload=b'Good luck with the COMP3331/9331 assignment!'
    (
        # --- IPv4 header (20 bytes) ---
        b'\x45'                 # Version=4, IHL=5
        b'\x00'                 # DSCP/ECN
        b'\x00\x48'             # Total Length = 72
        b'\x00\x05'             # Identification = 5
        b'\x00\x00'             # Flags: R=0, DF=0, MF=0; Offset=0
        b'\x40'                 # TTL = 64
        b'\x11'                 # Protocol = 17 (UDP)
        b'\x6e\x9d'             # Header checksum = 0x6e9d
        b'\x0a\x00\x00\x02'     # Source IP = 10.0.0.2
        b'\x01\x01\x01\x01'     # Dest IP   = 1.1.1.1

        # --- UDP header (8 bytes) ---
        b'\x04\xd2'             # Source port = 1234
        b'\x00\x35'             # Dest port   = 53
        b'\x00\x34'             # Length = 52
        b'\xec\x48'             # Checksum = 0xec48

        # --- Payload (44 bytes) ---
        b'\x47\x6f\x6f\x64'     # b'Good'
        b'\x20\x6c\x75\x63'     # b' luc'
        b'\x6b\x20\x77\x69'     # b'k wi'
        b'\x74\x68\x20\x74'     # b'th t'
        b'\x68\x65\x20\x43'     # b'he C'
        b'\x4f\x4d\x50\x33'     # b'OMP3'
        b'\x33\x33\x31\x2f'     # b'331/'
        b'\x39\x33\x33\x31'     # b'9331'
        b'\x20\x61\x73\x73'     # b' ass'
        b'\x69\x67\x6e\x6d'     # b'ignm'
        b'\x65\x6e\x74\x21'     # b'ent!'
    )
    ,
    # 10.0.0.2:1234 â†’ 1.1.1.1:53  payload=b'I only have a short time to live :('
    (
        # --- IPv4 header (20 bytes) ---
        b'\x45'                 # Version=4, IHL=5
        b'\x00'                 # DSCP/ECN
        b'\x00\x3f'             # Total Length = 63
        b'\x00\x06'             # Identification = 6
        b'\x00\x00'             # Flags: R=0, DF=0, MF=0; Offset=0
        b'\x01'                 # TTL = 1
        b'\x11'                 # Protocol = 17 (UDP)
        b'\xad\xa5'             # Header checksum = 0xada5
        b'\x0a\x00\x00\x02'     # Source IP = 10.0.0.2
        b'\x01\x01\x01\x01'     # Dest IP   = 1.1.1.1

        # --- UDP header (8 bytes) ---
        b'\x04\xd2'             # Source port = 1234
        b'\x00\x35'             # Dest port   = 53
        b'\x00\x2b'             # Length = 43
        b'\x8d\xfe'             # Checksum = 0x8dfe

        # --- Payload (35 bytes) ---
        b'\x49\x20\x6f\x6e'     # b'I on'
        b'\x6c\x79\x20\x68'     # b'ly h'
        b'\x61\x76\x65\x20'     # b'ave '
        b'\x61\x20\x73\x68'     # b'a sh'
        b'\x6f\x72\x74\x20'     # b'ort '
        b'\x74\x69\x6d\x65'     # b'time'
        b'\x20\x74\x6f\x20'     # b' to '
        b'\x6c\x69\x76\x65'     # b'live'
        b'\x20\x3a\x28'         # b' :('
    )
    ,
    # 10.0.0.2:1234 â†’ 8.8.8.8:53  payload=b'My IP checksum should fail :('
    (
        # --- IPv4 header (20 bytes) ---
        b'\x45'                 # Version=4, IHL=5
        b'\x00'                 # DSCP/ECN
        b'\x00\x39'             # Total Length = 57
        b'\x00\x07'             # Identification = 7
        b'\x00\x00'             # Flags: R=0, DF=0, MF=0; Offset=0
        b'\x40'                 # TTL = 64
        b'\x11'                 # Protocol = 17 (UDP)
        b'\x60\x94'             # Header checksum = 0x6094 (INVALID)
        b'\x0a\x00\x00\x02'     # Source IP = 10.0.0.2
        b'\x08\x08\x08\x08'     # Dest IP   = 8.8.8.8

        # --- UDP header (8 bytes) ---
        b'\x04\xd2'             # Source port = 1234
        b'\x00\x35'             # Dest port   = 53
        b'\x00\x25'             # Length = 37
        b'\xfe\x84'             # Checksum = 0xfe84

        # --- Payload (29 bytes) ---
        b'\x4d\x79\x20\x49'     # b'My I'
        b'\x50\x20\x63\x68'     # b'P ch'
        b'\x65\x63\x6b\x73'     # b'ecks'
        b'\x75\x6d\x20\x73'     # b'um s'
        b'\x68\x6f\x75\x6c'     # b'houl'
        b'\x64\x20\x66\x61'     # b'd fa'
        b'\x69\x6c\x20\x3a'     # b'il :'
        b'\x28'                 # b'('
    )
    ,
    # 10.0.0.2:1234 â†’ 8.8.8.8:53  payload=b'My UDP checksum should fail :('
    (
        # --- IPv4 header (20 bytes) ---
        b'\x45'                 # Version=4, IHL=5
        b'\x00'                 # DSCP/ECN
        b'\x00\x3a'             # Total Length = 58
        b'\x00\x08'             # Identification = 8
        b'\x00\x00'             # Flags: R=0, DF=0, MF=0; Offset=0
        b'\x40'                 # TTL = 64
        b'\x11'                 # Protocol = 17 (UDP)
        b'\x60\x9a'             # Header checksum = 0x609a
        b'\x0a\x00\x00\x02'     # Source IP = 10.0.0.2
        b'\x08\x08\x08\x08'     # Dest IP   = 8.8.8.8

        # --- UDP header (8 bytes) ---
        b'\x04\xd2'             # Source port = 1234
        b'\x00\x35'             # Dest port   = 53
        b'\x00\x26'             # Length = 38
        b'\xea\x47'             # Checksum = 0xea47 (INVALID)

        # --- Payload (30 bytes) ---
        b'\x4d\x79\x20\x55'     # b'My U'
        b'\x44\x50\x20\x63'     # b'DP c'
        b'\x68\x65\x63\x6b'     # b'heck'
        b'\x73\x75\x6d\x20'     # b'sum '
        b'\x73\x68\x6f\x75'     # b'shou'
        b'\x6c\x64\x20\x66'     # b'ld f'
        b'\x61\x69\x6c\x20'     # b'ail '
        b'\x3a\x28'             # b':('
    )
    ,
    # 10.0.0.2:1234 â†’ 8.8.8.8:53  payload=996 bytes
    (
        # --- IPv4 header (20 bytes) ---
        b'\x45'                 # Version=4, IHL=5
        b'\x00'                 # DSCP/ECN
        b'\x04\x00'             # Total Length = 1024
        b'\x00\x09'             # Identification = 9
        b'\x00\x00'             # Flags: R=0, DF=0, MF=0; Offset=0
        b'\x40'                 # TTL = 64
        b'\x11'                 # Protocol = 17 (UDP)
        b'\x5c\xd3'             # Header checksum = 0x5cd3
        b'\x0a\x00\x00\x02'     # Source IP = 10.0.0.2
        b'\x08\x08\x08\x08'     # Dest IP   = 8.8.8.8

        # --- UDP header (8 bytes) ---
        b'\x04\xd2'             # Source port = 1234
        b'\x00\x35'             # Dest port   = 53
        b'\x03\xec'             # Length = 1004
        b'\x13\x48'             # Checksum = 0x1348

        # --- Payload (996 bytes) ---
        b'\x00\x01\x02\x03'     # bytes 28-31 (....)
        b'\x04\x05\x06\x07'     # bytes 32-35 (....)
        b'\x08\x09\x0a\x0b'     # bytes 36-39 (....)
        b'\x0c\x0d\x0e\x0f'     # bytes 40-43 (....)
        b'\x10\x11\x12\x13'     # bytes 44-47 (....)
        b'\x14\x15\x16\x17'     # bytes 48-51 (....)
        b'\x18\x19\x1a\x1b'     # bytes 52-55 (....)
        b'\x1c\x1d\x1e\x1f'     # bytes 56-59 (....)
        b'\x20\x21\x22\x23'     # bytes 60-63 ( !"#)
        b'\x24\x25\x26\x27'     # bytes 64-67 ($%&')
        b'\x28\x29\x2a\x2b'     # bytes 68-71 (()*+)
        b'\x2c\x2d\x2e\x2f'     # bytes 72-75 (,-./)
        b'\x30\x31\x32\x33'     # bytes 76-79 (0123)
        b'\x34\x35\x36\x37'     # bytes 80-83 (4567)
        b'\x38\x39\x3a\x3b'     # bytes 84-87 (89:;)
        b'\x3c\x3d\x3e\x3f'     # bytes 88-91 (<=>?)
        b'\x40\x41\x42\x43'     # bytes 92-95 (@ABC)
        b'\x44\x45\x46\x47'     # bytes 96-99 (DEFG)
        b'\x48\x49\x4a\x4b'     # bytes 100-103 (HIJK)
        b'\x4c\x4d\x4e\x4f'     # bytes 104-107 (LMNO)
        b'\x50\x51\x52\x53'     # bytes 108-111 (PQRS)
        b'\x54\x55\x56\x57'     # bytes 112-115 (TUVW)
        b'\x58\x59\x5a\x5b'     # bytes 116-119 (XYZ[)
        b'\x5c\x5d\x5e\x5f'     # bytes 120-123 (\]^_)
        b'\x60\x61\x62\x63'     # bytes 124-127 (`abc)
        b'\x64\x65\x66\x67'     # bytes 128-131 (defg)
        b'\x68\x69\x6a\x6b'     # bytes 132-135 (hijk)
        b'\x6c\x6d\x6e\x6f'     # bytes 136-139 (lmno)
        b'\x70\x71\x72\x73'     # bytes 140-143 (pqrs)
        b'\x74\x75\x76\x77'     # bytes 144-147 (tuvw)
        b'\x78\x79\x7a\x7b'     # bytes 148-151 (xyz{)
        b'\x7c\x7d\x7e\x7f'     # bytes 152-155 (|}~.)
        b'\x80\x81\x82\x83'     # bytes 156-159 (....)
        b'\x84\x85\x86\x87'     # bytes 160-163 (....)
        b'\x88\x89\x8a\x8b'     # bytes 164-167 (....)
        b'\x8c\x8d\x8e\x8f'     # bytes 168-171 (....)
        b'\x90\x91\x92\x93'     # bytes 172-175 (....)
        b'\x94\x95\x96\x97'     # bytes 176-179 (....)
        b'\x98\x99\x9a\x9b'     # bytes 180-183 (....)
        b'\x9c\x9d\x9e\x9f'     # bytes 184-187 (....)
        b'\xa0\xa1\xa2\xa3'     # bytes 188-191 (....)
        b'\xa4\xa5\xa6\xa7'     # bytes 192-195 (....)
        b'\xa8\xa9\xaa\xab'     # bytes 196-199 (....)
        b'\xac\xad\xae\xaf'     # bytes 200-203 (....)
        b'\xb0\xb1\xb2\xb3'     # bytes 204-207 (....)
        b'\xb4\xb5\xb6\xb7'     # bytes 208-211 (....)
        b'\xb8\xb9\xba\xbb'     # bytes 212-215 (....)
        b'\xbc\xbd\xbe\xbf'     # bytes 216-219 (....)
        b'\xc0\xc1\xc2\xc3'     # bytes 220-223 (....)
        b'\xc4\xc5\xc6\xc7'     # bytes 224-227 (....)
        b'\xc8\xc9\xca\xcb'     # bytes 228-231 (....)
        b'\xcc\xcd\xce\xcf'     # bytes 232-235 (....)
        b'\xd0\xd1\xd2\xd3'     # bytes 236-239 (....)
        b'\xd4\xd5\xd6\xd7'     # bytes 240-243 (....)
        b'\xd8\xd9\xda\xdb'     # bytes 244-247 (....)
        b'\xdc\xdd\xde\xdf'     # bytes 248-251 (....)
        b'\xe0\xe1\xe2\xe3'     # bytes 252-255 (....)
        b'\xe4\xe5\xe6\xe7'     # bytes 256-259 (....)
        b'\xe8\xe9\xea\xeb'     # bytes 260-263 (....)
        b'\xec\xed\xee\xef'     # bytes 264-267 (....)
        b'\xf0\xf1\xf2\xf3'     # bytes 268-271 (....)
        b'\xf4\xf5\xf6\xf7'     # bytes 272-275 (....)
        b'\xf8\xf9\xfa\xfb'     # bytes 276-279 (....)
        b'\xfc\xfd\xfe\xff'     # bytes 280-283 (....)
        b'\x00\x01\x02\x03'     # bytes 284-287 (....)
        b'\x04\x05\x06\x07'     # bytes 288-291 (....)
        b'\x08\x09\x0a\x0b'     # bytes 292-295 (....)
        b'\x0c\x0d\x0e\x0f'     # bytes 296-299 (....)
        b'\x10\x11\x12\x13'     # bytes 300-303 (....)
        b'\x14\x15\x16\x17'     # bytes 304-307 (....)
        b'\x18\x19\x1a\x1b'     # bytes 308-311 (....)
        b'\x1c\x1d\x1e\x1f'     # bytes 312-315 (....)
        b'\x20\x21\x22\x23'     # bytes 316-319 ( !"#)
        b'\x24\x25\x26\x27'     # bytes 320-323 ($%&')
        b'\x28\x29\x2a\x2b'     # bytes 324-327 (()*+)
        b'\x2c\x2d\x2e\x2f'     # bytes 328-331 (,-./)
        b'\x30\x31\x32\x33'     # bytes 332-335 (0123)
        b'\x34\x35\x36\x37'     # bytes 336-339 (4567)
        b'\x38\x39\x3a\x3b'     # bytes 340-343 (89:;)
        b'\x3c\x3d\x3e\x3f'     # bytes 344-347 (<=>?)
        b'\x40\x41\x42\x43'     # bytes 348-351 (@ABC)
        b'\x44\x45\x46\x47'     # bytes 352-355 (DEFG)
        b'\x48\x49\x4a\x4b'     # bytes 356-359 (HIJK)
        b'\x4c\x4d\x4e\x4f'     # bytes 360-363 (LMNO)
        b'\x50\x51\x52\x53'     # bytes 364-367 (PQRS)
        b'\x54\x55\x56\x57'     # bytes 368-371 (TUVW)
        b'\x58\x59\x5a\x5b'     # bytes 372-375 (XYZ[)
        b'\x5c\x5d\x5e\x5f'     # bytes 376-379 (\]^_)
        b'\x60\x61\x62\x63'     # bytes 380-383 (`abc)
        b'\x64\x65\x66\x67'     # bytes 384-387 (defg)
        b'\x68\x69\x6a\x6b'     # bytes 388-391 (hijk)
        b'\x6c\x6d\x6e\x6f'     # bytes 392-395 (lmno)
        b'\x70\x71\x72\x73'     # bytes 396-399 (pqrs)
        b'\x74\x75\x76\x77'     # bytes 400-403 (tuvw)
        b'\x78\x79\x7a\x7b'     # bytes 404-407 (xyz{)
        b'\x7c\x7d\x7e\x7f'     # bytes 408-411 (|}~.)
        b'\x80\x81\x82\x83'     # bytes 412-415 (....)
        b'\x84\x85\x86\x87'     # bytes 416-419 (....)
        b'\x88\x89\x8a\x8b'     # bytes 420-423 (....)
        b'\x8c\x8d\x8e\x8f'     # bytes 424-427 (....)
        b'\x90\x91\x92\x93'     # bytes 428-431 (....)
        b'\x94\x95\x96\x97'     # bytes 432-435 (....)
        b'\x98\x99\x9a\x9b'     # bytes 436-439 (....)
        b'\x9c\x9d\x9e\x9f'     # bytes 440-443 (....)
        b'\xa0\xa1\xa2\xa3'     # bytes 444-447 (....)
        b'\xa4\xa5\xa6\xa7'     # bytes 448-451 (....)
        b'\xa8\xa9\xaa\xab'     # bytes 452-455 (....)
        b'\xac\xad\xae\xaf'     # bytes 456-459 (....)
        b'\xb0\xb1\xb2\xb3'     # bytes 460-463 (....)
        b'\xb4\xb5\xb6\xb7'     # bytes 464-467 (....)
        b'\xb8\xb9\xba\xbb'     # bytes 468-471 (....)
        b'\xbc\xbd\xbe\xbf'     # bytes 472-475 (....)
        b'\xc0\xc1\xc2\xc3'     # bytes 476-479 (....)
        b'\xc4\xc5\xc6\xc7'     # bytes 480-483 (....)
        b'\xc8\xc9\xca\xcb'     # bytes 484-487 (....)
        b'\xcc\xcd\xce\xcf'     # bytes 488-491 (....)
        b'\xd0\xd1\xd2\xd3'     # bytes 492-495 (....)
        b'\xd4\xd5\xd6\xd7'     # bytes 496-499 (....)
        b'\xd8\xd9\xda\xdb'     # bytes 500-503 (....)
        b'\xdc\xdd\xde\xdf'     # bytes 504-507 (....)
        b'\xe0\xe1\xe2\xe3'     # bytes 508-511 (....)
        b'\xe4\xe5\xe6\xe7'     # bytes 512-515 (....)
        b'\xe8\xe9\xea\xeb'     # bytes 516-519 (....)
        b'\xec\xed\xee\xef'     # bytes 520-523 (....)
        b'\xf0\xf1\xf2\xf3'     # bytes 524-527 (....)
        b'\xf4\xf5\xf6\xf7'     # bytes 528-531 (....)
        b'\xf8\xf9\xfa\xfb'     # bytes 532-535 (....)
        b'\xfc\xfd\xfe\xff'     # bytes 536-539 (....)
        b'\x00\x01\x02\x03'     # bytes 540-543 (....)
        b'\x04\x05\x06\x07'     # bytes 544-547 (....)
        b'\x08\x09\x0a\x0b'     # bytes 548-551 (....)
        b'\x0c\x0d\x0e\x0f'     # bytes 552-555 (....)
        b'\x10\x11\x12\x13'     # bytes 556-559 (....)
        b'\x14\x15\x16\x17'     # bytes 560-563 (....)
        b'\x18\x19\x1a\x1b'     # bytes 564-567 (....)
        b'\x1c\x1d\x1e\x1f'     # bytes 568-571 (....)
        b'\x20\x21\x22\x23'     # bytes 572-575 ( !"#)
        b'\x24\x25\x26\x27'     # bytes 576-579 ($%&')
        b'\x28\x29\x2a\x2b'     # bytes 580-583 (()*+)
        b'\x2c\x2d\x2e\x2f'     # bytes 584-587 (,-./)
        b'\x30\x31\x32\x33'     # bytes 588-591 (0123)
        b'\x34\x35\x36\x37'     # bytes 592-595 (4567)
        b'\x38\x39\x3a\x3b'     # bytes 596-599 (89:;)
        b'\x3c\x3d\x3e\x3f'     # bytes 600-603 (<=>?)
        b'\x40\x41\x42\x43'     # bytes 604-607 (@ABC)
        b'\x44\x45\x46\x47'     # bytes 608-611 (DEFG)
        b'\x48\x49\x4a\x4b'     # bytes 612-615 (HIJK)
        b'\x4c\x4d\x4e\x4f'     # bytes 616-619 (LMNO)
        b'\x50\x51\x52\x53'     # bytes 620-623 (PQRS)
        b'\x54\x55\x56\x57'     # bytes 624-627 (TUVW)
        b'\x58\x59\x5a\x5b'     # bytes 628-631 (XYZ[)
        b'\x5c\x5d\x5e\x5f'     # bytes 632-635 (\]^_)
        b'\x60\x61\x62\x63'     # bytes 636-639 (`abc)
        b'\x64\x65\x66\x67'     # bytes 640-643 (defg)
        b'\x68\x69\x6a\x6b'     # bytes 644-647 (hijk)
        b'\x6c\x6d\x6e\x6f'     # bytes 648-651 (lmno)
        b'\x70\x71\x72\x73'     # bytes 652-655 (pqrs)
        b'\x74\x75\x76\x77'     # bytes 656-659 (tuvw)
        b'\x78\x79\x7a\x7b'     # bytes 660-663 (xyz{)
        b'\x7c\x7d\x7e\x7f'     # bytes 664-667 (|}~.)
        b'\x80\x81\x82\x83'     # bytes 668-671 (....)
        b'\x84\x85\x86\x87'     # bytes 672-675 (....)
        b'\x88\x89\x8a\x8b'     # bytes 676-679 (....)
        b'\x8c\x8d\x8e\x8f'     # bytes 680-683 (....)
        b'\x90\x91\x92\x93'     # bytes 684-687 (....)
        b'\x94\x95\x96\x97'     # bytes 688-691 (....)
        b'\x98\x99\x9a\x9b'     # bytes 692-695 (....)
        b'\x9c\x9d\x9e\x9f'     # bytes 696-699 (....)
        b'\xa0\xa1\xa2\xa3'     # bytes 700-703 (....)
        b'\xa4\xa5\xa6\xa7'     # bytes 704-707 (....)
        b'\xa8\xa9\xaa\xab'     # bytes 708-711 (....)
        b'\xac\xad\xae\xaf'     # bytes 712-715 (....)
        b'\xb0\xb1\xb2\xb3'     # bytes 716-719 (....)
        b'\xb4\xb5\xb6\xb7'     # bytes 720-723 (....)
        b'\xb8\xb9\xba\xbb'     # bytes 724-727 (....)
        b'\xbc\xbd\xbe\xbf'     # bytes 728-731 (....)
        b'\xc0\xc1\xc2\xc3'     # bytes 732-735 (....)
        b'\xc4\xc5\xc6\xc7'     # bytes 736-739 (....)
        b'\xc8\xc9\xca\xcb'     # bytes 740-743 (....)
        b'\xcc\xcd\xce\xcf'     # bytes 744-747 (....)
        b'\xd0\xd1\xd2\xd3'     # bytes 748-751 (....)
        b'\xd4\xd5\xd6\xd7'     # bytes 752-755 (....)
        b'\xd8\xd9\xda\xdb'     # bytes 756-759 (....)
        b'\xdc\xdd\xde\xdf'     # bytes 760-763 (....)
        b'\xe0\xe1\xe2\xe3'     # bytes 764-767 (....)
        b'\xe4\xe5\xe6\xe7'     # bytes 768-771 (....)
        b'\xe8\xe9\xea\xeb'     # bytes 772-775 (....)
        b'\xec\xed\xee\xef'     # bytes 776-779 (....)
        b'\xf0\xf1\xf2\xf3'     # bytes 780-783 (....)
        b'\xf4\xf5\xf6\xf7'     # bytes 784-787 (....)
        b'\xf8\xf9\xfa\xfb'     # bytes 788-791 (....)
        b'\xfc\xfd\xfe\xff'     # bytes 792-795 (....)
        b'\x00\x01\x02\x03'     # bytes 796-799 (....)
        b'\x04\x05\x06\x07'     # bytes 800-803 (....)
        b'\x08\x09\x0a\x0b'     # bytes 804-807 (....)
        b'\x0c\x0d\x0e\x0f'     # bytes 808-811 (....)
        b'\x10\x11\x12\x13'     # bytes 812-815 (....)
        b'\x14\x15\x16\x17'     # bytes 816-819 (....)
        b'\x18\x19\x1a\x1b'     # bytes 820-823 (....)
        b'\x1c\x1d\x1e\x1f'     # bytes 824-827 (....)
        b'\x20\x21\x22\x23'     # bytes 828-831 ( !"#)
        b'\x24\x25\x26\x27'     # bytes 832-835 ($%&')
        b'\x28\x29\x2a\x2b'     # bytes 836-839 (()*+)
        b'\x2c\x2d\x2e\x2f'     # bytes 840-843 (,-./)
        b'\x30\x31\x32\x33'     # bytes 844-847 (0123)
        b'\x34\x35\x36\x37'     # bytes 848-851 (4567)
        b'\x38\x39\x3a\x3b'     # bytes 852-855 (89:;)
        b'\x3c\x3d\x3e\x3f'     # bytes 856-859 (<=>?)
        b'\x40\x41\x42\x43'     # bytes 860-863 (@ABC)
        b'\x44\x45\x46\x47'     # bytes 864-867 (DEFG)
        b'\x48\x49\x4a\x4b'     # bytes 868-871 (HIJK)
        b'\x4c\x4d\x4e\x4f'     # bytes 872-875 (LMNO)
        b'\x50\x51\x52\x53'     # bytes 876-879 (PQRS)
        b'\x54\x55\x56\x57'     # bytes 880-883 (TUVW)
        b'\x58\x59\x5a\x5b'     # bytes 884-887 (XYZ[)
        b'\x5c\x5d\x5e\x5f'     # bytes 888-891 (\]^_)
        b'\x60\x61\x62\x63'     # bytes 892-895 (`abc)
        b'\x64\x65\x66\x67'     # bytes 896-899 (defg)
        b'\x68\x69\x6a\x6b'     # bytes 900-903 (hijk)
        b'\x6c\x6d\x6e\x6f'     # bytes 904-907 (lmno)
        b'\x70\x71\x72\x73'     # bytes 908-911 (pqrs)
        b'\x74\x75\x76\x77'     # bytes 912-915 (tuvw)
        b'\x78\x79\x7a\x7b'     # bytes 916-919 (xyz{)
        b'\x7c\x7d\x7e\x7f'     # bytes 920-923 (|}~.)
        b'\x80\x81\x82\x83'     # bytes 924-927 (....)
        b'\x84\x85\x86\x87'     # bytes 928-931 (....)
        b'\x88\x89\x8a\x8b'     # bytes 932-935 (....)
        b'\x8c\x8d\x8e\x8f'     # bytes 936-939 (....)
        b'\x90\x91\x92\x93'     # bytes 940-943 (....)
        b'\x94\x95\x96\x97'     # bytes 944-947 (....)
        b'\x98\x99\x9a\x9b'     # bytes 948-951 (....)
        b'\x9c\x9d\x9e\x9f'     # bytes 952-955 (....)
        b'\xa0\xa1\xa2\xa3'     # bytes 956-959 (....)
        b'\xa4\xa5\xa6\xa7'     # bytes 960-963 (....)
        b'\xa8\xa9\xaa\xab'     # bytes 964-967 (....)
        b'\xac\xad\xae\xaf'     # bytes 968-971 (....)
        b'\xb0\xb1\xb2\xb3'     # bytes 972-975 (....)
        b'\xb4\xb5\xb6\xb7'     # bytes 976-979 (....)
        b'\xb8\xb9\xba\xbb'     # bytes 980-983 (....)
        b'\xbc\xbd\xbe\xbf'     # bytes 984-987 (....)
        b'\xc0\xc1\xc2\xc3'     # bytes 988-991 (....)
        b'\xc4\xc5\xc6\xc7'     # bytes 992-995 (....)
        b'\xc8\xc9\xca\xcb'     # bytes 996-999 (....)
        b'\xcc\xcd\xce\xcf'     # bytes 1000-1003 (....)
        b'\xd0\xd1\xd2\xd3'     # bytes 1004-1007 (....)
        b'\xd4\xd5\xd6\xd7'     # bytes 1008-1011 (....)
        b'\xd8\xd9\xda\xdb'     # bytes 1012-1015 (....)
        b'\xdc\xdd\xde\xdf'     # bytes 1016-1019 (....)
        b'\xe0\xe1\xe2\xe3'     # bytes 1020-1023 (....)
    )
    ,
]
# fmt: on
