# Hand-verified PE (91dcf7d4...) <-> ARM ELF (24f61120...) function pairs, from reading the
# decompiled code of both. Same routine, same protocol role, same constants/record layout.
STRICT = {
    0x4040F0: 0xA4C6,  # fill buffer with rand() bytes
    0x404120: 0xA4E4,  # reverse n bytes (24-bit length endianness)
    0x404150: 0xA508,  # select() wait on the socket with timeout
    0x404410: 0xA564,  # send_all loop (chunked)
    0x404480: 0xA598,  # recv_all loop, select-wait before each recv
    0x404590: 0xA5D8,  # send TLS record: type, version 0x0301, len, then payload
    0x404640: 0xA664,  # recv TLS record: header, check type and version 0x0301
    0x4044F0: 0xA624,  # send handshake message (record type 0x16), 24-bit length fixup
    0x404540: 0xA6F4,  # recv handshake message (0x16), 24-bit length fixup
    0x404850: 0xA730,  # parse ServerHello: session id len 0x20/0, read cipher suite
    0x4048A0: 0xA768,  # build fake ClientHello (random, session id, cipher list, SNI)
    0x405270: 0xAA60,  # build ClientKeyExchange (0x10), 0xc014 -> 0x61 / 0x41, 0x35 -> 0x100
    0x404700: 0xAAD0,  # fake TLS handshake driver (hello, 3 reads, CKE, CCS 0x14, finished 0x16)
    0x402440: 0x9110,  # graceful disconnect: SO_LINGER, shutdown, close
}
# Same role, different implementation (command protocol differs: PE 0x80xx, ELF 0x52xx).
LOOSE = {
    0x405370: 0xA378,  # main beacon loop
    0x405650: 0xA288,  # command receive loop (ELF function not recovered by SMDA)
    0x405910: 0x9F8C,  # connect to a C2 from the list and handshake
}
