"""Packet sniffer in python For Linux
"""
import struct
import socket

RECV_BUFFER = 65565
_HEADER_LENGTH = 20
_HEADER_FORMAT = '!BBHHHBBHBBBBBBBB'

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# receive a packet
while True:
    packet, address = sock.recvfrom(RECV_BUFFER)
    
    header = struct.unpack(_HEADER_FORMAT, packet[:_HEADER_LENGTH])
    print(header)

    version_ihl = header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    header_length = ihl * 4
    ttl = header[5]
    protocol = header[6]
    s_addr = header[8] # socket.inet_ntoa(header[8])
    d_addr = header[9] #socket.inet_ntoa(header[9])
    
    print(
        'IP -> Version:' + str(version) + ', Header Length:' + str(header_length)
        + ', TTL:' + str(ttl) + ', Protocol:' + str(protocol) + ', Source:'
        + str(s_addr) + ', Destination:' + str(d_addr)
    )


 
    # { 
    #     'source_ip': <>,
    #     'dest_ip': <>,
    #     'source_port': <>,
    #     'dest_port': <>,
    #     'timestamp': <>,
    #     'total_length': <input>,
    #     'cache_flag': <input>,
    #     'steps_flag': <input>,
    #     'type_flag': <input>,
    #     'status_code': <input>,
    #     'cache_control': <input>,
    #     'data': <input>
    # }

    # if(header[6]==6):
    #     print('Protocol = TCP')
    # elif(header[6]==17):
    #     print('Protocol = UDP')
    # elif(header[5]==1):
    #     print('Protocol = ICMP')
    # else:
    #     print('Undefined')
