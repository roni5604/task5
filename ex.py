#Packet sniffer in python
#For Linux
import struct
import socket

_TCP_HEADER = 6
_UDP_HEADER = 6
_ICMP_HEADER = 6

#create an INET, raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# receive a packet
while True:
    data = s.recvfrom(65565)
    packet=data[0]
    address= data[1]
    header=struct.unpack('!BBHHHBBHBBBBBBBB', packet[:20])
    print(header)
    # if(header[6]==6):
    #     print("Protocol = TCP")
    # elif(header[6]==17):
    #     print("Protocol = UDP")
    # elif(header[5]==1):
    #     print("Protocol = ICMP")