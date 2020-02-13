import socket
import sys
import struct
import re
from pythonosc import osc_message_builder
from pythonosc import udp_client

#recieve data
def recieveData(s):
    data = ''
    try:
        data = s.recvfrom(65565)
    except socket.timeout:
        data = ''
    except:
        print ("Error occurred")
        sys.exc_info()
    return data[0]

# get the time of service - 8 bits
def getTOS(data):
    precedence = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash", 4: "Flash override", 5: "CRITIC/ECP",
                  6: "Internetwork control", 7: "Network control"}
    delay = {0: "Normal delay", 1: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}

    D = data & 0x10
    D >>= 4
    T = data & 0x8
    T >>= 8
    R = data & 0x4
    R >>= 2
    M = data & 0x2
    M >>= 1

    tabs = '\n\t\t\t'
    TOS = precedence[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + reliability[R] + tabs + cost[M]
    return(TOS)

def getFlags(data):
    flagR = {0: '0 - Reserved bit'}
    flagDF = {0: '0 - Fragment if necessary', 1: '1 - Do not fragment'}
    flagMF = {0: '0 - Last fragment', 1: '1 - More fragments'}

    R = data & 0x8000
    R >>= 15
    DF = data & 0x4000
    DF >>= 14
    MF = data & 0x2000
    MF >>= 13

    tabs = '\n\t\t\t'
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return (flags)

def getProtocol(protocolNr):
    protocolFile = open('Protocols.txt', 'r')
    protocolData = protocolFile.read()
    protocol = re.findall(r'\n' + str(protocolNr) + ' (?:.)+\n', protocolData)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace('\n', '')
        protocol = protocol.replace(str(protocolNr), '')
        protocol = protocol.lstrip()
        return protocol
    else:
        return "No such protocol."


# the public network interface
HOST = socket.gethostbyname(socket.gethostname())

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# UDP Send
client = udp_client.UDPClient('127.0.0.1', 7300)

while True:
    data = recieveData(s)
    unpackedData = struct.unpack('!BBHHHBBH4s4s', data[:20])

    version_IHL = unpackedData[0]
    version = version_IHL >> 4
    IHL = version_IHL & 0xF
    TOS = unpackedData[1]
    totalLength = unpackedData[2]
    ID = unpackedData[3]
    flags = unpackedData[4]
    fragmentOffset = unpackedData[4] & 0x1FFF
    TTL = unpackedData[5]
    protocolNr = unpackedData[6]
    checksum = unpackedData[7]
    sourceAddress = socket.inet_ntoa(unpackedData[8])
    destinationAddress = socket.inet_ntoa(unpackedData[9])

    print("An IP packet with the size " + str(totalLength) + " was captured.")
    print("Raw data: " + str(data))
    print("\nParsed data")
    print("Version:\t\t\t" + str(version))
    print("Header Length:\t\t" + str(IHL*4) + ' bytes')
    print("Type of Service:\t" + getTOS(TOS))
    print("Length\t\t" + str(totalLength))
    print("ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ")")
    print("Flags:\t\t" + getFlags(flags))
    print("Fragment offset:\t" + str(fragmentOffset))
    print("TTL:\t\t\t" + str(TTL))
    print("Protocol:\t\t" + getProtocol(protocolNr))
    print("Checksum:\t\t" + str(checksum))
    print("Source:\t\t\t" + sourceAddress)
    print("Destination\t\t" + destinationAddress)
    print("Payload:\n" + str(data[20:]))

    ipNoteVal = [int(s) for s in re.findall(r'\b\d+\b', sourceAddress)]
    ipNoteVal = sum(ipNoteVal)
    ipNoteVal = int(ipNoteVal * 0.101)

    client = udp_client.UDPClient('127.0.0.1', 7300)
    msg = osc_message_builder.OscMessageBuilder(address='Note')
    msg.add_arg(ipNoteVal)
    msg.add_arg(127)
    #ICMP
    if protocolNr == 1:
        msg.add_arg(74)
    #TCP
    elif protocolNr == 6:
        msg.add_arg(14)
    #UDP
    elif protocolNr == 17:
        msg.add_arg(24)
    else:
        msg.add_arg(1)
    msg = msg.build()
    client.send(msg)
