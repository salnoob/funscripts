import socket
import ConfigParser
import subprocess
from struct import unpack

BUFFSIZE = 65535
# Set empty dict ?? Is this correct or use dict()
conns = {}
defaults = {
'clearport':'1400',
'ports':'1414,1515,1616',
'command':'echo Worked',
'udptcp':'udp',
'distractions':'True',
'outfile':'/tmp/out.txt',
'debug':'False'
}
config = ConfigParser.ConfigParser(defaults)
config.read("/etc/pk.cfg")

# Get from config file
portlist = [ int(x) for x in config.get('Ports','ports').split(",") ]
clearport = int(config.get('Ports','clearport'))
command = config.get('General','command') 
udptcp = config.get('General','udptcp')
distractions = config.getboolean('General','distractions')
outfile = config.get('IO','outfile')
debug = config.getboolean('IO','debug')

if debug:
  print "____ BEGIN CONFIG _____"
  print debug
  print portlist
  print command
  print udptcp 
  print distractions 
  print outfile 
  print clearport
  print "____ END CONFIG _____"

# For all ethernet. (TCP UDP ICMP ...)
#sock = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))

if udptcp == "udp":
    # UDP
    sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_UDP)
elif udptcp == "tcp": 
    # TCP
    sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
else:
    exit(1)

# Change to poll/select (if this is even needed since we are doing a read on a # socket...)
while 1:

    # Guess we don't need bind since raw reading
    packet,addr = sock.recvfrom(BUFFSIZE)

    # Not including options and padding
    ipheader= packet[:20]

    # Unpack the ip header
    iph = unpack('!BBHHHBBH4s4s',ipheader)

    # THanks to http://www.binarytides.com/python-packet-sniffer-code-linux/
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4

    if udptcp == "udp":
        # UDP
        udpheader = packet[iph_length:iph_length+8]
        udp_header = unpack('!HHHH',udpheader)
        srcport = udp_header[0]
        dstport = udp_header[1]
    else:    
        # TCP
        tcp_header = packet[iph_length:iph_length+20]
        tcpheader = unpack('!HHLLBBHHH',tcp_header)
        srcport = tcpheader[0]
        dstport = tcpheader[1]

    srcaddr = socket.inet_ntoa(iph[8])
    dstaddr = socket.inet_ntoa(iph[9])

    if dstport in portlist:
        if srcaddr not in conns:
            conns[srcaddr] = [dstport]
        else:
            conns[srcaddr].append(dstport)     
        
        if debug == True:
            print "SOURCE %s:%d" % (srcaddr,srcport)
            print "DESTINATION %s:%d" % (dstaddr,dstport)
            print "CONNS: %s" % conns

        if conns[srcaddr] == portlist:
            # Knock has been accepted
            fd = open(outfile,"wb")
            if debug: print command.format(srcaddr,srcport,dstaddr,dstport)
            subprocess.call(command.format(srcaddr,srcport,dstaddr,dstport).split(),stdout=fd) 
            if debug: print "after call"
            fd.close()

    else:
        # Reset on in-between connections (distraction knocks)
        if not distractions:
            conns[srcaddr] = list()
        # If using distractions, we need a way to reset our list
        elif int(dstport) == clearport:
            conns[srcaddr] = list()
            
sock.close()
