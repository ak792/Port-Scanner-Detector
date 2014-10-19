import dpkt
import pcap
import collections
import sys
import socket

ip_ports = {}
flagged_ips = set()


def usage():
    print 'Usage: sudo python psdetect.py interface'


def get_args():
    #gets the network interface to listen on
    if len(sys.argv) != 2:
        usage()
        sys.exit()

    return sys.argv[1]


def capture_packets(interface):
    #listens for and records incoming connections
    #outputs any scanners detected

    try:
        #listen for TCP packets on the specified interface
        pc = pcap.pcap(interface)
        pc.setfilter('tcp')

        #for each incoming packet
        for ts, buf in pc:
            eth, ip, tcp = parse_packet(buf)
            if pkt_is_syn(tcp) and not socket.gethostname() == socket.gethostbyaddr(socket.inet_ntoa(ip.src))[0]:
                #record when a SYN packet is received from a remote host
                detect_on_syn_recv(ts, ip, tcp)

    except OSError:
        usage()
        print 'Ensure valid interface'
        sys.exit()


def parse_packet(buf):
    #parses packet into Ethernet, IP, and TCP packets
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data

    return eth, ip, tcp


def pkt_is_syn(tcp):
    #checks if SYN flag is set
    syn_bitmask = 2

    if tcp.flags & syn_bitmask:
        return True

    return False


def detect_on_syn_recv(ts, ip, tcp):
    #Flags IPs that connect to 15 consecutive ports consecutively in a 5 second window

    #Gets dotted notation for the source IP address
    ip_src_str = socket.inet_ntoa(ip.src)

    #Writes a record of the connection into a dict of deques
    #Keys are the source IP addresses
    #Values are deques of {port_num, timestamp} dicts
    if not ip_src_str in ip_ports:
        #If a new host connected, create a new entry in the dict
        consec_ports_deque = collections.deque()
        consec_ports_deque.append({'port_num': tcp.dport, 'ts': ts})
        ip_ports[ip_src_str] = consec_ports_deque
    else:
        #If a host reconnected, check if is the (at least) 15th consecutive port in the last 5 seconds

        #Checks if this connection was established to the next consecutive port
        if tcp.dport != ip_ports[ip_src_str][-1]['port_num'] + 1:
            #If not, clear the deque since our condition for flagging a scanner was not met
            ip_ports[ip_src_str].clear()
        else:
            #If so, remove any records of connections from more than 5 seconds ago from the deque
            while len(ip_ports[ip_src_str]) > 0 and ts - ip_ports[ip_src_str][0]['ts'] > 5:
                ip_ports[ip_src_str].popleft()

            #Checks if the host established connections to 15+
            #consecutive ports consecutively within the last 5 seconds
            #Note that the most recent connection was not recorded yet, so
            #we check if the length of the deque is >= 14 (rather than >=15)
            if len(ip_ports[ip_src_str]) >= 14 and ts - ip_ports[ip_src_str][0]['ts'] <= 5:
                if not ip_src_str in flagged_ips:
                    #Flags this IP address as a port scanner
                    flagged_ips.add(ip_src_str)
                    print 'Scanner detected. The scanner originated from host', ip_src_str

        #adds a record of the current connection to the current IP address' deque
        ip_ports[ip_src_str].append({'port_num': tcp.dport, 'ts': ts})


#Begin capturing incoming packets
try:
    interface = get_args()
    capture_packets(interface)
except KeyboardInterrupt:
    print '\nTerminating program'
except EOFError:
    print 'Terminating program'