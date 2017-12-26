from scapy.all import *
import datetime
import time
import argparse
import sys

queries = {} # key=id+src.ip and value=packet

replies = {} # key=id+dst.ip and value=packet

# DNS Injection
def dns_detect(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):

        if packet[DNS].qr is 0 and packet[DNSQR].qtype is 1:
                queries[str(packet[DNS].id)+':'+packet[IP].src] = packet

        if packet[DNS].qr is 1 and packet[DNSQR].qtype is 1:

            # check if the response if for valid query id, if not, say that something went worng
            #
            # we have store the data of the response (mainly rname and id) in some data structure
            # before storing will have to check if it is already present in our data structure

            if str(packet[DNS].id)+':'+packet[IP].src in queries.keys():

                if str(packet[DNS].id)+':'+packet[IP].dst in replies.keys():

                    id = packet[DNS].id
                    req = packet[DNS].qd.qname.decode('utf-8')

                    value_pkt = replies[str(packet[DNS].id)+':'+packet[IP].dst]

                    if packet[IP].dst == value_pkt[IP].dst and \
                       packet[UDP].sport == value_pkt[UDP].sport and \
                       packet[UDP].dport == value_pkt[UDP].dport and \
                       packet[DNSQR].qname == value_pkt[DNSQR].qname and \
                       packet[IP].payload != value_pkt[IP].payload:

                        ttl_flag=0
                        mac_flag=0
                        rdata_flag=0

                        # check if ttl is same or not
                        if value_pkt[IP].ttl != packet[IP].ttl:
                            ttl_flag=1

                        # check if src mac is same or not
                        if value_pkt[Ether].src != packet[Ether].src:
                            mac_flag=1

                        ip1 = []
                        ip2 = []
                        ancount1 = value_pkt[DNS].ancount
                        ancount2 = packet[DNS].ancount
                        i = 0
                        j = 0
                        while i < ancount1:
                            if value_pkt[DNSRR][i].type is 1:  # if it is A type
                                ip1.append(value_pkt[DNSRR][i].rdata)
                            i += 1

                        while j < ancount2:
                            if packet[DNSRR][j].type is 1:  # if it is A type
                                ip2.append(packet[DNSRR][j].rdata)
                            j += 1

                        if len(ip1) > 0 and len(ip2) > 0:
                            # lets check if there is any intersection between the lists ip1 and ip2
                            intersection = [val for val in ip1 if val in ip2]
                            if len(intersection) == 0:
                                rdata_flag=1
                                line1 = 'Answer1  {0}'.format(ip1)
                                line2 = 'Answer2  {0}'.format(ip2)

                        if len(ip1) > 0 and len(ip2) == 0:
                            rdata_flag = 1
                            line1 = 'Answer1  {0}'.format(ip1)
                            line2 = 'Answer2  [Not A type response]'

                        if len(ip1) == 0 and len(ip2) > 0:
                            rdata_flag = 1
                            line1 = 'Answer1  [Not A type response]'
                            line2 = 'Answer2  {0}'.format(ip2)

                        if len(ip1) == 0 and len(ip2) == 0:
                            rdata_flag = 1
                            line1 = 'Answer1  [Not A type response]'
                            line2 = 'Answer2  [Not A type response]'


                        if ttl_flag or mac_flag or rdata_flag: # it is a spoofed packet

                            ts = packet.time
                            st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                            print('\n')
                            print(st + " DNS Poisoning attempt detected !!")
                            line0 = "TXID {0} Request {1}".format(id, req)

                            print(line0)
                            print(line1)
                            print(line2)


                else:
                    replies[str(packet[DNS].id)+':'+packet[IP].dst] = packet

            else:
                # some dumb attacker trying to attack with randomly generated id for a match

                ts = packet.time
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                print(st + " DNS Poisoning attempt detected !!")
                print("Response DNS packet has been found which is not asked for !!")

                id = packet[DNS].id
                req = packet[DNS].qd.qname.decode('utf-8')
                line0 = "TXID {0} Request {1}".format(id, req)
                print(line0)



def cli_parser():
    parser = argparse.ArgumentParser(description="DNS DETECT tool",add_help=False)
    parser.add_argument("-i")
    parser.add_argument("-r")
    parser.add_argument('expression',nargs='*')
    args=parser.parse_args()
    return args.i,args.r,args.expression


if __name__ == '__main__':
    i_flag=0
    r_flag=0
    interface, tracefile, expression = cli_parser()
    try:

        if interface and tracefile:
            print('')
            print("Invalid command line arguments. Both -i and -r options are not accepted simultaneously.")
            sys.exit()

        if interface:
            i_flag=1

        if tracefile:
            r_flag=1

        if expression:
            exp_as_str = " ".join(expression)
            print('')
            print("BPF filter specified: " + exp_as_str)
            bpf = exp_as_str + " and udp port 53"
        else:
            bpf = "udp port 53"
            print('')
            print("No BPF filter specified.")



        if i_flag == 1 and r_flag == 0:
            print("Interface specified: " + interface)
            sniff(filter=bpf, iface=interface, prn=dns_detect, store=0)

        if i_flag == 0 and r_flag == 1:
            print("Trace file specified: " + tracefile)
            sniff(filter=bpf, offline=tracefile, prn=dns_detect, store=0)

        if i_flag == 0 and r_flag == 0:
            print("No interface or tracefile specified, selecting a default interface.")
            sniff(filter=bpf, prn=dns_detect, store=0)

        if i_flag == 1 and r_flag == 1:
            sys.exit()


    except AttributeError:
        print("Invalid command line arguments")
        sys.exit()