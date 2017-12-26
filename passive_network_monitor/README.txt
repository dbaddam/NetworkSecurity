-----------------------------------------------------------------------------------------------------------------------------------------------------------

PASSIVE NETWORK MONITORING:
-----------

mydump.c sniffs the ethernet packets live or from a given *.pcap file

Brief Description:

1. Used getopt() in C to parse the input arguments from command line(-r or -s or -i)
	-i -> live capture
	-r -> reads from the pcap file given

	-s -> prints only the packets with given search string in payload

2. Based on the given input argument, it defines the handle to be live capture one or pcap offline reader.

3. got_packet() checks for the ether type (IP if equal to 0x800) and processes for protocol(TCP, UDP, ICMP) or else prints the raw payload.

4. Have used the helper function print_payload() function from above mentioned link as it is after prof. has confirmed to use that in our code.



Example 1:
command: ./mydump -r *.pcap 
prints all the packets reading from the given pcap file.

Example 2:
command: ./mydump -r *.pcap -s HTTP
prints the packets reading from the given pcap file with "HTTP" string in their payload.

Example 3:
command: ./mydump -r *.pcap icmp
prints only the ICMP packets reading from the given pcap file.

Example 4:
command: ./mydump -i eth0
prints the packets received through live capture, from given device "eth0"

Example 5:
command: ./mydump
prints the packets received through live capture picking a default device got from devlookup() of pcap library.

Example 6:
command: ./mydump -r *.pcap -i en0
prints ERROR statement as both -r and -i cannot be used to handle the packets at once.

Example 7:
command: ./mydump -r *.pcap -s HTTP tcp port 80
prints the TCP packets with port 80 in their source or destination ip addresses and has "HTTP" in their payload string.

REFERENCES:
http://www.tcpdump.org/pcap.html
