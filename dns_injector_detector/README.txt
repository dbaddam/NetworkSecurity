-----------------------------------------------------------------------------------------------------------------------------------------------------------

DNS INJECT:
-----------
	The DNS packet injector 'dnsinject.py' will capture the traffic from a network interface in promiscuous mode, and attempt to inject forged responses 
	to selected DNS A type queries with the goal to poison the resolver's cache. The dns injector filterr for DNS fields having (qr==0) as they mean query 
	packets, also checks for DNSQR field (qtype==1) as it means for a A type request. And then it creates a response spoof packet gathering the information 
	from the sniffed query dns packet by adding the response record field DNSRR with rdata=<attacker_wanted_ip>.


Working examples of commands:

$ sudo python3 dnsinject.py -i <network_intefrace> -h hostnames ip host <ip_value_to_filter>
	The above command captures the traffic from given network interface in promiscuous mode and injects forged responses from given hostname file for 
	given domain names and also filters for given expression (ip host 192.168.10.0)

$ sudo python3 dnsinject.py -i <network_intefrace> ip host <ip_value_to_filter>
	when no hostnames file is given, it injects the forged relpied with the local ip of the server for all the sniffed domain names.

$ sudo python3 dnsinject.py
	when no interface is specified, it sniffs on default interface.
-----------------------------------------------------------------------------------------------------------------------------------------------------------

DNS DETECT:
-----------
	The DNS poisoning attack detector 'dnsdetect.py', will capture the traffic from a network interface in promiscuous mode and 
	detect DNS poisoning attack attempts. Detection will be based on identifying duplicate responses towards the same destination that contain different 
	answers for the same A tyep request. 

	False positives detection:

	DNS detector sniffs for both response packets and query packets and stores them. When recieved a response packet it looks for a matching query packet 
	if the response is really asked for, if not, detects that response has been found for which no query has been asked. When a matching id is found in 
	stored queries, it countinues to check if there is any matching id in the previously stored responses, it detects the dns poisoning attempt and prints 
	both the packtes and time of detection to the terminal.

	When two responses are recieved with the same transaction ID and have any intersection between their rdata fields, that is ips, we assume those to be 
	two different but legitimate responses from the server. 

	Also, checking if the received duplicate responses have same time to live (ttl) value, if so, we do not consider either of them to be a spoofed one.
	I am checking for the source MAC address fields in the duplicate responses and if different we consider one of them to be a spoofed response.

	The false positives can be detected by doing reverse DNS lookup of the domains we received in both the duplicate resonses with same transaction ID, but
	even this action of reverse DNS lookup can be spoofed by the attacker. Hence, not considered this way to detect false positives.


Working examples of commands:
-----------------------------

$ sudo python3 dnsdetect.py -i <network_interface> -r <pcap_file> <expression>
	The above commands exits with an error message as only one of the options i or r shall be specified

$ sudo python3 dnsdetect.py -r <pcap_file> <expression>
	Sniffs from the given pcap file and detects for nany duplicate DNS A type responses and displays them onto terminal. Also applies the given expression
	as bpf filter while sniffing.

$ sudo python3 dnsdetect.py -i <network_interface> <expression>
	Sniffs from the given network interface

$ sudo python3 dnsdetect.py 
	Sniffs from a default network device.

Also, when we want to specify two or more expressions with 'and' or 'or' that has to be given in circular braces along with escape characters

$ sudo python3 dnsdetect.py \(expression1 or expression2 \)

$ sudo python3 dnsdetect.py \(ip src 192.168.10.12 or ip src 192.168.10.20 \)


Example outputs for DNS DETECT:
-------------------------------

$ sudo python3 dnsdetect.py -r traffic.pcap

			2017-12-08 08:04:43.342446 DNS Poisoning attempt detected !!
			TXID 9025 Request www.instagram.com.
			Answer1  ['172.24.30.52']
			Answer2  ['31.13.71.174']

			2017-12-09 18:11:04.426612 DNS Poisoning attempt detected !!
			TXID 24814 Request tiles.services.mozilla.com.
			Answer1  ['172.24.30.52']
			Answer2  ['34.210.37.21', '52.25.39.121', '35.164.42.31', '52.10.50.117', '54.69.231.249', '52.32.216.235', '52.26.56.183', '34.214.191.72']

			2017-12-08 08:04:48.309727 DNS Poisoning attempt detected !!
			TXID 41545 Request img-getpocket.cdn.mozilla.net.
			Answer1  ['172.24.30.52']
			Answer2  ['13.33.81.58']

			2017-12-09 18:11:04.568383 DNS Poisoning attempt detected !!
			TXID 43476 Request www.leetcode.com.
			Answer1  ['172.24.30.52']
			Answer2  ['104.27.161.90', '104.27.160.90']

			2017-12-08 08:05:05.231552 DNS Poisoning attempt detected !!
			TXID 49631 Request www.citibank.com.
			Answer1  ['172.24.30.52']
			Answer2  ['23.193.205.115']

The above example shows the attempts(collected from many other attempted detects from traffic.pcap file) where attacker was successfully able to send the 
response query for the domains like instagram, leetcode, citibank which were never visited before in victims machine, meaning no dns cached 
for these entries. Hence, these sites were redirected by attacker to Answer1 ip "172.24.30.52" instead of original ips in Answer2. Also, when reading from a 
pcap file, there is known bug which cannot hanlde additional filters. Prof had asked to mention in the report the same.

Also when it detects a duplicate response for not existent domains and where in the type of response is not of A type, it prints in the following format.
The Answer1 is of attacker ip and later response Answer2 is from DNS resolver saying, not existent domain, hence not a A type response which does not 
contain IP in the response.

			2017-12-08 19:02:33.442129 DNS Poisoning attempt detected !!
			TXID 50288 Request wiubvownv.com.
			Answer1  ['172.24.30.52']
			Answer2  [Not A type response]
-----------------------------------------------------------------------------------------------------------------------------------------------------------
Environment Details:
--------------------

OS: MAC OS X
Language: Python
Version: 3.6.3

Testing purpose:

DNS Inject and detect run on MAC OS X
Victim on UBUNTU 16.04

-----------------------------------------------------------------------------------------------------------------------------------------------------------
References:
-----------

https://thepacketgeek.com/scapy-p-09-scapy-and-dns/

https://thepacketgeek.com/scapy-sniffing-with-custom-actions-part-1/

https://itgeekchronicles.co.uk/2014/05/12/scapy-iterating-over-dns-responses/

http://www.firewall.cx/networking-topics/protocols/domain-name-system-dns/161-protocols-dns-response.html

https://www.youtube.com/watch?v=RAOHmrtaimU

http://securitynik.blogspot.com/2014/05/building-your-own-tools-with-scapy.html

Hackish way to get locap ip:
https://stackoverflow.com/a/166589

CLI parser:
https://docs.python.org/2/library/argparse.html
-----------------------------------------------------------------------------------------------------------------------------------------------------------