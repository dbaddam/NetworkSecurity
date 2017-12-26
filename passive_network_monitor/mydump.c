#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>


/* Address Resolution packet */
#define ETHERTYPE_ARP		0x806
#define ETHERTYPE_REVARP 	0x8035
#define ETHERTYPE_IP		0x800


/*  default snap length (maximum bytes per packet to capture) 
	The original Ethernet IEEE 802.3 standard defined the minimum Ethernet frame size as 64 bytes and the maximum as 1518 bytes. 
	The maximum was later increased to 1522 bytes to allow for VLAN tagging. 
	The minimum size of an Ethernet frame that carries an ICMP packet is 74 bytes.
*/
#define SNAP_LEN 1522

/* ethernet headers are ALWAYS exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/*	UDP Header */
struct sniff_udp {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};



// Defined incase user inputs -s string
	const char *str;

// is flag for -s string set, did user gave an input
	int sflag = 0;


int stringlen(const char *a) 
 {
     int length = 0;
     while(*a)
     {   
         length++;
         a++;
     }   
     return length;
 }

void strrev(char *a) 
 {
    char temp;
    int i,j;
    for(i = stringlen(a)-1, j=0; i>=j;i--, j++)
    {   
        temp = a[i];
        a[i] = a[j];
        a[j] = temp;
    }   
 }
typedef int boolean;
 
 #define true 1
 #define false 0
// int to string
void intTOstring(int number, char *p, int base)
 {
     int i=0;
     boolean isNeg = false;
     if(number == 0)
     {   
         p[i++]='0';
         p[i]='\0';
     }   
     if(number < 0)
     {   
         number = -1*number;
         isNeg = true;
     }
     while(number !=0)
     {
         int rem = number % base;
         p[i++] = rem + '0';
         number = number/base;
     }
     if(isNeg)
     {
         p[i++] = '-';
     }
     p[i] = '\0';
     strrev(p);
 }


/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	//printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}



/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}



/*	
 *	Print the time stamp from header for both live and offline capture 
 */
void print_timestamp(const struct pcap_pkthdr *header){
	struct timeval tv = header->ts;
	time_t nowtime = tv.tv_sec;
	struct tm *nowtm = localtime(&nowtime);
	char buffer[64], timeBuffer[64];

//	gettimeofday(&tv, NULL);
	
	strftime(buffer, sizeof buffer, "%Y-%m-%d %H:%M:%S", nowtm);

	//snprintf(timeBuffer, sizeof timeBuffer, "%s.%06d", buffer, tv.tv_usec);
	printf("%s.%06ld ",buffer, tv.tv_usec);
}

void print_mac_address(u_char ether_host[ETHER_ADDR_LEN]){
	int i;
	for(i=0; i<ETHER_ADDR_LEN; i++){
		if(i==ETHER_ADDR_LEN-1){
			printf("%02X", ether_host[i]);
		}else{
			printf("%02X:", ether_host[i]);
		}
	}
	return;
}
void print_ether_type(const struct sniff_ethernet *ethernet){
	printf(" type 0x%x ", ntohs(ethernet->ether_type));
}

void print_header_len(int length){
	printf("len %d ", length);printf("\n");
}

void print_first_line(const struct pcap_pkthdr *header, const struct sniff_ethernet *ethernet){
	print_timestamp(header);
	print_mac_address((u_char *)ethernet->ether_shost);printf(" -> ");
	print_mac_address((u_char *)ethernet->ether_dhost);
	print_ether_type(ethernet);
	print_header_len(header->len);
}

/* A function used in pcap_loop as an argument and prints the packet information
	based on the type of packet
*/

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	//	declaration of pointers to different packet headers
	const struct sniff_ethernet *ethernet;  
	const struct sniff_ip *ip;              
	const struct sniff_udp *udp;
	const struct sniff_tcp *tcp;
	const char *payload;
	const char *payload1;

	int size_ip;	
	int size_udp;
	int size_tcp;
	int size_icmp;
	int size_payload;

	int src_port;
	int dest_port;

	char *packetString = NULL;
	packetString = (char*)malloc(2000);

	//	define the ethernet header
	ethernet = (struct sniff_ethernet*)(packet);

	

	


	
/*
//	check if it is an ARP packet and handle it
if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP || 
	ntohs(ethernet->ether_type) == ETHERTYPE_REVARP) {
*/

if((ntohs(ethernet->ether_type) != ETHERTYPE_IP)) {
    //printf("ARP\n");

    //const struct sniff_arp *arp;
    //arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);

    //define the tcp payload pointer
	//payload = (char *)(packet + SIZE_ETHERNET + sizeof arp);
	
	payload = (char *)(packet + SIZE_ETHERNET);

	//compute the payload size
	// = (total ip - ip size - tcp size), as rest falls into payload size
	//size_payload = (header->len) - (sizeof arp);
	size_payload = (header->len) - (SIZE_ETHERNET);

}
else{



	//	define ip header which is packet plus length of above ethernet header 
	//	ethernet header size = 14 always as defined above
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

	//	calculate the size of ip header
	size_ip = IP_HL(ip)*4;
	if(size_ip < 20){
		printf("Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	char srcBuffer[100];
	char dstBuffer[100];


	// determine protocol from ip header
	switch(ip->ip_p) {

		case IPPROTO_TCP:

		//	printf("   Protocol: TCP\n");
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if(size_tcp < 20){
				printf("(Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			intTOstring(ntohs(tcp->th_sport), srcBuffer, 10);
			intTOstring(ntohs(tcp->th_dport), dstBuffer, 10);

			strcat(packetString, inet_ntoa(ip->ip_src));
			strcat(packetString, ":");
			strcat(packetString, srcBuffer);
			strcat(packetString, " -> ");
			strcat(packetString, inet_ntoa(ip->ip_dst));
			strcat(packetString, ":");
			strcat(packetString, dstBuffer);
			strcat(packetString, " TCP");

			
			//define the tcp payload pointer
			payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

			//compute the payload size
			// = (total ip - ip size - tcp size), as rest falls into payload size
			size_payload = ntohs(ip->ip_len) - (size_ip+size_tcp);
			break;

		case IPPROTO_UDP:
		//	printf("   Protocol: UDP\n");

			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

			size_udp = ntohs(udp->uh_ulen);

			intTOstring(ntohs(udp->uh_sport), srcBuffer, 10);
			intTOstring(ntohs(udp->uh_dport), dstBuffer, 10);

			strcat(packetString, inet_ntoa(ip->ip_src));
			strcat(packetString, ":");
			strcat(packetString, srcBuffer);
			strcat(packetString, " -> ");
			strcat(packetString, inet_ntoa(ip->ip_dst));
			strcat(packetString, ":");
			strcat(packetString, dstBuffer);
			strcat(packetString, " UDP");
			

			payload = (char *)(packet + SIZE_ETHERNET + size_ip + sizeof udp);
			size_payload = ntohs(ip->ip_len) - (size_ip + sizeof udp);
			break;

		case IPPROTO_ICMP:

			strcat(packetString, inet_ntoa(ip->ip_src));
			strcat(packetString, " -> ");
			strcat(packetString, inet_ntoa(ip->ip_dst));
			strcat(packetString, " ICMP");

			payload = (char *)(packet + SIZE_ETHERNET + size_ip);
			size_payload = ntohs(ip->ip_len) - (size_ip);
			break;

		default:
			//printf("   Protocol: unknown");
			strcat(packetString, inet_ntoa(ip->ip_src));
			strcat(packetString, " -> ");
			strcat(packetString, inet_ntoa(ip->ip_dst));
			strcat(packetString, " OTHER");
			payload = (char *)(packet + SIZE_ETHERNET + size_ip);
			size_payload = ntohs(ip->ip_len) - (size_ip);
			break;
	}
	

}
	
	int len = size_payload;
	const char *ch;
	ch = payload;
	char printable_payload[len];
	int j=0;
	int i;
	for(i=0; i<len; i++){
		if (isprint(*ch)){
			printable_payload[j++] = *ch;
		}
		ch++;
	}

	//printf("\nPayload size = %d Bytes\n", size_payload);
	if(size_payload > 0){
		if(sflag == 1){
			//payload1 = strstr(payload, str);
			payload1 = strstr(printable_payload, str);
			//printf("payload1 = %s\n", payload1);
			if(payload1){
				print_first_line(header, ethernet);
				if(*packetString){
					printf("%s\n", packetString);
				}
				print_payload((u_char *)payload, size_payload);
				printf("\n");
			}else{
				return;
			}
		}else{
			print_first_line(header, ethernet);
			if(*packetString){
				printf("%s\n", packetString);
			}
			print_payload((u_char *)payload, size_payload);
			printf("\n");
		}
		
	}
	return;

}




int main(int argc, char **argv){

	//	capture device name
	char *dev = NULL;

	//	the error buffer returned by pcap_lookupdev
	char errbuf[PCAP_ERRBUF_SIZE];

	//	subnet mask for capture device
	bpf_u_int32 mask;

	//	ip for capture device
	bpf_u_int32 net;

	//	handle to capture packet
	pcap_t *handle = NULL;

	//	filter expression : as of now hardcoded
	//char filter_exp[] = "ip";
	char filter_exp[100];
	//filter_exp[0] = ''

	//	compiled filter expression
	struct bpf_program fp;

	//	packet
	const u_char *packet;

	//	The header that pcap gives us
	struct pcap_pkthdr header;	

	//falg for -i
	int iflag = 0;

	//flag for -r
	int rflag = 0;


	/*	If there are no arguments capture a device using pcap_lookupdev
	 *	If there are arguments  assign handle based on -i or -r
	 *	handle the string in -s option.
	 */

	if(argc > 1){
  		int c;
  		while ((c = getopt (argc, argv, "i:r:s:")) != -1)
    		switch (c)
      	{
      		case 'i':
      			iflag = 1;
      			dev = optarg;
      		    //printf("%s\n", optarg);				
      		    break;
     		case 'r':
     			rflag = 1;
     			handle = pcap_open_offline(optarg, errbuf);
      		    //printf("%s\n", optarg);
      		    if(handle == NULL){
					fprintf(stderr, "Could not open the offline pcap file %s: %s\n",optarg, errbuf);
					return(-1);
				}
      		    break;
     		case 's':
     			sflag = 1;
     			str = optarg;
     			//printf("%s\n", optarg);
	            break;
      		
      		default:
        	abort ();
      	}
  		for (int index = optind; index < argc; index++){
  			strcat(filter_exp, argv[index]);
  			strcat(filter_exp, " ");
    		//printf ("filter exp arguments = %s\n", argv[index]);  	
  		}
	}

	if(iflag && rflag){
		printf("\nPlease enter any one of the modes(-i or -r) for capturing the packets:\n\n");
		printf("-i deviceName -> to capture live traffic through given device/interface.\n");
		printf("-r *.pcap     -> to read packets from a given input *.pcap file.\n\n");
		return(-1);
	}
	//printf("%s\n", filter_exp);


	if(!dev){
		/*
	  		get capture device name from command line, 
	  		if not present get using pacap_lookupdev 
		*/
		dev = pcap_lookupdev(errbuf);
		if(dev == NULL){
			fprintf(stderr, "Could not find the default device: %s\n", errbuf);
			return(-1);
		}
		//printf("Device = %s\n",dev);

		/*
	  		get the network number and mask related to the captured device above
		*/

		if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
			fprintf(stderr, "Could not get the net and mask for device %s: %s\n",dev, errbuf );
			net =0;
			mask =0;
		}
	}


	/*
	  open the captured device above
	*/
	if(!handle){
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
		if(handle == NULL){
			fprintf(stderr, "Could not open the captured device %s: %s\n",dev,errbuf);
		return(-1);
		}
	}
	


	/* make sure we are capturing on an ethernet device */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		return(-1);
	}


	/* compile the filter expression */
	if(pcap_compile(handle, &fp, filter_exp, 0, net)==-1){
		fprintf(stderr, "Could not compile the filter %s: %s\n",filter_exp, pcap_geterr(handle));
		return(-1);
	}

	/* applying the above compiled filter */
	if(pcap_setfilter(handle, &fp)==-1){
		fprintf(stderr, "Could not set the filter %s: %s\n",filter_exp, pcap_geterr(handle));
		return(-1);
	}


/*
	// grab a packet
	packet = pcap_next(handle, &header);
*/


	pcap_loop(handle, -1, got_packet, NULL);


	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	return(0);
}