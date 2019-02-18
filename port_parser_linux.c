
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

pcap_t* pd;
int linkhdrlen;
static u_int tcp_packet_counter = 0;
static u_int upd_packet_counter = 0;

pcap_t* open_pcap_socket(char* device, const char* bpfstr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pd;
    uint32_t  srcip, netmask;
    struct bpf_program  bpf;

    if (!*device && !(device = pcap_lookupdev(errbuf)))
    {
        printf("pcap_lookupdev(): %s\n", errbuf);
        return NULL;
    }
    
    if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) < 0)
    {
        printf("pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    if (pcap_compile(pd, &bpf, (char*)bpfstr, 0, netmask))
    {
        printf("pcap_compile(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    if (pcap_setfilter(pd, &bpf) < 0)
    {
        printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
        return NULL;
    }


    
    return pd;
}



void capture_loop(pcap_t* pd, int packets, pcap_handler func, u_char* user_arg)
{
    int linktype;
	

    if ((linktype = pcap_datalink(pd)) < 0)
    {
        printf("pcap_datalink(): %s\n", pcap_geterr(pd));
        return;
    }
 
    switch (linktype)
    {
    case DLT_NULL:
        linkhdrlen = 4;
        break;
 
    case DLT_EN10MB:
        linkhdrlen = 14;
        break;
 
    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;
 	
    default:
        printf("Unsupported datalink (%d)\n", linktype);
        return;
    }
 
    if (pcap_loop(pd, packets, func, user_arg) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(pd));
}


void parse_packet_verbose(u_char *packetptr)
{
    struct ip* iphdr;
    struct tcphdr* tcphdr;
    struct ether_header* ethhdr;
	
	int data_len;
    iphdr = (struct ip*)packetptr;
    ethhdr = (struct ether_header*)packetptr;
	tcphdr = (struct tcphdr*)packetptr;
	
	printf("----------------------------------\n");
	printf("Src Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
        ethhdr->ether_shost[0],ethhdr->ether_shost[1],
        ethhdr->ether_shost[2],ethhdr->ether_shost[3],
        ethhdr->ether_shost[4],ethhdr->ether_shost[5]);		

    printf("Dst Mac Address:%02x:%02x:%02x:%02x:%02x:%02x\n",
        ethhdr->ether_dhost[0],ethhdr->ether_dhost[1],
        ethhdr->ether_dhost[2],ethhdr->ether_dhost[3],
        ethhdr->ether_dhost[4],ethhdr->ether_dhost[5]);

	
	if(ntohs(ethhdr->ether_type) == ETHERTYPE_IP)
	{
		printf("----------------------------------\n");
		printf("IPv4 Header\n");
		printf("------------------------------------\n");		
		printf("Header Length: %d\n", iphdr->ip_hl);
		printf("Version: %d\n", iphdr->ip_v);
		printf("Service Type: %d\n", iphdr->ip_tos);
		printf("Total Length: %d\n", ntohs(iphdr->ip_len));
		printf("Ident: %d\n", ntohs(iphdr->ip_id));
		printf("Protocol: %d\n", iphdr->ip_p);
		printf("Checksum: %d\n", ntohs(iphdr->ip_sum));
		printf("Src Address: %s\n", inet_ntoa(iphdr->ip_src));
		printf("Dst Address: %s\n", inet_ntoa(iphdr->ip_dst));
	}

	if(iphdr->ip_p == IPPROTO_TCP)
	{
		printf("----------------------------------\n");
		printf("TCP Header\n");
		printf("------------------------------------\n");				
		printf("Src Port: %d\n", ntohs(tcphdr->source));
		printf("Dst Port: %d\n", ntohs(tcphdr->dest));
		printf("Seq Number: %u\n", ntohl(tcphdr->seq));
		printf("Ack Number: %u\n", ntohl(tcphdr->ack_seq));
		printf("Data Offset: %d\n", tcphdr->doff);
		printf("Flags Urg: 0x%2x%c\n", tcphdr->urg, ' ');
		printf("Flags Ack: 0x%2x%c\n", tcphdr->ack, ' ');
		printf("Flags Psh: 0x%2x%c\n", tcphdr->psh, ' ');
		printf("Flags Rst: 0x%2x%c\n", tcphdr->rst, ' ');	
		printf("Flags Syn: 0x%2x%c\n", tcphdr->syn, ' ');
		printf("Flags Fin: 0x%2x%c\n", tcphdr->fin, ' ');
		printf("Window: %d\n", ntohs(tcphdr->window));
		printf("Checksum: %d\n", ntohs(tcphdr->check));
		printf("Urgent Pointer: %d\n", ntohs(tcphdr->urg_ptr));	

		data_len = (ntohs(iphdr->ip_len)) - 40;
		printf("Data Length : %d\n", data_len);
		printf("\n\n\n");
	}

	


}
void parse_packet_ipmac(u_char *packetptr)
{
    struct ip* iphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    struct ether_header* ethhdr;
	
    char iphdrInfo[256], srcip[256], dstip[256];
 	
    packetptr += linkhdrlen;

    iphdr = (struct ip*)packetptr;
    ethhdr = (struct ether_header*)packetptr;

    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
	
	printf("----------------------------------\n");
	printf("MAC : %02x:%02x:%02x:%02x:%02x:%02x ->",
        ethhdr->ether_shost[0],ethhdr->ether_shost[1],
        ethhdr->ether_shost[2],ethhdr->ether_shost[3],
        ethhdr->ether_shost[4],ethhdr->ether_shost[5]);		

    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
        ethhdr->ether_dhost[0],ethhdr->ether_dhost[1],
        ethhdr->ether_dhost[2],ethhdr->ether_dhost[3],
        ethhdr->ether_dhost[4],ethhdr->ether_dhost[5]);
	
    packetptr += 4*iphdr->ip_hl;
	

    switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;

        printf("TCP  %s:%d -> %s:%d\n", 
            srcip, ntohs(tcphdr->source),
            dstip, ntohs(tcphdr->dest));
		
		printf("Port %d -> %d \n", 
			ntohs(tcphdr->th_sport),
			ntohs(tcphdr->th_dport));
      break;
    case IPPROTO_UDP:
        udphdr = (struct udphdr*)packetptr;
        printf("UDP  %s:%d -> %s:%d\n",
            srcip, ntohs(udphdr->source),
            dstip, ntohs(udphdr->dest));

		printf("Port %d -> %d \n", 
			ntohs(udphdr->uh_sport),
			ntohs(udphdr->uh_dport));
        break;
	}

}

void choise_parse(u_char *user, struct pcap_pkthdr *packethdr, 
                  u_char *packetptr)
{
	(*user == 0x01) ? parse_packet_verbose(packetptr) : parse_packet_ipmac(packetptr);
}


int main(int argc, char **argv)
{
	u_char user_arg = 0x00;
    char interface[256] = "", bpfstr[256] = "";
    int packets = 0, i, c;

    while((c = getopt(argc, argv, "hil:n:v:")) != -1 )
    {
        switch(c)
        {
        case 'h':
            printf("%s [-h] [-i] [-n] [-v] [-l]  \n",argv[0]);
            exit(0);
            break; 
        case 'i':
            strcpy(interface, optarg);
            break; 
        case 'n':
            packets = atoi(optarg);
            break; 
		case 'v':
			user_arg = 0x01;
			break;
		case 'l':
			user_arg = 0x02;
			break;
        }
    }
    


    if ((pd = open_pcap_socket(interface, bpfstr)))
    {
       capture_loop(pd, packets, (pcap_handler)choise_parse, &user_arg); 
    }
    exit(0);
}
