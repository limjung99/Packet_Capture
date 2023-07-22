#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN 6
#define ETHER_LENGTH 14
/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
	u_int8_t th_off;
	u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct libnet_ipv4_hdr
{
	u_int8_t ip_vhl;
	u_int8_t ip_tos;       /* type of service */
	u_int16_t ip_len;         /* total length */
	u_int16_t ip_id;          /* identification */
	u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_ether_hdr{
	u_int8_t ether_dhost[ETHER_ADDR_LEN];
	u_int8_t ether_shost[ETHER_ADDR_LEN];
	u_int16_t type;
};

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

void print_mac(u_int8_t *m){
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",m[0],m[1],m[2],m[3],m[4],m[5]);
}

void print_ip(struct in_addr ip){
	u_int32_t ip_addr = ntohl(ip.s_addr);
	u_int8_t ip1 = (ip_addr & 0xff000000) >> 24; 
	u_int8_t ip2 = (ip_addr & 0x00ff0000) >> 16; 
	u_int8_t ip3 = (ip_addr & 0x0000ff00) >> 8;  
	u_int8_t ip4 = ip_addr & 0x000000ff;        
	printf("%d:%d:%d:%d\n",ip1,ip2,ip3,ip4);
}


typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_port(u_int16_t port_addr){
	u_int16_t host_port_addr = ntohs(port_addr);
	printf("%d\n",host_port_addr);
}
	

void parse_packet(const u_char* packet,struct pcap_pkthdr* header){
	struct libnet_ether_hdr *eth_hdr =(struct libnet_ether_hdr*) packet;
	u_int8_t *dhost = eth_hdr->ether_dhost;
	u_int8_t *shost = eth_hdr->ether_shost;
	u_int16_t type = eth_hdr->type;
	type = ntohs(type);
	if(type!=0x0800) return; /* not a ipv4 protocol */
	//IP 
 	struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr*)(packet+ETHER_LENGTH);
	struct in_addr sip = ip_hdr->ip_src;
    struct in_addr dip = ip_hdr->ip_dst;
	u_int8_t protocol = ip_hdr->ip_p;
	u_int8_t ip_vhl = ip_hdr->ip_vhl;
	u_int8_t ip_version = (ip_vhl & 0xf0)>>4;
	u_int8_t ip_header_length = ip_vhl & 0x0f;
	if(protocol!=0x6) return; /* not a tcp protocol */
	//TCP
	struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*)(packet+ETHER_LENGTH+ip_header_length*4);
	u_int16_t th_sport = ntohs(tcp_hdr->th_sport);       /* source port */
    u_int16_t th_dport = ntohs(tcp_hdr->th_dport);       /* destination port */
	u_int8_t th_off = (tcp_hdr->th_off)>>4;
	u_int8_t start_offset = ETHER_LENGTH + ip_header_length*4 + th_off*4;
	//print
	printf("------------------------------------\n");
	printf("source mac address:");
	print_mac(shost);
	printf("destination mac address:");
	print_mac(dhost);
	printf("source ip address:");
	print_ip(sip);
	printf("destination ip address:");
	print_ip(dip);
	printf("source port address:");
	print_port(th_sport);
	printf("destination port addrdss:");
	print_port(th_dport);
	printf("data payload : ");
	for(int i=start_offset;i<header->caplen;i++){
		printf("%02x:",packet[i]);
		if(i-start_offset>9) break;
	}
	printf("\n");
	printf("------------------------------------\n");

}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		//packet포인터는 packet byte stream. 즉 pocket 구조체의 시작주소를 포인팅
		//header포인터는 packet의 헤더정보  구조체의 시작주소를 포인팅
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		parse_packet(packet,header);
			
	}
	
	pcap_close(pcap);
}
