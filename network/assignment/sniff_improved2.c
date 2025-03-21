#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {  //총 14바이트
    u_char ether_dhost[6];  // destination host address
    u_char ether_shost[6];  // source host address
    u_short ether_type;     /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {  
    unsigned char iph_ihl:4,  // IP header length
                  iph_ver:4;  // IP version
    unsigned char iph_tos;    // Type of service
    unsigned short int iph_len;  // IP Packet length (data + header)
    unsigned short int iph_ident;  // Identification
    unsigned short int iph_flag:3, // Fragmentation flags
                      iph_offset:13;  // Flags offset
    unsigned char iph_ttl;  // Time to Live
    unsigned char iph_protocol;  // Protocol type
    unsigned short int iph_checksum;  // IP datagram checksum
    struct in_addr iph_sourceip; // Source IP address
    struct in_addr iph_destip;   // Destination IP address
};


/* TCP Header */
struct tcpheader {
		u_short tcp_sport;             /* source port*/
		u_short tcp_dport;             /* destination port*/
		u_int   tcp_seq;               /* sequence number */
		u_int   tcp_ack;               /* acknowledgement number */
		u_char  tcp_offx2;             /* data offset, rsvd tcp header 길이*/
		
#define TH_OFF(th)   (((th)->tcp_offx2 & 0xf0) >> 4)
		u_char  tcp_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS     (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short tcp_win;     /*window*/
		u_short tcp_sum;     /*checksum*/
		u_short tcp_urp;     /*urgent pointer*/
};


void print_mac(const u_char *src_mac, const u_char *dest_mac) {
	
	printf("         From : %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
	printf("           To : %02x:%02x:%02x:%02x:%02x:%02x\n", dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);			

}

void print_ip (struct in_addr src_ip, struct in_addr dest_ip) {
		
	printf("       From : %s\n", inet_ntoa(src_ip));
    	printf("         To : %s\n", inet_ntoa(dest_ip));
    
}

void print_port (const unsigned short src_port, const unsigned short dest_port) {

	printf("        From : %u\n", ntohs(src_port));
	printf("        To : %u\n", ntohs(dest_port));
} 

void print_message(const unsigned char *message, int message_size) {
	printf("    Message (%d bytes): ", message_size);
		
	for (int i = 0; i< message_size; i++) {
		printf("%02x ", message[i]);  //16진수로 출력하기.
	}
	printf("\n");
		
}

// 이더넷 헤더 벗기기 
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
// void got_segment 함수 추가 (IP Header 벗기기)
/*IP header 벗길 때 iph_ihl:4비트 변수에서 길이 값 갖고와서 그 만큼 포인터 이동시키기*/
//void got_message 함수 추가(pay_load) (Transport Header 벗기기)
/*위 함수를 다 따로 쓰는 것이 아니라 하나의 got_packet()함수에서 모두 실행해야 함.*/     
    
    struct ethheader *eth = (struct ethheader *)packet;
    print_mac(eth -> ether_shost, eth ->  ether_dhost); 
    // src mac 과 dst mac 출력
    
    if (ntohs(eth->ether_type) == 0x0800) {  // Check if IPv4
        struct ipheader *ip = (struct ipheader *)
				      (packet + sizeof(struct ethheader));
        print_ip(ip->iph_sourceip, ip->iph_destip);
        			
	int ip_header_len = 0;
	int tcp_header_len = 0;
	int message_size = 0;

        /* Determine protocol */
        switch (ip->iph_protocol) {
            case IPPROTO_TCP:
            	ip_header_len = (ip->iph_ihl) * 4; // tcp length byte추출
                printf("   Protocol: TCP\n");
                struct tcpheader *tcp = (struct tcpheader*) 
				              (packet + sizeof(struct ethheader) + ip_header_len); //내가 씀 (가장 안전).
                
                tcp_header_len = TH_OFF(tcp) * 4;
                message_size = ntohs(ip->iph_len) - (ip_header_len + tcp_header_len);
                const u_char *message = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
                
                print_port(tcp -> tcp_sport, tcp -> tcp_dport);
                if (message_size > 0) {
	               print_message(message, message_size);
                }
                break;
                
            case IPPROTO_UDP:
                printf("   Protocol: UDP\n");
                break;
                
            case IPPROTO_ICMP:
                printf("   Protocol: ICMP\n");
                break;
                
            default:
                printf("   Protocol: Others\n");
                break;
        }
    }
}

// void got_segment 함수 추가 (IP Header 벗기기)
/*IP header 벗길 때 iph_ihl:4비트 변수에서 길이 값 갖고와서 그 만큼 포인터 이동시키기*/
//void got_message 함수 추가(pay_load) (Transport Header 벗기기)
/**/
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device enp0s3: %s\n", errbuf);
        return 1;
    }

    // Step 2: Compile filter_exp into BPF pseudo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        pcap_perror(handle, "Error: ");
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
		
    pcap_close(handle);  // Close the handle
    return 0;
}
