#include "scan_lib.h"
/*发送三个ICMP报文*/
int pack(int pack_no, pid_t pid, char sendpacket[]);
void send_packet(int sockfd, pid_t pid, struct sockaddr_in* dest_addr_p)
{
    char sendpacket[PACKET_SIZE];
    int packetsize, i, nsend = 0;
    for (i = 0; i < MAX_ICMP_NO_PACKETS; i++) {
        nsend++;
        packetsize = pack(nsend, pid, sendpacket); /*设置ICMP报头*/
        if (sendto(sockfd, sendpacket, packetsize, 0,
            (struct sockaddr*)dest_addr_p, sizeof(*dest_addr_p)) < 0)
        {
            perror("sendto error");
            return;
        }
    }


}