#include "scan_lib.h"

int icmp_pack(int pack_no, pid_t pid, char sendpacket[]);
int tcp_pack(unsigned short randomport, char sendpacket[], int flag);
void send_one_packet(unsigned short randomport, char sendpacket[], int flag);
void send_icmp_packet(pid_t pid)
{
    char sendpacket[PACKET_SIZE];

    int packetsize, i, nsend = 0;
    for (i = 0; i < MAX_ICMP_NO_PACKETS; i++) {
        nsend++;
        packetsize = icmp_pack(nsend, pid, sendpacket); /*设置ICMP报头*/
        if (sendto( sockfd,sendpacket, packetsize, 0,
            (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0)
        {
            perror("sendto error");
            return;
        }
    }
    usleep(ICMP_SEND_RACE);
}

void send_tcp_packet()
{
    char sendpacket[PACKET_SIZE];
    unsigned short n = MAX_TCP_PORT_PACKETS;
    unsigned short  i, nsend = 0;
    unsigned short random_ports[MAX_TCP_PORT_PACKETS+1];
    srand((int)time(NULL));
    for (i = 0; i < MAX_TCP_PORT_PACKETS+1; i++)
    {
        random_ports[i] = i ;

    }
    for (i = 1; i < n+1; i++) {
        unsigned short tmp1 = (rand() % MAX_TCP_PORT_PACKETS)+1;
        unsigned short tmp2=random_ports[i];
        random_ports[i] = random_ports[tmp1];
        random_ports[tmp1] = tmp2;
    }
    
    for (i = 0; i < n; i++) {
        nsend++;
            send_one_packet(random_ports[i+1], sendpacket, -1);
    }
}

/*单次发包单拿出来作为函数，方便回复rst时调用*/
void send_one_packet(unsigned short randomport,  char sendpacket[],int flag)
{
    int packetsize;
    packetsize = tcp_pack(randomport, sendpacket,flag ); /*设置TCP报头*/
    if (sendto(sockfd, sendpacket, packetsize, 0,
        (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0)
    {
        perror("sendto error");
        return;
    }

    usleep(TCP_SEND_RACE);
}