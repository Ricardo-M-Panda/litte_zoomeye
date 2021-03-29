#include "scan_lib.h"

void alarm_handler(int sockfd);
int unpack(char* buf, int len, struct sockaddr_in* from_p);
/*接收所有ICMP报文*/
void recv_packet(int sockfd, unsigned int ip_list_len)
{
    struct sockaddr_in from;

    char recvpacket[PACKET_SIZE];
    int n, nreceived = 0, all_packet = (ip_list_len * MAX_ICMP_NO_PACKETS);
    socklen_t fromlen;


    fromlen = sizeof(from);
    /*考虑两种情形，满足其一则结束接收包。*/
    /*1.已接受到所有发出去的包*/
    /*2.最多可等待时间已经用完，其中每个包以400ms为最大等待时间*/
                /*设定信号及闹钟*/
    if (signal(SIGALRM, alarm_handler)) {
        perror("signal sigalarm error");
    }
    double time = ICMP_MAX_WAIT_TIME * all_packet;
    alarm(time);
    printf("\n---------CLOCK!-%f--------\n", time);

    /*此处时间为底线，用完则立刻停止*/
    while (nreceived < all_packet)
    {

        if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0,
            (struct sockaddr*)&from, &fromlen)) < 0)
        {
            if (errno == EINTR)continue;
            perror("recvfrom error");
            continue;
        }
        if (unpack(recvpacket, n, &from) == -1)
            continue;
        /*所发包=ip数*MAX_ICMP_NO_PACKETS，此处接收也应如此*/
        nreceived++;
        printf("allpacket is :%d,nreceived is : %d ,ip_list_len is %d", all_packet, nreceived, ip_list_len);

    }
    return;
}