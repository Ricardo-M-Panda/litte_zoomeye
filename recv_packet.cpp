#include "scan_lib.h"
pid_t send_rst_pid;
void alarm_handler(int sig);
void child_handler(int sig);
int icmp_unpack(char* buf, int len, struct sockaddr_in* from_p);
int tcp_unpack(char* buf, int len, struct sockaddr_in* from_p, unsigned short* p_dest_port);
void send_one_packet(unsigned short randomport, char sendpacket[], int flag);
/*接收所有ICMP报文*/
void icmp_recv_packet( unsigned int ip_list_len)
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
    while (nreceived<all_packet)
    {

        if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0,
            (struct sockaddr*)&from, &fromlen)) < 0)
        {
            if (errno == EINTR)continue;
            perror("recvfrom error");
            continue;
        }
        if (icmp_unpack(recvpacket, n, &from) == -1)
            continue;
        /*所发包=ip数*MAX_ICMP_NO_PACKETS，此处接收也应如此*/
        nreceived++;
        printf("\nallpacket is :%d,nreceived is : %d ,ip_list_len is %d\n", all_packet, nreceived, ip_list_len);

    }
    close(sockfd);
    exit(1);
}


void tcp_recv_packet( unsigned int ip_list_len)
{
    struct sockaddr_in from;
    struct sockaddr_in* dest_addr_p;
    unsigned short dest_port;
    unsigned int flag;
    char recvpacket[PACKET_SIZE];
    int n, nreceived = 0, all_packet = ip_list_len* MAX_TCP_PORT_PACKETS;
    socklen_t fromlen;


    fromlen = sizeof(from);
    /*考虑两种情形，满足其一则结束接收包。*/
    /*1.已接受到所有发出去的包*/
    /*2.最多可等待时间已经用完，其中每个包以400ms为最大等待时间*/
                /*设定信号及闹钟*/
    if (signal(SIGALRM, alarm_handler)) {
        perror("signal sigalarm error");
    }
    double time = TCP_MAX_PACKET_TIME * all_packet;
    /*设置一个时间等待上限，避免浪费太多时间*/
    if (time > TCP_MAX_WAIT_TIME)
        time = TCP_MAX_WAIT_TIME;
    alarm(time);
    printf("\n---------CLOCK!-%f--------\n", time);

    if (signal(SIGCHLD, child_handler)) {
        perror("signal sigchld error");
    }

    /*此处时间为底线，用完则立刻停止*/
    while (1)
    {

        if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0,
            (struct sockaddr*)&from, &fromlen)) < 0)
        {
            if (errno == EINTR)continue;
            perror("recvfrom error");
            continue;
        }
        if ((flag=tcp_unpack( recvpacket, n, &from ,&dest_port )) == -1)
            continue;
        else 
        {
            send_rst_pid =fork() ;
            if (send_rst_pid < 0)
            {
                perror("send_rst_pid fork error");
            }
            else if (send_rst_pid == 0) {
                char sendpacket[PACKET_SIZE];
                send_one_packet(dest_port, sendpacket,flag);
                close(sockfd);
                exit(2);
            }
            
        }
        /*所发包=ip数*MAX_ICMP_NO_PACKETS，此处接收也应如此*/
        nreceived++;
        printf("\nallpacket is :%d,nreceived is : %d ,ip_list_len is %d\n", all_packet, nreceived, ip_list_len);

    }
    close(sockfd);
    exit(1);
}