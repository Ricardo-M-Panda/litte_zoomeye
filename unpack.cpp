#include "scan_lib.h"


struct sockaddr_in dest_rst_addr;
/*rst_ack_seq是接收包的确认号，rst_seq则是序列号*/
unsigned int rst_ack_seq, rst_seq;
extern unsigned int port_flag;


tcp_result_list*  tcp_unpack(char* buf, int len, struct sockaddr_in* from_p, unsigned short* p_dest_port)
{
    int i, iphdrlen;
    struct ip* ip;
    struct tcphdr* tcp;
    //struct timeval* tvsend;
    char* os;

    ip = (struct ip*)buf;

    iphdrlen = ip->ip_hl << 2;    /*求ip报头长度,即ip报头的长度标志乘4*/
    tcp = (struct tcphdr*)(buf + iphdrlen);  /*越过ip报头,指向TCP报头*/
    len -= iphdrlen;            /*ICMP报头及ICMP数据报的总长度*/
    if (len < 20)                /*小于ICMP报头长度则不合理*/
    {
        printf("\nTCP packets\'s length is less than 20\n");
        return NULL;
    }
    /*简单判断下，是否是回复自己的包*/

    if (tcp->dest != htons(TCP_SEND_PORT))
    {
        return NULL;
    }
    /*回复syn+ack则该端口已打开，实际上对方也可能分两次发送，但此处不作考虑*/
    if (tcp->ack == 1 && tcp->syn == 1)
    {

        *p_dest_port = ntohs(tcp->source);
        dest_rst_addr = *from_p;
        rst_ack_seq = tcp->ack_seq;
        rst_seq = tcp->seq;


        unsigned result_port= ntohs(tcp->source);
        char* result_ip= inet_ntoa(from_p->sin_addr);


        printf("\n%s port  %d is open \n", result_ip, result_port);
        tcp_result_list* node = (tcp_result_list*)malloc(sizeof(tcp_result_list));
        node->ip = result_ip;
        node->port = result_port;

        /*控制权交回给调用程序，使其通过并发回复相应的rst包*/
        port_flag = ntohl(tcp->seq);            
        return node;
    }
    else
        return NULL;
}

/*剥去ICMP报头*/
icmp_result_list* icmp_unpack(char* buf, int len, struct sockaddr_in* from_p)
{
    int i, iphdrlen;
    struct ip* ip;
    struct icmp* icmp;
    //struct timeval* tvsend;
    char* os;
    ip = (struct ip*)buf;
    iphdrlen = ip->ip_hl << 2;    /*求ip报头长度,即ip报头的长度标志乘4*/
    icmp = (struct icmp*)(buf + iphdrlen);  /*越过ip报头,指向ICMP报头*/
    len -= iphdrlen;            /*ICMP报头及ICMP数据报的总长度*/
    if (len < 8)                /*小于ICMP报头长度则不合理*/
    {
        printf("ICMP packets\'s length is less than 8\n");
        return NULL;
    }
    /*确保所接收的是ICMP的回应*/
    if (icmp->icmp_type == ICMP_ECHOREPLY)

    {
        if (ip->ip_ttl > 128)
        {
            os = "Unix";
        }
        else if (ip->ip_ttl > 64)
        {
            os = "windows NT/2000/XP/10";
        }
        else if (ip->ip_ttl > 32)
        {
            os = "Linux or Compaq64 5.0";
        }
        else
        {
            os = "Windows 95/98";
        }
        printf("\n %s is active, icmp_seq=%u ttl=%d OS : %s \n",
            inet_ntoa(from_p->sin_addr),
            icmp->icmp_seq,
            ip->ip_ttl,
            os);
        icmp_result_list* node = (icmp_result_list*)malloc(sizeof(icmp_result_list));
        node->icmp_os = os;
        node->ipaddress = inet_ntoa(from_p->sin_addr);
        node->next = NULL;

        return node;
    }
    else
        return NULL;
}