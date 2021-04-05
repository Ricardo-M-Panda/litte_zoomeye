#include "scan_lib.h"
struct sockaddr_in dest_rst_addr;
/*rst_ack_seq是接收包的确认号，rst_seq则是序列号*/
unsigned int rst_ack_seq,rst_seq;

unsigned int tcp_unpack(char* buf, int len, struct sockaddr_in * from_p ,unsigned short * p_dest_port  )
{
    int i, iphdrlen;
    struct ip* ip;
    struct tcphdr* tcp;
    //struct timeval* tvsend;
    char* os;
    
    ip = (struct ip*)buf;
    //printf("\ndst ip :%s\n", inet_ntoa(ip->ip_dst));
    //printf("\nsrc ip :%s\n", inet_ntoa(ip->ip_src));


    

    iphdrlen = ip->ip_hl << 2;    /*求ip报头长度,即ip报头的长度标志乘4*/
    tcp = (struct tcphdr*)(buf + iphdrlen);  /*越过ip报头,指向TCP报头*/
    len -= iphdrlen;            /*ICMP报头及ICMP数据报的总长度*/
    if (len < 20)                /*小于ICMP报头长度则不合理*/
    {
        printf("\nTCP packets\'s length is less than 20\n");
        return -1;
    }
    /*简单判断下，是否是回复自己的包*/

    if (tcp->dest != htons(TCP_SEND_PORT) )
    {
        return -1;
    }
    /*回复syn+ack则该端口已打开*/
    if (tcp->ack==1 && tcp->syn == 1)
    {

        *p_dest_port = ntohs(tcp->source);
        dest_rst_addr = *from_p;
        rst_ack_seq = tcp->ack_seq;
        rst_seq = tcp->seq;
        printf("\n%s port  %d is open \n", inet_ntoa(from_p->sin_addr), ntohs(tcp->source));
        /*控制权交回给调用程序，使其通过并发回复rst包*/
        return ntohl(tcp->seq);
    }
    else
        return -1;
}

/*剥去ICMP报头*/
int icmp_unpack(char* buf, int len, struct sockaddr_in* from_p)
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
        return -1;
    }
    /*确保所接收的是ICMP的回应*/
    if (icmp->icmp_type == ICMP_ECHOREPLY)

    {
        //tvsend = (struct timeval*)icmp->icmp_data;
        //tv_sub(&tvrecv, tvsend);  /*接收和发送的时间差*/
        //rtt = tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000;  /*以毫秒为单位计算rtt*/
        /*显示相关信息*/
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
        printf("\n %d byte from %s: icmp_seq=%u ttl=%d OS : %s \n",
            len,
            inet_ntoa(from_p->sin_addr),
            icmp->icmp_seq,
            ip->ip_ttl,
            os);
        return 1;
    }
    else
        return -1;
}