#include "scan_lib.h"
/*剥去ICMP报头*/
int unpack(char* buf, int len, struct sockaddr_in* from_p)
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