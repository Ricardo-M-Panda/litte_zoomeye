#include "scan_lib.h"

struct sockaddr_in dest_rst_addr;

/*rst_ack_seq是接收包的确认号，rst_seq则是序列号*/
unsigned int rst_ack_seq,rst_seq;
int sql_insert(char* sql_query);
int sql_select(char* select_query);

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
    /*回复syn+ack则该端口已打开，实际上对方也可能分两次发送，但此处不作考虑*/
    if (tcp->ack==1 && tcp->syn == 1)
    {

        *p_dest_port = ntohs(tcp->source);
        dest_rst_addr = *from_p;
        rst_ack_seq = tcp->ack_seq;
        rst_seq = tcp->seq;
        /*记录下ip和端口*/
        char* icmp_select_query = "select ipv4_address from ip_list";
        if (sql_select(icmp_select_query))
        {
            perror("\n sql select error\n");
            exit;
        }
        while ((row = mysql_fetch_row(sql_result)) != NULL) {
            printf("ip is %s , ", row);
            char* num_to_string;
            sprintf(num_to_string, "%d", ntohs(tcp->source));
            char insert_query[95];
            memset(insert_query, 0, sizeof(insert_query));
            strcat(insert_query, "INSERT INTO `");
            strcat(insert_query, inet_ntoa(from_p->sin_addr));
            strcat(insert_query, "` (`port`) VALUES(");
            strcat(insert_query, num_to_string);
            strcat(insert_query, ");");
            sql_insert(insert_query);
        }

        printf("\n%s port  %d is open \n", inet_ntoa(from_p->sin_addr), ntohs(tcp->source));
        
        
        
        /*控制权交回给调用程序，使其通过并发回复相应的rst包*/
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
        /*将结果记录在数据库中*/

        char insert_query[100];
        memset(insert_query, 0, sizeof(insert_query));
        strcat(insert_query, "INSERT INTO ip_list ( ipv4_address,ping_os)VALUES('");
        strcat(insert_query, inet_ntoa(from_p->sin_addr));
        strcat(insert_query, "','");
        strcat(insert_query, os);
        strcat(insert_query, "')");
        sql_insert(insert_query);
        return 1;
    }
    else
        return -1;
}