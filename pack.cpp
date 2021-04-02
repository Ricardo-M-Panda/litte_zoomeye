#include "scan_lib.h"
extern sockaddr_in dest_rst_addr;
extern unsigned int rst_seq, rst_ack_seq;
struct tcp_false_hdr
{
    unsigned int  src_ip;
    unsigned int  dst_ip;
    unsigned char zero,protocol;
    unsigned short tcp_len;
};

/*带有选项字段的首部*/
struct tcp_option_hdr {
    struct tcphdr  tcp_hdr;
    unsigned char option;
    unsigned char option_length;
    unsigned short option_value;

};

unsigned short cal_chksum(unsigned short* addr, int len);
/*设置ICMP报头*/
int icmp_pack(int pack_no, pid_t pid, char sendpacket[])
{
    int i, packsize;
    struct icmp* icmp;
    //struct timeval* tval;
    icmp = (struct icmp*)sendpacket;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = pack_no;
    /*此处pid为主进程fork后得到的子进程id,用于设置ICMP的标志符*/
    icmp->icmp_id = pid;
    packsize = 8 + ICMP_PACKET_DATE_LEN;
    //tval = (struct timeval*)icmp->icmp_data;
    //gettimeofday(tval, NULL);    /*记录发送时间*/
    icmp->icmp_cksum = cal_chksum((unsigned short*)icmp, packsize); /*校验算法*/
    return packsize;
}



/*设置TCP报头*/
int tcp_pack(unsigned short randomport, char sendpacket[],int flag)
{
    ///*本机套接字分配的ip地址*/
    //struct sockaddr_in clientAddr;
    //socklen_t clientAddrLen = sizeof(clientAddr);
    //if (getsockname(*p_sockfd, (struct sockaddr*)&clientAddr, &clientAddrLen) == -1) {
    //    printf("getsockname error: %s(errno: %d))\n", strerror(errno), errno);
    //    exit(0);
    //}
    int i, packsize;
    struct tcphdr* tcp;
    //struct timeval* tval;

    /*以tcphdr结构操作套接字要发送的字节流*/
    tcp = (struct tcphdr*)sendpacket;
    tcp->source = source_addr.sin_port;
    tcp->dest = htons((unsigned short)randomport);

    
    
    tcp->res1 = 0;
    /* +1: 设置一个4字节的MSS选项,后续应化简 */
    tcp->doff= (sizeof(struct tcphdr) / 4)+1;
    tcp->fin = 0;
    /*根据flag判断发送syn还是rst*/


    tcp->psh = 0;
    tcp->ack = 0;
    tcp->urg = 0;
    tcp->ece = 0;
    tcp->cwr = 0;
    tcp->window= htons(TCP_WINDOW_SIZE);
    /*校验算法*/
    tcp->check=0;
    tcp->urg_ptr=0;
    
    /*伪头部*/
    struct tcp_false_hdr f_tcp;
    f_tcp.src_ip = source_addr.sin_addr.s_addr;
    if (flag == -1) {
        tcp->seq = htonl(TCP_INIT_SEQ);
        tcp->ack_seq = 0;//
        tcp->syn = 1;
        tcp->rst = 0;
        /*dest_addr是全局变量，可能在此处被修改，在此处添加一个判断作为测试*/
        f_tcp.dst_ip = dest_addr.sin_addr.s_addr;
    }
    else
    {
        tcp->seq = rst_ack_seq;
        tcp->ack_seq = htonl(ntohl(rst_seq) + 1);//
        tcp->syn = 0;
        tcp->rst = 1;
        f_tcp.dst_ip = dest_rst_addr.sin_addr.s_addr;
    }
    f_tcp.zero = 0;
    f_tcp.protocol = IPPROTO_TCP;
    f_tcp.tcp_len = htons(sizeof(tcphdr)+4);
    /*计算校验和，先将伪首部和首部拼接起来*/
    /*首部最长60字节，伪首部12字节*/

    tcp_option_hdr * p_tcp_option_hdr;
    /*以选项套接字格式操作要发送的字节流*/
    p_tcp_option_hdr = (tcp_option_hdr*)sendpacket;
    p_tcp_option_hdr->option = 2;

    p_tcp_option_hdr->option_length = 4;
    p_tcp_option_hdr->option_value = htons(1460);
    packsize = sizeof(*p_tcp_option_hdr) + TCP_PACKET_DATE_LEN;
    char buffers[256];
    memset(buffers, 0, 256);
    memcpy(buffers, &f_tcp, sizeof(f_tcp));
    memcpy(buffers + sizeof(f_tcp), p_tcp_option_hdr, sizeof(*p_tcp_option_hdr));
    tcp->check = cal_chksum((unsigned short*)buffers, packsize);
    //memset(buffers, 0, 256);
    //memcpy(buffers, &f_tcp, sizeof(f_tcp));
    //memcpy(buffers + sizeof(f_tcp), &tcp, sizeof(tcp));
    //tcp->check = cal_chksum((unsigned short*)buffers, packsize);
    return packsize;
}