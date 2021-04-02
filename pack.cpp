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
struct tcp_option_mss {
    unsigned char option;
    unsigned char option_length;
    unsigned short option_value;
};
struct tcp_option_sack {
    unsigned char option;
    unsigned char option_length;
};

/*禁止自动对齐，防止对齐时自动填充nop*/
struct tcp_option_timestamp {
    unsigned char option;
    unsigned char option_length;
    unsigned long option_value;
}__attribute__((packed)) data;
struct tcp_option_nop {
    unsigned char option;

};
struct tcp_option_winows_sale {
    unsigned char option;
    unsigned char option_length;
    unsigned char option_value;
};

struct tcp_option {
    struct tcp_option_mss mss;
    struct tcp_option_sack sack;
    struct tcp_option_timestamp timestamp;
    struct tcp_option_nop nop;
    struct tcp_option_winows_sale windowssale;
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

    int i, packsize;
    /*设置IP头*/
    struct ip* ip = (struct ip*)sendpacket;
    ip->ip_v = IPVERSION;
    ip->ip_hl = sizeof(struct ip) / 4;
    ip->ip_tos = 0;
    /*暂时置为0，所有其他内容填好后，再写ip长度*/
    ip->ip_len = 0;
    ip->ip_id = 0;
    ip->ip_off = 0;
    ip->ip_ttl = rand()%30+24;
    ip->ip_p = IPPROTO_TCP;
    ip->ip_sum = 0;
    ip->ip_src.s_addr = source_addr.sin_addr.s_addr;
    if (flag == -1)
        ip->ip_dst.s_addr = dest_addr.sin_addr.s_addr;
    else
        ip->ip_dst.s_addr = dest_rst_addr.sin_addr.s_addr;
    struct tcphdr* tcp;
    //struct timeval* tval;

    /*以tcphdr结构操作套接字要发送的字节流*/
    tcp = (struct tcphdr*)(sendpacket+sizeof(*ip));
    tcp->source = source_addr.sin_port;
    tcp->dest = htons((unsigned short)randomport);

    
    
    tcp->res1 = 0;
    /* 先置0*/
    tcp->doff= 0;
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
    f_tcp.tcp_len = 0;
    /*计算校验和，先将伪首部和首部拼接起来*/
    /*首部最长60字节，伪首部12字节*/

    struct timeval tv;
    gettimeofday(&tv, NULL);
    /*TCP选项*/
    tcp_option* tcp_option =(struct tcp_option*)(sendpacket + sizeof(*ip)+sizeof(*tcp));
    tcp_option->mss.option = 2;
    tcp_option->mss.option_length = 4;
    tcp_option->mss.option_value = htons(1460);

    tcp_option->sack.option = 4;
    tcp_option->sack.option_length = 2;



    tcp_option->timestamp.option = 8;
    tcp_option->timestamp.option_length = 10;
    tcp_option->timestamp.option_value = htonl(tv.tv_sec * 1000 + tv.tv_usec / 1000);

    tcp_option->nop.option = 1;

    tcp_option->windowssale.option = 3;
    tcp_option->windowssale.option_length = 3;
    tcp_option->windowssale.option_value = 7;

    /*修正上面结构体中有关长度的字段，单独拿出来是方便后续更改*/
    unsigned int tcp_hdr_len = sizeof(*tcp) + sizeof(*tcp_option);
    tcp->doff = tcp_hdr_len/4;
    f_tcp.tcp_len = htons(tcp_hdr_len);

    /*计算tcp校验和*/
    packsize = tcp_hdr_len + TCP_PACKET_DATE_LEN;
    char buffers[256];
    memset(buffers, 0, 256);
    memcpy(buffers, &f_tcp, sizeof(f_tcp));
    memcpy(buffers + sizeof(f_tcp), tcp, sizeof(*tcp));
    memcpy(buffers + sizeof(f_tcp) + sizeof(*tcp), tcp_option, sizeof(*tcp_option));
    tcp->check = cal_chksum((unsigned short*)buffers, packsize);
    //memset(buffers, 0, 256);
    //memcpy(buffers, &f_tcp, sizeof(f_tcp));
    //memcpy(buffers + sizeof(f_tcp), &tcp, sizeof(tcp));
    //tcp->check = cal_chksum((unsigned short*)buffers, packsize);
    packsize += sizeof(*ip);
    ip->ip_len = packsize;
    return packsize;
}