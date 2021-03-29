#include "scan_lib.h"

unsigned short cal_chksum(unsigned short* addr, int len);

/*设置ICMP报头*/
int pack(int pack_no, pid_t pid, char sendpacket[])
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