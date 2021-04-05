#include "scan_lib.h"
#include <cassert>
/*校验和算法*/
unsigned short cal_chksum(unsigned short* addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short* w ;
    w = addr;
    unsigned short answer = 0;

    /*把ICMP报头二进制数据以2字节为单位累加起来*/
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    /*若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加*/
    if (nleft == 1)
    {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    answer = ~sum;
    return answer;
}

uint16_t GetChecksum(const void* const addr, const size_t bytes)
{
    const uint16_t* word;
    uint32_t sum;
    uint16_t checksum;
    size_t nleft;
    assert(addr);
    assert(bytes > 8 - 1);
    word = (const uint16_t*)addr;
    nleft = bytes;
    /* 使用32 位累加器，顺序累加16 位数据，进位保存在高16 位 */
    for (sum = 0; nleft > 1; nleft -= 2)
    {
        sum += *word;
        ++word;
    }
    /* 如果总字节为奇数则处理最后一个字节 */
    sum += nleft ? *(uint8_t*)word : 0;
    /* 将进位加到低16 位，并将本次计算产生的进位再次加到低16 位 */
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    /* 结果取反并截低16 位为校验和 */
    return checksum = ~sum;
}