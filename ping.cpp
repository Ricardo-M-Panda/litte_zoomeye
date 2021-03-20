#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include<stdlib.h>
#include <string.h>
#include <sys/time.h>
#include<string.h>
#include<sys/stat.h>
#include<fcntl.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#define PACKET_SIZE     4096
#define MAX_WAIT_TIME   5
#define MAX_NO_PACKETS  3
#define MAX_IP_ADDRESS  200
#define PACKET_DATE_LEN 56
/*定义网卡，用来开启混杂模式*/
#define ETH_NAME    "eth1"
char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];
unsigned long ip_list[MAX_IP_ADDRESS];

/*进程码*/
pid_t pid;
struct sockaddr_in dest_addr;

struct sockaddr_in from;
//struct timeval tvrecv;

void alarm_handler(int sockfd);
unsigned short cal_chksum(unsigned short* addr, int len);
int pack(int pack_no);
void send_packet(int sockfd);
/*ip_list_len为待扫描ip项目数，此处用来告知接收进程最少应接收的数据包数量*/
void recv_packet(int sockfd,int ip_list_len);
int unpack(char* buf, int len);
unsigned int get_ipList(char* filename);

int do_promisc(void);
int check_nic(void);

//void tv_sub(struct timeval* out, struct timeval* in);
/*接收进程的闹钟声*/
void alarm_handler(int sockfd)
{
    printf("\n--------------------PING END-------------------\n");
    close(sockfd);
    exit(1);

}
/*校验和算法*/
unsigned short cal_chksum(unsigned short* addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short* w = addr;
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
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}
/*设置ICMP报头*/
int pack(int pack_no)
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
    packsize = 8 + PACKET_DATE_LEN;
    //tval = (struct timeval*)icmp->icmp_data;
    //gettimeofday(tval, NULL);    /*记录发送时间*/
    icmp->icmp_cksum = cal_chksum((unsigned short*)icmp, packsize); /*校验算法*/
    return packsize;
}
/*发送三个ICMP报文*/
void send_packet(int sockfd)
{
    int packetsize, i, nsend = 0;
    for (i = 0; i < MAX_NO_PACKETS; i++) {
        nsend++;
        packetsize = pack(nsend); /*设置ICMP报头*/
        if (sendto(sockfd, sendpacket, packetsize, 0,
            (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0)
        {
            perror("sendto error");
            return;
        }
    }


}
/*接收所有ICMP报文*/
void recv_packet(int sockfd,int ip_list_len)
{
    int n, nreceived = 0,all_packet= (ip_list_len * MAX_NO_PACKETS);
    socklen_t fromlen;


    fromlen = sizeof(from);
    /*考虑两种情形，满足其一则结束接收包。*/
    /*1.已接受到所有发出去的包*/
    /*2.最多可等待时间已经用完，其中每个包以400ms为最大等待时间*/
                /*设定信号及闹钟*/
    if (signal(SIGALRM, alarm_handler)) {
        perror("signal sigalarm error");
    }
    double time = 0.3*all_packet;
    alarm(time);
    printf("\n---------CLOCK!-%f--------\n",time);

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
        if (unpack(recvpacket, n) == -1)
            continue;
        /*所发包=ip数*MAX_NO_PACKETS，此处接收也应如此*/
            nreceived++;
         printf("allpacket is :%d,nreceived is : %d ,ip_list_len is %d",all_packet,nreceived, ip_list_len);
        
    }
    return;
}
/*剥去ICMP报头*/
int unpack(char* buf, int len)
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
        if (ip->ip_ttl>128)
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
            inet_ntoa(from.sin_addr),
            icmp->icmp_seq,
            ip->ip_ttl,
            os);
        return 1;
    }
    else    
        return -1;
}




/*获取待扫描ip清单*/
unsigned int  get_ipList(char* filename) {
    int fd = open(filename, O_RDWR);
    unsigned int i = 0;
    if (fd == -1)
    {
        printf("error is %s\n", strerror(errno));
    }
    else
    {
        /*打印文件描述符号*/
        printf("success fd = %d\n", fd);
        char buf[200], * next_deli = NULL, * delimiter = ",";

        int  str_len;
        read(fd, buf, 200);
        str_len = strlen(buf);

        if ((buf[str_len - 1]) == '\n')
            (buf[str_len - 1]) = '\0';
        char* pToken = strtok_r(buf, delimiter, &next_deli);


        while (pToken)
        {
            ip_list[i] = inet_addr(pToken);

            i++;
            pToken = strtok_r(NULL, delimiter, &next_deli);
        }

        close(fd);

    }
    return i;

}



/*主函数*/
main()
{
    int i, datalen = PACKET_DATE_LEN;
    char* filename = "ip_icmp", * hostname = NULL;
    unsigned ip_list_len;
    /*获取需要扫描的ip列表,该函数返回值为ip列表项目数*/
    if ((ip_list_len = get_ipList(filename)) == 0)
    {
        printf("ip list is none");
        exit;
    }


    /*双进程，一发一收*/
    pid = fork();
    int sockfd;
    if (pid < 0)
    {
        perror("creat fork error");
        exit(1);
    }
    struct hostent* host;
    struct protoent* protocol;
    unsigned long inaddr = 0;
    int size = 50 * 1024;

    if ((protocol = getprotobyname("icmp")) == NULL)
    {
        perror("getprotobyname");
        exit(1);
    }
    /*生成使用ICMP的原始套接字,这种套接字只有root才能生成*/
    if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0)
    {
        perror("socket error");
        exit(1);
    }
    /* 回收root权限,设置当前用户权限*/
    setuid(getuid());
    /*扩大套接字接收缓冲区到50K这样做主要为了减小接收缓冲区溢出的
      的可能性,若无意中ping一个广播地址或多播地址,将会引来大量应答*/
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    /*接收所有ICMP报文*/
    if (pid == 0)
    {

        
        printf("\n I am child,pid id :%d, getpid is %d \n", pid, getpid());
        /*混杂模式*/
        //do_promisc();
        recv_packet(sockfd, ip_list_len);
    }
    if (pid > 0) {
        printf("\n I am parent,pid id :%d \n", pid);
        bzero(&dest_addr, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        i = 0;
        printf("\n--------------------PING START-------------------\n");
        while ((inaddr = ip_list[i]) != 0)
        {
            /*判断是主机名还是ip地址*/
            if (inaddr == INADDR_NONE)
            {
                if ((host = gethostbyname(hostname)) == NULL) /*是主机名*/
                {
                    perror("gethostbyname error");
                    exit(1);
                }
                memcpy((char*)&dest_addr.sin_addr, host->h_addr, host->h_length);
            }
            else    /*是ip地址*/
                dest_addr.sin_addr.s_addr = inaddr;
            printf("PING %s(%s): %d bytes data in ICMP packets.\n", inet_ntoa(dest_addr.sin_addr),
                inet_ntoa(dest_addr.sin_addr), datalen);
            send_packet(sockfd);  /*发送所有ICMP报文*/
            i++;
        }
        close(sockfd);
        /*阻塞，等待接收进程结束并回收它*/
        int status;
        pid_t child_finish_pid=wait(&status);
       
        int sta = WEXITSTATUS(status);
        if (child_finish_pid != -1)
        {
            if (sta != 0)
                printf("\nChild process: %d exited normally and has been recycled\n", child_finish_pid);
            if (sta == 0)
                printf("\nChild process: %d failed to exit normally and has been recycled\n", child_finish_pid);
        }
        else
            perror("wait error");

    }
    return (1);
}


///*两个timeval结构相减*/
//void tv_sub(struct timeval* out, struct timeval* in)
//{
//    if ((out->tv_usec -= in->tv_usec) < 0)
//    {
//        --out->tv_sec;
//        out->tv_usec += 1000000;
//    }
//    out->tv_sec -= in->tv_sec;
//}
///*------------- The End -----------*/



/*以下为设定混杂模式的函数*/
int do_promisc(void)
{

    int f, s;
    struct ifreq ifr;

    if ((f = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        return -1;
    }
    strcpy(ifr.ifr_name, ETH_NAME);

    if ((s = ioctl(f, SIOCGIFFLAGS, &ifr)) < 0)
    {
        close(f);
        return-1;
    }

    if (ifr.ifr_flags & IFF_RUNNING)
    {
        printf("eth link up\n");
    }
    else
    {
        printf("eth link down\n");
    }

    ifr.ifr_flags |= IFF_PROMISC;
    if ((s = ioctl(f, SIOCSIFFLAGS, &ifr)) < 0)
    {
        return -1;
    }

    printf("Setting interface ::: %s ::: to promisc\n\n", ifr.ifr_name);
    return 0;
}
int check_nic(void)
{
    struct ifreq ifr;
    int skfd = socket(AF_INET, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, ETH_NAME);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0)
    {
        close(skfd);
        return -1;
    }
    if (ifr.ifr_flags & IFF_RUNNING)
    {
        printf("link up\n");
        close(skfd);
        return 0; // 网卡已插上网线
    }
    else
    {
        printf("link down\n");
        close(skfd);
        return -1;
    }
}





