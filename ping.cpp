#include "scan_lib.h"


void send_packet(int sockfd, pid_t pid , struct sockaddr_in * dest_addr);

/*ip_list_len为待扫描ip项目数，此处用来告知接收进程最少应接收的数据包数量*/
void recv_packet(int sockfd, unsigned int ip_list_len);

/*获取待扫描ip清单*/
/*文件中读取ip（临时）*/
unsigned int get_ipList(char* filename, in_addr_t ip_list[]);
int do_promisc(void);
int check_nic(void);

//void tv_sub(struct timeval* out, struct timeval* in);





/*扫描主函数*/
void icmp_scan(int task)
{
    struct sockaddr_in dest_addr;
    /*进程码*/
    pid_t pid;
    int i, datalen = ICMP_PACKET_DATE_LEN;
    char* filename = "ip_icmp", * hostname = NULL;
    unsigned int ip_list_len;
    /*这个数组是用来存储被inet_addr函数转换的网络地址的*/
/*注意返回值虽然有的地方说明是unsigned long相同，但那是32位long*/
    in_addr_t ip_list[MAX_IP_ADDRESS];
    /*获取需要扫描的ip列表,该函数返回值为ip列表项目数*/
    if ((ip_list_len = get_ipList(filename,ip_list)) == 0)
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
        printf("\n--------------------START-------------------\n");
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
            send_packet(sockfd, pid,  &dest_addr);  /*发送所有ICMP报文*/
            i++;
        }
        close(sockfd);
        /*阻塞，等待接收进程结束并回收它*/
        int status;
        pid_t child_finish_pid = wait(&status);

        int sta = WEXITSTATUS(status);
        if (child_finish_pid != -1)
        {
            if (sta != 0)
                printf("\nChild process: %d exited normally and has been recycled\n", child_finish_pid);
            if (sta == 0)
                printf("\nChild process: %d failed to exit normally and  recycled\n", child_finish_pid);
        }
        else
            perror("wait error");

    }
    return;
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





