#include "scan_lib.h"


void send_tcp_packet();

/*ip_list_len为待扫描ip项目数，此处用来告知接收进程最少应接收的数据包数量*/
void tcp_recv_packet(unsigned int ip_list_len);

/*获取待扫描ip清单*/
/*文件中读取ip（临时）*/
unsigned int get_ipList(char* filename, in_addr_t ip_list[]);
int do_promisc(void);
int check_nic(void);
MYSQL_RES* sql_select(char* select_query);
//void tv_sub(struct timeval* out, struct timeval* in);



/*扫描主函数*/
void tcp_scan()
{

    /*进程码*/
    pid_t pid;
    int i, datalen = TCP_PACKET_DATE_LEN;
    char* filename = "ip_icmp", * hostname = NULL;
    unsigned int ip_list_len;
    /*这个数组是用来存储被inet_addr函数转换的网络地址的*/
    in_addr_t ip_list[MAX_IP_ADDRESS];
    /*获取需要扫描的ip列表,该函数返回值为ip列表项目数*/
    if ((ip_list_len = get_ipList(filename, ip_list)) == 0)
    {
        printf("ip list is none");
        exit;
    }
    struct hostent* host;
    struct protoent* protocol;
    unsigned long inaddr = 0;
    int size = 60 * 1024;

    if ((protocol = getprotobyname("tcp")) == NULL)
    {
        perror("getprotobyname");
        exit(1);
    }
    /*生成使用ICMP的原始套接字,这种套接字只有root才能生成*/
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
    {
        perror("socket error");
        exit(1);
    }
    /* 回收root权限,设置当前用户权限*/
    setuid(getuid());
    /*扩大套接字接收缓冲区到50K这样做主要为了减小接收缓冲区溢出的
      的可能性,若无意中ping一个广播地址或多播地址,将会引来大量应答*/
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    /*自己设置ip头*/
    const int on = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));


    /*本地ip*/
    memset(&source_addr, 0, sizeof(source_addr));
    char hname[128];
    struct hostent* hent;
    gethostname(hname, sizeof(hname));
    hent = gethostbyname(hname);
    printf("\nhostname: %s\n ", hent->h_name);
    //printf("address is: %s\n", inet_ntoa(*(struct in_addr*)(hent->h_addr)));
    memcpy((char*)&source_addr.sin_addr, hent->h_addr, hent->h_length);
    source_addr.sin_family = AF_INET;

    //source_addr.sin_addr.s_addr = inet_addr("192.168.1.108");
    source_addr.sin_port = htons(TCP_SEND_PORT);
    bind(sockfd, (struct sockaddr*)&source_addr, sizeof(source_addr));
    printf("\naddress is:%s \n port is: %d\n", inet_ntoa(source_addr.sin_addr), ntohs(source_addr.sin_port));
    /*双进程，一发一收*/
    pid = fork();

    if (pid < 0)
    {
        perror("creat fork error");
        exit(1);
    }
    /*-----------------------------------------------------------------------*/
    /*接收所有报文*/
    if (pid == 0)
    {

        printf("\n I am child,pid id :%d, getpid is %d \n", pid, getpid());
        /*混杂模式*/
        //do_promisc();
        tcp_recv_packet(ip_list_len);
        exit(1);
    }
    /*-----------------------------------------------------------------------*/


    /*发报文*/
    if (pid > 0) {
        printf("\n I am parent,pid id :%d \n", pid);
        bzero(&dest_addr, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;

        char* sql_ip_table = "SELECT `ipv4_address` FROM `ip_list` ";

        MYSQL_RES* sql_result;
        MYSQL_ROW row;
        if (!(sql_result = sql_select(sql_ip_table)))
        {
            perror("\n sql select error\n");
            exit;
        }
        printf("\n--------------------START-------------------\n");
        while ((row = mysql_fetch_row(sql_result)) != NULL) {
            printf("ip is %s ", row[0]);
            inaddr = inet_addr(row[0]);
            dest_addr.sin_addr.s_addr = inaddr;
            printf("TCP SCAN %s(%s): %d bytes data in SYN packets.\n",
                inet_ntoa(dest_addr.sin_addr),
                inet_ntoa(dest_addr.sin_addr), datalen);
            send_tcp_packet();  /*发送所有TCP报文*/
            i++;
        }
        close(sockfd);
        /*阻塞，等待接收进程结束并回收它*/
        int status;
        pid_t child_finish_pid = wait(&status);
        int sta = WIFEXITED(status);
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