#include "scan_lib.h"
pid_t send_rst_pid;
void alarm_handler(int sig);
void child_handler(int sig);
icmp_result_list* icmp_unpack(char* buf, int len, struct sockaddr_in* from_p);
tcp_result_list * tcp_unpack(char* buf, int len, struct sockaddr_in* from_p, unsigned short* p_dest_port);
void send_one_packet(unsigned short randomport, char sendpacket[], int flag);
int sql_insert(char* sql_query);
void sql_close();

/*设定一个控制循环侦听结束的标志供给闹钟触发函数使用*/
bool icmp_recv_flag=1;
bool tcp_recv_flag = 1;

unsigned int port_flag=-1;
/*接收所有ICMP报文*/
void icmp_recv_packet( unsigned int ip_list_len)
{
    /*用来储存结果的链表*/
    icmp_result_list * head,* end,*node,*node_tmp;
    end = NULL; node = NULL;
    head =(icmp_result_list*)malloc(sizeof(icmp_result_list));
    head->icmp_os = NULL;
    head->ipaddress = NULL;
    head->next = NULL;
    end=head;
    struct sockaddr_in from;
    char recvpacket[PACKET_SIZE];
    int n, nreceived = 0, all_packet = (ip_list_len * MAX_ICMP_NO_PACKETS);
    socklen_t fromlen;
    fromlen = sizeof(from);
    /*考虑两种情形，满足其一则结束接收包。*/
    /*1.已接受到所有发出去的包*/
    /*2.最多可等待时间已经用完，其中每个包以400ms为最大等待时间*/
                /*设定信号及闹钟*/
    if (signal(SIGALRM, alarm_handler)) {
        perror("signal sigalarm error");
    }
    double time = ICMP_PACKET_WAIT_TIME * all_packet;
    time = time > ICMP_MAX_WAIT_TIME ? ICMP_MAX_WAIT_TIME : time;
    alarm(time);
    printf("\n---------CLOCK!-%f--------\n", time);

    /*此处时间为底线，用完则立刻停止*/
    while (nreceived<all_packet&& icmp_recv_flag)
    {

        if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0,
            (struct sockaddr*)&from, &fromlen)) < 0)
        {
            if (errno == EINTR)continue;
            perror("recvfrom error");
            continue;
        }
        node_tmp = icmp_unpack(recvpacket, n, &from);
        if (!node_tmp)
            continue;
        /*将该结果结点加入链表*/
        node = (icmp_result_list*)malloc(sizeof(icmp_result_list));
        node->icmp_os = strdup(node_tmp->icmp_os);
        node->ipaddress = strdup(node_tmp->ipaddress);
        node->next = NULL;
        free(node_tmp);
        node_tmp = NULL;
        end->next = node;
        end = node;
        node = NULL;

        /*所发包=ip数*MAX_ICMP_NO_PACKETS，此处接收也应如此*/
        nreceived++;

        printf("\nallpacket is :%d,nreceived is : %d ,ip_list_len is %d\n", all_packet, nreceived, ip_list_len);

    }
    if (icmp_recv_flag == 0)
        printf("icmp_recv_flag is change to %d", icmp_recv_flag);
    node = head->next;
    puts("list is working!");
    printf("head next is %s",head->next->ipaddress);
    while (node)
    {
        node_tmp = node;
        printf("\n os is : %s, ipv4 is %s\n", node->icmp_os, node->ipaddress);
        /*将结果记录在数据库中*/
        char insert_query[100];
        memset(insert_query, 0, sizeof(insert_query));
        strcat(insert_query, "INSERT INTO ip_list ( ipv4_address,ping_os)VALUES('");
        strcat(insert_query, node->ipaddress);
        strcat(insert_query, "','");
        strcat(insert_query, node->icmp_os);
        strcat(insert_query, "')");
        sql_insert(insert_query);

        /*清除结点*/
        node = node->next;
        free(node_tmp->icmp_os);
        node_tmp->icmp_os = NULL;
        free(node_tmp->ipaddress);
        node_tmp->ipaddress = NULL;
        free(node_tmp);
        node_tmp = NULL;
    }
    free(head);
    head = NULL;
    puts("work is ending!");
    close(sockfd);
    exit(1);
}




void tcp_recv_packet(unsigned int ip_list_len)
{
    /*用来储存结果的链表*/
    tcp_result_list* head, * end, * node, * node_tmp;
    end = NULL; node = NULL;
    head = (tcp_result_list*)malloc(sizeof(tcp_result_list));
    head->next = NULL;
    end = head;


    struct sockaddr_in from;
    struct sockaddr_in* dest_addr_p;
    unsigned short dest_port;
    unsigned int flag;
    char recvpacket[PACKET_SIZE];
    int n, nreceived = 0, all_packet = ip_list_len * MAX_TCP_PORT_PACKETS;
    socklen_t fromlen;


    fromlen = sizeof(from);
    /*考虑两种情形，满足其一则结束接收包。*/
    /*1.已接受到所有发出去的包*/
    /*2.最多可等待时间已经用完，其中每个包以400ms为最大等待时间*/
                /*设定信号及闹钟*/
    if (signal(SIGALRM, alarm_handler)) {
        perror("signal sigalarm error");
    }
    double time = TCP_PACKET_WAIT_TIME * all_packet;
    /*设置一个时间等待上限，避免浪费太多时间*/
    if (time > TCP_MAX_WAIT_TIME)
        time = TCP_MAX_WAIT_TIME;
    /*每接收到一个包就重新计时*/

    alarm(TCP_MAX_WAIT_TIME);
    printf("\n---------CLOCK!-%f--------\n", time);

    if (signal(SIGCHLD, child_handler)) {
        perror("signal sigchld error");
    }
    bool test = 1;
    /*此处时间为底线，用完则立刻停止*/
    while (tcp_recv_flag)
    {

        if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0,
            (struct sockaddr*)&from, &fromlen)) < 0)
        {
            if (errno == EINTR)continue;
            perror("recvfrom error");
            continue;
        }
        node_tmp = tcp_unpack(recvpacket, n, &from, &dest_port);
        if (!node_tmp)
            continue;


            send_rst_pid = fork();
            if (send_rst_pid < 0)
            {
                perror("send_rst_pid fork error");
            }
            else if (send_rst_pid == 0) {
                char sendpacket[PACKET_SIZE];
                send_one_packet(dest_port, sendpacket, flag);
                free(head);
                close(sockfd);
                exit(2);
            }

            port_flag = -1;

            puts("aaaaaaaa");
            printf("\n node ip is %s ,port is %d \n", node_tmp->ip,node_tmp->port);


                node = (tcp_result_list*)malloc(sizeof(tcp_result_list));

            //node = (tcp_result_list*)malloc(sizeof(tcp_result_list));
            node->ip = strdup(node_tmp->ip);
            node->port = node_tmp->port;
            node->next = NULL;
            free(node_tmp);
            node_tmp = NULL;

            end->next = node;
            end = node;

        /*所发包=ip数*MAX_ICMP_NO_PACKETS，此处接收也应如此*/
        nreceived++;
        printf("\nallpacket is :%d,nreceived is : %d ,ip_list_len is %d\n", all_packet, nreceived, ip_list_len);

    }
    node = head->next;
    end->next = NULL;
    while (node) {
        printf("\n node print %s\n",node->ip);

            char string_port[10];
            sprintf(string_port, "%d", node->port);
            char insert_query[100];
            memset(insert_query, 0, sizeof(insert_query));
            strcat(insert_query, "INSERT INTO `"); 
            strcat(insert_query, node->ip);
            strcat(insert_query, "`(`port`) VALUES( ");
            strcat(insert_query, string_port);
            strcat(insert_query, ")");
            sql_insert(insert_query);

            /*将结果记录在数据库中*/
            node_tmp = node;
            node = node->next;
            free(node_tmp->ip);
            node_tmp->ip = NULL;
            free(node_tmp);
            node_tmp = NULL;

    }
    free(head);
    puts("head has been free");
    close(sockfd);
    exit(1);
}