#pragma once
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
#include <linux/tcp.h>
#include<time.h>
#include<math.h>
#include "cJSON.h"
#include <mysql.h>
/*--------------icmp-----------------*/
#define PACKET_SIZE     1024
#define ICMP_MAX_WAIT_TIME   0.6
#define MAX_ICMP_NO_PACKETS  1
#define MAX_IP_ADDRESS  200
#define ICMP_PACKET_DATE_LEN 56
#define ICMP_SEND_RACE 1000
/*定义网卡，用来开启混杂模式*/
#define ETH_NAME    "eth1"
/*--------------icmp-----------------*/

/*--------------tcp------------------*/
#define TCP_PACKET_DATE_LEN 0
#define MAX_TCP_PORT_PACKETS 500
#define TCP_PACKET_WAIT_TIME 0.005
#define TCP_MAX_WAIT_TIME  5
#define TCP_SEND_PORT 44628
#define TCP_INIT_SEQ 1
#define TCP_WINDOW_SIZE 1024
#define TCP_SEND_RACE 100
/*--------------tcp------------------*/

/*---------------------全局变量-------------------------*/
extern int sockfd;
extern struct sockaddr_in source_addr ,dest_addr ;

/*---------------------全局变量-------------------------*/

/*-----------------------sql---------------------------*/
extern MYSQL conn;
extern int res;
extern MYSQL_RES* sql_result;
extern MYSQL_ROW row;

/*-----------------------sql---------------------------*/
