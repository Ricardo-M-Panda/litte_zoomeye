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

/*--------------icmp-----------------*/
#define PACKET_SIZE     4096
#define ICMP_MAX_WAIT_TIME   0.3
#define MAX_ICMP_NO_PACKETS  3
#define MAX_IP_ADDRESS  200
#define ICMP_PACKET_DATE_LEN 56
/*定义网卡，用来开启混杂模式*/
#define ETH_NAME    "eth1"
/*--------------icmp-----------------*/

