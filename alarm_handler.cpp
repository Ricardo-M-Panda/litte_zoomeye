#include "scan_lib.h"
/*接收进程的闹钟声*/
void alarm_handler(int sockfd)
{
    printf("\n--------------------PING END-------------------\n");
    close(sockfd);
    exit(1);

}