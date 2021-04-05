#include <stdio.h>
#include<time.h>
#include<math.h>
#include <stdlib.h>

#include <unistd.h>
#include <signal.h>
#define MAX_TCP_PORT_PACKETS 100
void timeover(int sig) {
    printf("\nhei\n");
    exit;
}
void alarm_time() {
    if (signal(SIGALRM, timeover)) {
        perror("signal sigalarm error");
    }
    alarm(3);
    int n = 10;
    while (1)
    {
        alarm(n--);
    }


}
