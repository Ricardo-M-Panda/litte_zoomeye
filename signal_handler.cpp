#include "scan_lib.h"
extern pid_t send_rst_pid;
/*接收进程的闹钟声*/
void alarm_handler(int sig)
{
    printf("\n--------------------END-------------------\n");
    close(sockfd);
    exit(1);

}
void child_handler(int sig)
{
    int status;
    pid_t child_finish_pid = waitpid(send_rst_pid,&status, WNOHANG);
    if(child_finish_pid )
        return;
    int sta = WEXITSTATUS(status);
    if (child_finish_pid != -1)
    {
        if (sta != 0)
            printf("\n TCP Child process: %d exited normally and has been recycled\n", child_finish_pid);
        if (sta == 0)
            printf("\n TCP Child process: %d failed to exit normally and  recycled\n", child_finish_pid);
    }

    return;
}