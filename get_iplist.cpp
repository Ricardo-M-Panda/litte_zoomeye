#include "scan_lib.h"

unsigned int  get_ipList(char* filename, in_addr_t ip_list[]) {
    /*这个数组是用来存储被inet_addr函数转换的网络地址的*/
/*注意返回值虽然有的地方说明是unsigned long相同，但那是32位long*/
    
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
        char buf[MAX_IP_ADDRESS], * next_deli = NULL, * delimiter = ",";

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

