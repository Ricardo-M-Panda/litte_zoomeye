#include "scan_lib.h"

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