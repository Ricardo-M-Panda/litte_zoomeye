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

#define PACKET_SIZE     4096
#define MAX_WAIT_TIME   5
#define MAX_NO_PACKETS  3
#define MAX_IP_ADDRESS  200
#define PACKET_DATE_LEN 56
/*����������������������ģʽ*/
#define ETH_NAME    "eth1"
char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];
unsigned long ip_list[MAX_IP_ADDRESS];
/*key��Ϊ���ؿ��ƽ��ܽ��̽���*/
int KEY;
/*������*/
pid_t pid;
struct sockaddr_in dest_addr;

struct sockaddr_in from;
//struct timeval tvrecv;

void alarm_handler(int sockfd);
unsigned short cal_chksum(unsigned short* addr, int len);
int pack(int pack_no);
void send_packet(int sockfd);
/*ip_list_lenΪ��ɨ��ip��Ŀ�����˴�������֪���ս�������Ӧ���յ����ݰ�����*/
void recv_packet(int sockfd,int ip_list_len);
int unpack(char* buf, int len);
void get_ipList(char* filename);
/*��ȡ���鳤��*/
int getArrayLen(unsigned long array[]);
int do_promisc(void);
int check_nic(void);
int getArrayLen(unsigned long array[])
{
    return (sizeof(array) / sizeof(array[0]));

}
//void tv_sub(struct timeval* out, struct timeval* in);
/*���ս��̵�������*/
void alarm_handler(int sockfd)
{
    KEY = 0;
    printf("\n--------------------PING END-------------------\n");
    close(sockfd);
    exit(1);

}
/*У����㷨*/
unsigned short cal_chksum(unsigned short* addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short* w = addr;
    unsigned short answer = 0;

    /*��ICMP��ͷ������������2�ֽ�Ϊ��λ�ۼ�����*/
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    /*��ICMP��ͷΪ�������ֽڣ���ʣ�����һ�ֽڡ������һ���ֽ���Ϊһ��2�ֽ����ݵĸ��ֽڣ����2�ֽ����ݵĵ��ֽ�Ϊ0�������ۼ�*/
    if (nleft == 1)
    {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}
/*����ICMP��ͷ*/
int pack(int pack_no)
{
    int i, packsize;
    struct icmp* icmp;
    //struct timeval* tval;
    icmp = (struct icmp*)sendpacket;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = pack_no;
    icmp->icmp_id = pid;
    packsize = 8 + PACKET_DATE_LEN;
    //tval = (struct timeval*)icmp->icmp_data;
    //gettimeofday(tval, NULL);    /*��¼����ʱ��*/
    icmp->icmp_cksum = cal_chksum((unsigned short*)icmp, packsize); /*У���㷨*/
    return packsize;
}
/*��������ICMP����*/
void send_packet(int sockfd)
{
    int packetsize, i, nsend = 0;
    for (i = 0; i < MAX_NO_PACKETS; i++) {
        nsend++;
        packetsize = pack(nsend); /*����ICMP��ͷ*/
        if (sendto(sockfd, sendpacket, packetsize, 0,
            (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0)
        {
            perror("sendto error");
            return;
        }
    }


}
/*��������ICMP����*/
void recv_packet(int sockfd,int ip_list_len)
{
    int n, nreceived = 0;
    socklen_t fromlen;


    fromlen = sizeof(from);
    while (KEY == 1)
    {
        if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0,
            (struct sockaddr*)&from, &fromlen)) < 0)
        {
            if (errno == EINTR)continue;
            perror("recvfrom error");
            continue;
        }
        if (unpack(recvpacket, n) == -1)continue;
        nreceived++;
        if (nreceived == ip_list_len)
        {
            /*�趨�źż�����*/
            printf("\n---------CLOCK!---------\n");
            if (signal(SIGALRM, alarm_handler)) {
                perror("signal sigalarm error");
            }
            /*ָ�����Ѿ����������٣����Ͱ���������Ӧ���յİ���*/
            /*��Ȼ�������յ�ʱ�䣨���ڿ�������ģʽ���ѽ��յĲ�һ�����Լ����ģ�*/
            alarm(3);
        }
        
    }
}
/*��ȥICMP��ͷ*/
int unpack(char* buf, int len)
{
    int i, iphdrlen;
    struct ip* ip;
    struct icmp* icmp;
    //struct timeval* tvsend;
    double rtt;
    ip = (struct ip*)buf;
    iphdrlen = ip->ip_hl << 2;    /*��ip��ͷ����,��ip��ͷ�ĳ��ȱ�־��4*/
    icmp = (struct icmp*)(buf + iphdrlen);  /*Խ��ip��ͷ,ָ��ICMP��ͷ*/
    len -= iphdrlen;            /*ICMP��ͷ��ICMP���ݱ����ܳ���*/
    if (len < 8)                /*С��ICMP��ͷ�����򲻺���*/
    {
        printf("ICMP packets\'s length is less than 8\n");
        return -1;
    }
    /*ȷ�������յ���ICMP�Ļ�Ӧ*/
    if (icmp->icmp_type == ICMP_ECHOREPLY)

    {
        //tvsend = (struct timeval*)icmp->icmp_data;
        //tv_sub(&tvrecv, tvsend);  /*���պͷ��͵�ʱ���*/
        //rtt = tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000;  /*�Ժ���Ϊ��λ����rtt*/
        /*��ʾ�����Ϣ*/
        printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n",
            len,
            inet_ntoa(from.sin_addr),
            icmp->icmp_seq,
            ip->ip_ttl,
            rtt);
        return 1;
    }
    else    
        return -1;
}




/*��ȡ��ɨ��ip�嵥*/
void  get_ipList(char* filename) {
    int fd = open(filename, O_RDWR);
    if (fd == -1)
    {
        printf("error is %s\n", strerror(errno));
    }
    else
    {
        /*��ӡ�ļ���������*/
        printf("success fd = %d\n", fd);
        char buf[200], * next_deli = NULL, * delimiter = ",";

        int i = 0, str_len;
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
        i = 0;

        close(fd);

    }
    exit;

}



/*������*/
main()
{
    KEY = 1;
    int i, datalen = PACKET_DATE_LEN;
    char* filename = "ip_icmp", * hostname = NULL;
    /*��ȡ��Ҫɨ���ip�б�*/
    get_ipList(filename);
    /*ip�б���Ŀ��*/
    int ip_list_len = getArrayLen(ip_list);
    unsigned long* ip_list_main;


    /*˫���̣�һ��һ��*/
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
    /*����ʹ��ICMP��ԭʼ�׽���,�����׽���ֻ��root��������*/
    if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0)
    {
        perror("socket error");
        exit(1);
    }
    /* ����rootȨ��,���õ�ǰ�û�Ȩ��*/
    setuid(getuid());
    /*�����׽��ֽ��ջ�������50K��������ҪΪ�˼�С���ջ����������
      �Ŀ�����,��������pingһ���㲥��ַ��ಥ��ַ,������������Ӧ��*/
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    /*��������ICMP����*/
    if (pid == 0)
    {
        printf("\n I am child,pid id :%d, getpid is %d \n", pid, getpid());
        // do_promisc();
        recv_packet(sockfd, ip_list_len);
    }
    if (pid > 0) {
        printf("\n I am parent,pid id :%d \n", pid);
        bzero(&dest_addr, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        i = 0;
        printf("\n--------------------PING START-------------------\n");
        while ((inaddr = ip_list[i]) != 0)
        {
            /*�ж�������������ip��ַ*/
            if (inaddr == INADDR_NONE)
            {
                if ((host = gethostbyname(hostname)) == NULL) /*��������*/
                {
                    perror("gethostbyname error");
                    exit(1);
                }
                memcpy((char*)&dest_addr.sin_addr, host->h_addr, host->h_length);
            }
            else    /*��ip��ַ*/
                dest_addr.sin_addr.s_addr = inaddr;
            /*��ȡmain�Ľ���id,��������ICMP�ı�־��*/
            printf("PING %s(%s): %d bytes data in ICMP packets.\n", inet_ntoa(dest_addr.sin_addr),
                inet_ntoa(dest_addr.sin_addr), datalen);
            send_packet(sockfd);  /*��������ICMP����*/
            i++;
        }
        close(sockfd);
        /*�������ȴ����ս��̽�����������*/
        int status;
        pid_t child_finish_pid=wait(&status);
       
        int sta = WEXITSTATUS(status);
        if (child_finish_pid != -1)
        {
            if (sta != 0)
                printf("\nChild process: %d exited normally and has been recycled\n", child_finish_pid);
            if (sta == 0)
                printf("\nChild process: %d failed to exit normally and has been recycled\n", child_finish_pid);
        }
        else
            perror("wait error");

    }
    return (1);
}


///*����timeval�ṹ���*/
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



/*����Ϊ�趨����ģʽ�ĺ���*/
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
        return 0; // �����Ѳ�������
    }
    else
    {
        printf("link down\n");
        close(skfd);
        return -1;
    }
}





