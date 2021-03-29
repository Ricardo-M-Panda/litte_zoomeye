#include "scan_lib.h"
#define BUF_SIZE 64*1024
#define RLT_SIZE

struct mysql_packet {
	/*两部分1：n*/
	unsigned int version;
	unsigned int server_id;
	unsigned int random_num;


};

void fingerprint_scan() {
	int sock;
	char serv_msg[BUF_SIZE];
	int result, i, recv_len;
	struct sockaddr_in serv_adr;
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1)
	{
		perror("socket() error");
	}
	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family = AF_INET;
	serv_adr.sin_addr.s_addr = inet_addr("47.106.249.36");
	serv_adr.sin_port = htons(atoi("443"));

	if (connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
		perror("coonetct() error");
	else
		puts("connected..........");
	recv_len = 0;
	i = 0;

	char  send_msg[] = "GET / HTTP/1.1\r\nAccept:*//*\r\nAccept_language:zh-cn\r\nAccept-Encoding:gzip,deflate\r\nUser-Agent:Mozilla/4.0 (compatible;MSIE 5.5 Windows 98)\r\nHost: abc.abcdefg\r\nConnection:Keep-Alive\r\n\r\n";
	write(sock, send_msg, strlen(send_msg));
	recv_len = read(sock, serv_msg, BUF_SIZE);
	printf("%s", serv_msg);
	//char  send_msg[] = " mysql -u root -p ";
	/*
	for (i = 0; i < 100; i++) {
		printf("%c", serv_msg[i]);
	}*/


	close(sock);
}