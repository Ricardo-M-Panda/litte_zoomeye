#include "scan_lib.h"

#include <ctype.h>
#include <regex.h>

#define BUF_SIZE 4*1024
#define RLT_SIZE
#define RLUE_LEN 200
#define REV_LEN 100
#define MAX_REG 5
#define MAX_ENDING_00 15
void catch_server_name(char rev_msg[], unsigned int len);
void catch_ssh(char rev_msg[]);
char* use_reg(char text[], char  reg_str[]);
/*向开放端口发起连接，（发送请求报文后）读取其回复报文*/
void fingerprint_catch() {

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
	serv_adr.sin_addr.s_addr = inet_addr("117.247.227.146");
	serv_adr.sin_port = htons(atoi("9200"));

	if (connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
		perror("coonetct() error");
	else
		puts("connected..........");
	recv_len = 0;
	i = 0;
	char send_mes[] = "GET / HTTP/1.1 \r\n\r\n";

	write(sock, send_mes, RLUE_LEN);

	recv_len = read(sock, serv_msg, BUF_SIZE);
	/**/
	unsigned int rev_mes_len = strlen(serv_msg);
	close(sock);
	/*目标主机响应信息*/
	/*响应信息长度*/
	unsigned int len= rev_mes_len;
	/*获取响应信息的真实长度,这里以 MAX_ENDING_00: 10 个连续\0作为结束符*/
	int count_00=0,count_i=0;
	if (rev_mes_len < REV_LEN)
	{
		unsigned int max_len = BUF_SIZE - rev_mes_len;
		while (count_00 != MAX_ENDING_00 && count_i<(max_len))
		{
			if (serv_msg[rev_mes_len + count_i] == 0)
				count_00++;
			else
				count_00 = 0;
			count_i++;
		}
		len = rev_mes_len + count_i - MAX_ENDING_00;
	}

	printf("\n\n");

	
	/*ip、端口、banner存入数据库*/



	///*全文转小写，方便对比*/
	for (i = 0; i < len; i++)
	{
		/*将结束符 \0 替换为 ~ 从而方便处理（正则）字符串*/
		if (serv_msg[i] == 0)
		{
			serv_msg[i] = 126;
		}
		serv_msg[i] = tolower(serv_msg[i]);

	}
	puts(serv_msg);
	catch_ssh(serv_msg);
	/*分析协议*/


	
}

void catch_server_name(char rev_msg[], unsigned int len) {
	int i,j=0;
	printf("\n");
	printf("\n");

	char* first_char = strstr(rev_msg,"server");
	if (first_char)
	{
		while (first_char[j] != '\n' && j < len) 
			j++;
		/*此处也可考虑申请堆空间从而节省空间的使用*/
		char catch_id[REV_LEN / 2];
		/*得到的结果字符串也可能时多个以空白符分隔的网络组件名拼接起来的*/
		strncpy(catch_id, first_char, j);
		printf("\n");
		puts(catch_id);
	}
	else
		return;



}
/*协议分析*/


/*协议上层组件分析，仅针对http上层应用*/

/*获取banner中的版本号*/
void catch_ssh(char rev_msg[]){
	char* first_char = strstr(rev_msg, "server version ");
	char reg_str[] = "[0-9]+([.][0-9 a-z A-Z]+)+([- ][a-z A-Z 0-9]+)?";
	if (first_char)
	{
		use_reg(first_char, reg_str);
	}
}



char* use_reg(char text[],char  reg_str[]) {
	puts("!!!!!!");
	puts(text);
	puts(reg_str);
	puts("!!!!!!");
	int i;
	char ebuff[256];
	int ret;
	int cflags;
	regex_t reg;
	regmatch_t rm[MAX_REG];
	char* part_str = NULL;

	cflags = REG_EXTENDED | REG_ICASE;



	ret = regcomp(&reg, reg_str, cflags);
	if (ret)
	{
		regerror(ret, &reg, ebuff, 256);
		fprintf(stderr, "%s\n", ebuff);
		goto end;
	}

	ret = regexec(&reg, text, MAX_REG, rm, 0);
	if (ret)
	{
		regerror(ret, &reg, ebuff, 256);
		fprintf(stderr, "%s\n", ebuff);
		goto end;
	}

	regerror(ret, &reg, ebuff, 256);
	fprintf(stderr, "result is:\n%s\n\n", ebuff);

	for (i = 0; i < MAX_REG; i++)
	{
		if (rm[i].rm_so > -1)
		{
			part_str = strndup(text + rm[i].rm_so, rm[i].rm_eo - rm[i].rm_so);
			fprintf(stderr, "%s\n", part_str);
			free(part_str);
			part_str = NULL;
		}
	}

end:
	regfree(&reg);

	return 0;
}


