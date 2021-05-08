#include "cJSON.h"
#include "cJSON.c"
#include "scan_lib.h"

#include <ctype.h>
#include <regex.h>

#define BUF_SIZE 4*1024
#define RLT_SIZE
#define RLUE_LEN 200
#define REV_LEN 100
#define MAX_REG 20
#define MAX_ENDING_00 15
#define HTTP_SERVER_BSS 7
int  catch_ssh(char rev_msg[]);
char** get_server_version(char* buf);

#define RULE_SIZE 2048
/*此函数使用过后，所返回的指针需要释放掉*/
char** use_reg(char text[], char  reg_str[], bool multiple);

void http_server(char* server);
/*向开放端口发起连接，（发送请求报文后）读取其回复报文*/
/*此函数有纰漏，超时会阻塞*/
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
	serv_adr.sin_addr.s_addr = inet_addr("118.240.106.105");
	serv_adr.sin_port = htons(atoi("9200"));

	if (connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
	{
		perror("coonetct() error");
		exit;
	}

	else
		puts("connected..........");
	recv_len = 0;
	i = 0;
	/*统一发送相同请求，忽略掉需要正确请求才可获得响应的协议*/
	char send_mes[] = "GET / HTTP/1.1 \r\n\r\n";

	write(sock, send_mes, RLUE_LEN);

	recv_len = read(sock, serv_msg, BUF_SIZE);
	/**/
	unsigned int rev_mes_len = strlen(serv_msg);
	close(sock);
	/*目标主机响应信息*/
	/*响应信息长度*/
	unsigned int len= rev_mes_len;
	/*获取响应信息的真实长度,防止被信息中的\x00符号误导,这里以 MAX_ENDING_00 即 10 个连续\x00作为结束符*/
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


/*协议上层组件分析，仅针对http上层应用*/

/*获取banner中的版本号*/
int catch_ssh(char rev_msg[]){
	FILE* fp;
	char str[RULE_SIZE];
	char* str_p;
	str_p = str;
	/*判断文件是否打开失败*/
	if ((fp = fopen("rule.json", "rb")) == NULL) {
		puts("Fail to open file!");
		exit(0);
	}
	int j = 0;
	/*循环读取文件的每一行数据*/
	fread(str, RULE_SIZE, 1, fp);

	/*操作结束后关闭文件*/
	fclose(fp);
	cJSON* root = cJSON_Parse(str);
	if (!root) {
		printf("get root faild !\n");
		return -1;
	}
	cJSON* js_protocol = cJSON_GetObjectItem(root, "protocol");
	if (!js_protocol) {
		printf("no protocol!\n");
		return -1;
	}
	int array_size = cJSON_GetArraySize(js_protocol);
	printf("array size is %d\n", array_size);
	int i = 0;
	for (int i = 0; i < array_size; i++) 
	{
		cJSON* item = cJSON_GetArrayItem(js_protocol, i);
		//char *str = cJSON_PrintUnformatted(item);
		cJSON* name = cJSON_GetObjectItem(item, "name");
		//printf("name type is %d\n", name->type);
		//printf("name:%s\n", name->valuestring);

		cJSON* key_string = cJSON_GetObjectItem(item, "key_string");
		//printf("key_string type is %d\n", key_string->type);
		//printf("key_string:%s\n", key_string->valuestring);

		cJSON* get_version_method = cJSON_GetObjectItem(item, "get_version_method");
		//printf("get_version_method type is %d\n", get_version_method->type);
		//printf("get_version_method:%s\n", get_version_method->valuestring);

		cJSON* get_version_bss = cJSON_GetObjectItem(item, "get_version_bss");
		//printf("get_version_bss type is %d\n", get_version_bss->type);
		//printf("get_version_bss:%d\n", get_version_bss->valueint);

		//char* first_char = strstr(rev_msg, key_string->valuestring);
		char* first_char = *use_reg(rev_msg, key_string->valuestring,0);
		/*char reg_str[] = "[0-9]+([.][0-9 a-z A-Z]+)+([- ][a-z A-Z 0-9]+)?";*/
		if (first_char)	
		{


			/*确定出协议类别后，尝试抓取它的版本*/
			char* banner_ver_tmp, *banner_ver;
			if (banner_ver_tmp = *use_reg(rev_msg, get_version_method->valuestring,0))
			{
				banner_ver = strdup(banner_ver_tmp+ get_version_bss->valueint);
				fprintf(stderr, "protocol is %s,and the version is :%s", name->valuestring, banner_ver);
			}
			else
				fprintf(stderr, "protocol is %s", name->valuestring);
			printf("\n\n!!!!!!!!\n\n");
			if (!strcmp(name->valuestring, "http"))
			{
				puts("\n$$$$$$$$$$$$$$$$$$$$$\n");
				http_server(rev_msg);
			}
			free(first_char);
			free(banner_ver_tmp);
			free(banner_ver);
			first_char = NULL;
			banner_ver = NULL;
			banner_ver_tmp = NULL;
			
			break;
		}
	}

	if (root)
		cJSON_Delete(root);
	return 0;
}
/*如果使用了multiple=1，返回值是一个指针数组，使用完毕后该数组的每一项指针都应释放掉*/
char ** use_reg(char text[],char  reg_str[],bool multiple) {
	char* text_copy=strdup(text);
	
	char* multiple_reg[MAX_REG];
	/*上述数组的计数器*/
	int multiple_seq = 0;
	int i;
	char ebuff[256];
	int ret;
	int cflags;
	regex_t reg;
	/*此处需优化*/
	regmatch_t rm[MAX_REG];
	char* part_str = NULL;

	cflags = REG_EXTENDED | REG_ICASE ;



	ret = regcomp(&reg, reg_str, cflags);
	if (ret)
	{
		regerror(ret, &reg, ebuff, 256);
		fprintf(stderr, "%s\n", ebuff);
		goto end;
	}
	while (text_copy)
	{
		ret = regexec(&reg, text_copy, MAX_REG, rm, 0);
		if (ret)
		{
			regerror(ret, &reg, ebuff, 256);
			fprintf(stderr, "%s\n", ebuff);
			goto end;
		}

		regerror(ret, &reg, ebuff, 256);
		fprintf(stderr, "result is:\n%s\n\n", ebuff);

		if (rm[0].rm_so > -1)
		{

			part_str = strndup(text_copy + rm[0].rm_so, rm[0].rm_eo - rm[0].rm_so);
			fprintf(stderr, "\n@@@@@result: %s @@@@@\n", part_str);
			/*仅一个匹配*/
			if (!multiple)
				break;
			/*多匹配*/
			multiple_reg[multiple_seq] = part_str;
			multiple_seq++;
			part_str = NULL;

			//free(part_str);
			//part_str = NULL;

			text_copy += rm[0].rm_eo;
			continue;
		}
	}
	free(text_copy);
	text_copy = NULL;

	//if (multiple)
	//{
	//	puts("\nwork!!");
	//	for (i = 0; i < MAX_REG; i++)
	//	{
	//		if (rm[i].rm_so > -1)
	//		{
	//			part_str = strndup(text + rm[i].rm_so, rm[i].rm_eo - rm[i].rm_so);
	//			fprintf(stderr, "\n%d is : %s\n", i, part_str);
	//			free(part_str);
	//			part_str = NULL;
	//		}
	//	}
	//}
	//else if(multiple==0)
	//{
	//	/*仅保留第一个最长匹配结果*/

	//	if (rm[0].rm_so > -1)
	//	{
	//		part_str = strndup(text + rm[0].rm_so, rm[0].rm_eo - rm[0].rm_so);
	//		fprintf(stderr, "@@@@@\nresult: %s\n@@@@@", part_str);
	//	}
	//}


end:
	regfree(&reg);
	if(multiple)
		return multiple_reg;
	else
		return &part_str;
}

void http_server(char * rev_msg) {
	//char* next_deli1, next_deli2;
	//char* deli1 = " ", * deli2 = "/";
	//char* pToken = strtok_r(server, deli1, &next_deli1);
	//while (pToken)
	//{
	//	ip_list[i] = inet_addr(pToken);

	//	i++;
	//	pToken = strtok_r(NULL, delimiter, &next_deli);

	//}
	char* server;
	puts("((((((((((((((((((((((((((((((((((((((((((");
	server=*use_reg(rev_msg, "server:.+", 0);
	if (!server)
		return;
	puts(server);
	char** multiple_reg;
	multiple_reg=use_reg(server+ HTTP_SERVER_BSS,"[a-zA-Z_\-]+(/[0-9a-zA-Z\.]+)" , 1);
	int i=0;
	while (multiple_reg[i])
	{
		//printf("\nreg %d is %s\n", i, multiple_reg[i]);
		char** split_result;
		split_result=get_server_version(multiple_reg[i]);
		printf("\nserver  %s  id :%d , and the version is %s !\n", split_result[0],i, split_result[1]);
		free(multiple_reg[i]);
		multiple_reg[i] = NULL;
		i++;
	}
	free(server);

	server = NULL;
	return;
}
/*默认只切分一次，分隔符为"/"*/
char** get_server_version(char* buf) {
	char* delimiter = "/", * next_deli = NULL;
	char* pToken = strtok_r(buf, delimiter, &next_deli);
	char* server_version[2];
	int i = 0;
	while (pToken)
	{
		server_version[i]=pToken;
		i++;
		pToken = strtok_r(NULL, delimiter, &next_deli);
	}
	return server_version;
}

