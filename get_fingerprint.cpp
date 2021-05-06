#include "cJSON.h"
#include "cJSON.c"
#include "scan_lib.h"

#include <ctype.h>
#include <regex.h>

#define BUF_SIZE 4*1024
#define RLT_SIZE
#define RLUE_LEN 200
#define REV_LEN 100
#define MAX_REG 10
#define MAX_ENDING_00 15
int  catch_ssh(char rev_msg[]);


#define RULE_SIZE 2048
/*此函数使用过后，所返回的指针需要释放掉*/
char* use_reg(char text[], char  reg_str[], bool multiple);
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
	serv_adr.sin_addr.s_addr = inet_addr("127.0.0.1");
	serv_adr.sin_port = htons(atoi("22"));

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
	printf("\n!!!!!!!!!!!file!!!!!!!!!!!!!!!!!!!!\n");
	puts(str);
	printf("\n!!!!!!!!!!!file!!!!!!!!!!!!!!!!\n");
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
		printf("name type is %d\n", name->type);
		printf("name:%s\n", name->valuestring);

		cJSON* key_string = cJSON_GetObjectItem(item, "key_string");
		printf("key_string type is %d\n", key_string->type);
		printf("key_string:%s\n", key_string->valuestring);

		cJSON* get_version_method = cJSON_GetObjectItem(item, "get_version_method");
		printf("get_version_method type is %d\n", get_version_method->type);
		printf("get_version_method:%s\n", get_version_method->valuestring);

		cJSON* get_version_bss = cJSON_GetObjectItem(item, "get_version_bss");
		printf("get_version_bss type is %d\n", get_version_bss->type);
		printf("get_version_bss:%d\n", get_version_bss->valueint);

		//char* first_char = strstr(rev_msg, key_string->valuestring);
		char* first_char = use_reg(rev_msg, key_string->valuestring,0);
		/*char reg_str[] = "[0-9]+([.][0-9 a-z A-Z]+)+([- ][a-z A-Z 0-9]+)?";*/
		if (first_char)
		
		{
			/*确定出协议类别后，尝试抓取它的版本*/
			char* banner_ver_tmp, *banner_ver;
			if (banner_ver_tmp = use_reg(rev_msg, get_version_method->valuestring,0))
			{
				banner_ver = strdup(banner_ver_tmp+ get_version_bss->valueint);
				fprintf(stderr, "protocol is %s,and the version is :%s", key_string->valuestring, banner_ver);
			}
			else
				fprintf(stderr, "protocol is %s", key_string->valuestring);
			printf("\n\n!!!!!!!!\n\n");
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

char * use_reg(char text[],char  reg_str[],bool multiple) {
	puts("@@@@@@@@text and reg_str@@@@@@@@@@");
	puts(text);
	puts(reg_str);
	puts("@@@@@@@@text and reg_str@@@@@@@@@@");
	int i;
	char ebuff[256];
	int ret;
	int cflags;
	regex_t reg;
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

	ret = regexec(&reg, text, MAX_REG, rm, 0);
	if (ret)
	{
		regerror(ret, &reg, ebuff, 256);
		fprintf(stderr, "%s\n", ebuff);
		goto end;
	}

	regerror(ret, &reg, ebuff, 256);
	fprintf(stderr, "result is:\n%s\n\n", ebuff);
	if(multiple=1)
		for (i = 0; i < MAX_REG; i++)
		{
			if (rm[i].rm_so > -1)
			{
				part_str = strndup(text + rm[i].rm_so, rm[i].rm_eo - rm[i].rm_so);
				fprintf(stderr, "\n%d is : %s\n",i, part_str);
				free(part_str);
				part_str = NULL;
			}
		}
	/*仅保留第一个最长匹配结果*/

	if (rm[i].rm_so > -1)
	{
		part_str = strndup(text + rm[0].rm_so, rm[0].rm_eo - rm[0].rm_so);
		fprintf(stderr, "@@@@@\nresult: %s\n@@@@@", part_str);
	}

end:
	regfree(&reg);

	return part_str;
}

void http_server(char * server) {
	
}

