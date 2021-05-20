#include "scan_lib.h"

#include <ctype.h>
#include <regex.h>

#define BUF_SIZE 4*1024
#define RLT_SIZE
#define RLUE_LEN 200
#define REV_LEN 100
#define MAX_REV_LEN 4096
/*最大匹配数量*/
#define MAX_REG 20
/*组成字符串结束标志的连续的\00数量*/
#define MAX_ENDING_00 15
#define HTTP_SERVER_BSS 7
int  catch_fingerprint(char rev_msg[], char* finger_ip, char* finger_port,char* serv_msg_bak);
char** get_server_version(char* buf);

#define RULE_SIZE 2048
/*此函数使用过后，所返回的指针需要释放掉*/
void fingerprint_catch(char* finger_ip, char* finger_port);
char** use_reg(char text[], char  reg_str[], bool multiple);

void http_server(char* server , char* finger_port, char* ip);
MYSQL_RES* sql_select(char* select_query);
int sql_insert(char* sql_query);
int sql_update(char* update_sql_query);
/*向开放端口发起连接，（发送请求报文后）读取其回复报文*/
/*此函数有纰漏，超时会阻塞*/
void fingerprint_protoctol() {

	/*查询每个ip的端口*/
	char* sql_ip_table = "SELECT `ipv4_address` FROM `ip_list` ";
	
	MYSQL_RES* sql_result;
	MYSQL_ROW row;
	if (!(sql_result=sql_select(sql_ip_table)))
	{
		perror("\n sql select error\n");
		exit;
	}

	while ((row = mysql_fetch_row(sql_result)) != NULL) {
		printf("ip is %s ", row[0]);

		char sql_port[40];
		memset(sql_port, 0, sizeof(sql_port));
		strcat(sql_port, "SELECT `port` FROM `");
		strcat(sql_port, row[0]);
		strcat(sql_port, "`");
		MYSQL_RES* sql_port_res;
		MYSQL_ROW row_port;

		if (!(sql_port_res=sql_select(sql_port)))
		{
			perror("\n sql select error\n");
			continue;
		}
		printf("\nselect ip is %s \n",row[0]);
		while ((row_port = mysql_fetch_row(sql_port_res)) != NULL) {
			printf("\nselect ip is %s port is %s\n", row[0],row_port[0]);
			fingerprint_catch(row[0], row_port[0]);
		}

	}
	//char* the_ip = "47.111.11.142";
	//unsigned short the_port = 22;

}


void fingerprint_catch(char *finger_ip,char* finger_port) {

	int sock;
	char serv_msg[BUF_SIZE];
	int result, i, recv_len;
	struct sockaddr_in serv_adr;
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1)
	{
		perror("socket() error");
		return;
	}
	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family = AF_INET;

	serv_adr.sin_addr.s_addr = inet_addr(finger_ip);
	serv_adr.sin_port = htons(atoi(finger_port));

	if (connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
	{
		perror("coonetct() error");
		return;
	}

	else
		puts("connected..........");
	recv_len = 0;
	i = 0;
	/*统一发送相同请求，忽略掉需要正确请求才可获得响应的协议*/
	char send_mes[] = "GET / HTTP/1.1\r\n\r\n";

	write(sock, send_mes, RLUE_LEN);

	recv_len = read(sock, serv_msg, BUF_SIZE);

	
	puts(serv_msg);
	unsigned int rev_mes_len = strlen(serv_msg);
	close(sock);
	/*目标主机响应信息*/
	/*响应信息长度*/
	unsigned int len= rev_mes_len;
	/*获取响应信息的真实长度,防止被信息中的\x00符号误导,这里以 MAX_ENDING_00 即 15 个连续\x00作为结束符*/
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
	/*由于数据库中banner设置最长为4096，所以此处应该做下检测*/
	len = len < MAX_REV_LEN ? len:MAX_REV_LEN;
	printf("\n\n");

	
	/*ip、端口、banner存入数据库*/

	char* serv_msg_bak = NULL;
	/*拷贝一份响应报文的备份，供后续上传数据库使用*/
	/*但是应先对报文进行预处理，将报文中的单引号转换为两个单引号，防止sql语句被截断*/
	/*首先统计报文中的单引号数量*/
	serv_msg_bak = (char*)malloc(len);
	for (int i = 0, j = 0, k = -1; i < len,j<len; i++, j++)
	{
		serv_msg_bak[j] = serv_msg[i];

		if (serv_msg[i] == 39)
		{
			j++;
			serv_msg_bak[j] = 39;
		}
	}
	printf("\nthis is %s\n", serv_msg_bak);
	//free(serv_msg_bak);
	//serv_msg_bak = NULL;

	
	///*全文转小写，方便对比*/
	for (i = 0; i < len; i++)
	{
		/*将结束符 \0 替换为 ~ 从而方便处理（正则）字符串*/
		if (serv_msg[i] == 0)
		{
			serv_msg[i] = 126;
		}
		//serv_msg[i] = tolower(serv_msg[i]);

	}
	puts(serv_msg);




	catch_fingerprint(serv_msg, finger_ip, finger_port, serv_msg_bak);
	/*分析协议*/


	
}


/*协议上层组件分析，仅针对http上层应用*/

/*获取banner中的版本号*/
int  catch_fingerprint(char rev_msg[], char* finger_ip, char* finger_port,char* serv_msg_bak){
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
	char* result_verion=NULL, * result_protoctol=NULL;
	for (int i = 0; i < array_size; i++) 
	{
		cJSON* item = cJSON_GetArrayItem(js_protocol, i);
		cJSON* name = cJSON_GetObjectItem(item, "name");
		cJSON* key_string = cJSON_GetObjectItem(item, "key_string");
		cJSON* get_version_method = cJSON_GetObjectItem(item, "get_version_method");
		cJSON* get_version_bss = cJSON_GetObjectItem(item, "get_version_bss");
		char* first_char = *use_reg(rev_msg, key_string->valuestring,0);
		if (first_char)	
		{
			/*确定出协议类别后，尝试抓取它的版本*/
			char* banner_ver_tmp=NULL, *banner_ver=NULL;
			result_protoctol = strdup(name->valuestring);
			if (banner_ver_tmp = *use_reg(rev_msg, get_version_method->valuestring,0))
			{
				banner_ver = strdup(banner_ver_tmp+ get_version_bss->valueint);
				fprintf(stderr, "protocol is %s,and the version is :%s", name->valuestring, banner_ver);
				result_verion = strdup(banner_ver);
			}
			else
			{
				fprintf(stderr, "protocol is %s ,version is unknow", name->valuestring);
				result_verion = strdup("unknow");
			}
				
			printf("\n\n!!!!!!!!\n\n");

	
			/*存进数据库*/
			
			char port_info_update[4200];
			memset(port_info_update, 0, sizeof(port_info_update));
			strcat(port_info_update, "UPDATE `");
			strcat(port_info_update, finger_ip);
			strcat(port_info_update, "` SET `banner` = '");
			strcat(port_info_update, serv_msg_bak);
			strcat(port_info_update, "', `protocol` = '");
			strcat(port_info_update, result_protoctol);
			strcat(port_info_update, "', `pro_version` = '");
			strcat(port_info_update, result_verion);
			strcat(port_info_update, "' WHERE `port` = ");
			strcat(port_info_update, finger_port);
			printf("\n!!!!!!I AM BANNER!!!!!!%s\n", serv_msg_bak);

			sql_update(port_info_update);
			/*free掉之前申请的空间*/
			free(serv_msg_bak); serv_msg_bak = NULL;
			free(result_protoctol); result_protoctol = NULL;
			free(result_verion); result_verion = NULL;


			if (!strcmp(name->valuestring, "http"))
			{
				puts("\n$$$$$$$$$$$$$$$$$$$$$\n");
				http_server(rev_msg,finger_port, finger_ip);
			}
			free(first_char);
			free(banner_ver_tmp);
			if(banner_ver)
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
	int i = 0;
	char* multiple_reg[MAX_REG];
	for(i=0;i< MAX_REG;i++)
		multiple_reg[i]=NULL;
	/*上述数组的计数器*/
	int multiple_seq = 0;

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
	while (text_copy&& multiple_seq< MAX_REG)
	{
		ret = regexec(&reg, text_copy, MAX_REG, rm, 0);
		if (ret)
		{
			regerror(ret, &reg, ebuff, 256);
			fprintf(stderr, "%s\n", ebuff);
			goto end;
		}

		regerror(ret, &reg, ebuff, 256);
		fprintf(stderr, "\n\n result is:%s\n\n", ebuff);

		if (rm[0].rm_so > -1)
		{

			part_str = strndup(text_copy + rm[0].rm_so, rm[0].rm_eo - rm[0].rm_so);
			fprintf(stderr, "\n@@@@@reg is: %s @@@@@\n", part_str);
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

end:
	regfree(&reg);
	if(multiple)
		return multiple_reg;
	else
		return &part_str;
}

void http_server(char * rev_msg,char* finger_port, char* finger_ip) {

	char* server,* server_tmp;
	puts("((((((((((((((((((((((((((((((((((((((((((");
	server_tmp=*use_reg(rev_msg, "server:[^\r\n]+", 0);
	if (!server_tmp)
	{
		printf("\n no server! \n");
		return;
	}
	server = strdup(server_tmp);
	free(server_tmp);
	server_tmp = NULL;

	if (!server)
		return;
	puts(server);

	char* os_reg=NULL,*os_reg_tmp=NULL;
	if (os_reg_tmp = *use_reg(server, "\\([^\n]+\\)", 0))
	{
		size_t os_reg_len = strlen(os_reg_tmp);
		if (os_reg_tmp)
		{
			memset(strstr(server, os_reg_tmp), ' ', os_reg_len);
			os_reg = strndup(os_reg_tmp + 1, os_reg_len - 2);
			printf("\nos is %s\n", os_reg);
			free(os_reg);
			os_reg = NULL;
		}
	}
	
	puts(server);
	free(os_reg_tmp);
	os_reg_tmp = NULL;

	int i = 0,j=0;
	char** multiple_reg;
	multiple_reg=use_reg(server+ HTTP_SERVER_BSS,"[a-zA-Z_\-]+(/[0-9a-zA-Z\.\-]+)?" , 1);
	char** split_result=NULL; 	
	bool split_flag = false;
	while (multiple_reg[i])
	{
		printf("\n%s\n", multiple_reg[i]);

		split_result=get_server_version(multiple_reg[i]);
		bool cmp_flag = strcmp("unknow", split_result[1]);
		if (i == 0 && cmp_flag)
			split_flag = true;

		if (split_flag && !cmp_flag)
		{
			free(multiple_reg[i]);
			multiple_reg[i] = NULL;
			i++;
			continue;
		}

		printf("\nserver  %s  id :%d , and the version is %s !\n", split_result[0], j, split_result[1]);
		/*存储server进数据表*/	
		char insert_server_sql [200];
		memset(insert_server_sql, 0, sizeof(insert_server_sql));
		strcat(insert_server_sql, "INSERT INTO `server_list`(`server_name`, `ip`, `port`, `version`) VALUES('");
		strcat(insert_server_sql, split_result[0]);
		strcat(insert_server_sql, "', '");
		strcat(insert_server_sql, finger_ip);
		strcat(insert_server_sql, "', '");
		strcat(insert_server_sql, finger_port);
		strcat(insert_server_sql, "', '");
		strcat(insert_server_sql, split_result[1]);
		strcat(insert_server_sql, "')");
		sql_insert(insert_server_sql);

		j++;
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
	server_version[0] = "unknow";
	server_version[1] = "unknow";
	int i = 0;
	while (pToken)
	{
		server_version[i]=pToken;
		i++;
		pToken = strtok_r(NULL, delimiter, &next_deli);
	}
	return server_version;
}

