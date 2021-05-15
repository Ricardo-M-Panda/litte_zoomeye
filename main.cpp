#include "scan_lib.h"
void icmp_scan();
void tcp_scan();
void alarm_time();
void fingerprint_catch();
int sockfd;
void file_write(char* filename);
int sql_init();
int sql_select(char * select_query);
void sql_close();
int sql_insert(char* sql_query);
void creat_ipaddress_table(char* row);
struct sockaddr_in dest_addr, source_addr;
main() {
	if (sql_init())
	{
		perror("\n connect mysql error\n");
		exit;
	}

	icmp_scan();


	/*为每个探测到的活动主机在数据库中生成自己的数据表*/
	char* icmp_select_query = "select * from ip_list";
	if (sql_select(icmp_select_query))
	{
		perror("\n sql select error\n");
		exit;
	}
	while ((row = mysql_fetch_row(sql_result)) != NULL) {
		printf("ip is %s , ", row[0]);
		creat_ipaddress_table(row[0]);
	}
	/*扫描活动ip的开放端口*/
	//tcp_scan();


	/*将获取到的port、banner等指纹信息填充进去*/

	sql_close();

}

