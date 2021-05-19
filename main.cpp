#include "scan_lib.h"
void icmp_scan();
void tcp_scan();
void alarm_time();
void fingerprint_protoctol();
int sockfd;
void file_write(char* filename);
int sql_init();
void sql_close();
int sql_insert(char* sql_query);
void creat_ipaddress_table(char* row);
void creat_ip_list_table();

struct sockaddr_in dest_addr, source_addr;

main(){
		if (sql_init())
	{
		perror("\n connect mysql error\n");
		exit;
	}
	fingerprint_protoctol();
		sql_close();

}

//main() {
//	if (sql_init())
//	{
//		perror("\n connect mysql error\n");
//		exit;
//	}
//
//	icmp_scan();
//	creat_ip_list_table();
//
//	
//
//
//	/*扫描活动ip的开放端口*/
//
//
//	tcp_scan();
//
//
//	/*将获取到的port、banner等指纹信息填充进去*/
//
//	sql_close();
//
//}
//
