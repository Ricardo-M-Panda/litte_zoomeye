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
void final_sql();
struct sockaddr_in dest_addr, source_addr;


main() {
	if (sql_init())
	{
		perror("\n connect mysql error\n");
		exit;
	}

	icmp_scan();

	creat_ip_list_table();

	tcp_scan();

	fingerprint_protoctol();

	final_sql();

	sql_close();

}
