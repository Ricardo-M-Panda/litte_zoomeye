#include "scan_lib.h"
void icmp_scan();
void tcp_scan();
void alarm_time();
void fingerprint_catch();
int sockfd;
void file_write(char* filename);

struct sockaddr_in dest_addr, source_addr;
main() {

	fingerprint_catch();
}