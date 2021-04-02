#include "scan_lib.h"
void icmp_scan();
void tcp_scan();
void randnumber();
int sockfd;
struct sockaddr_in dest_addr, source_addr;
main() {
	tcp_scan();
}