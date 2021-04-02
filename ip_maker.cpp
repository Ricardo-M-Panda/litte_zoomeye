#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
//点分ip4地址转long存储
#include <arpa/inet.h>

void file_delete(char* filename);
void file_read(char* filename);
void file_write(char* filename);
void get_ipList(char* filename);
//int main(int argc, char* argv[])
//{
//	char  *filename="ip_icmp";
//	get_ipList(filename);
//	
//	
//	
//}
///*获取待扫描ip清单*/
//void get_ipList(char* filename) {
//	int fd = open(filename, O_RDWR);
//	if (fd == -1)
//	{
//		printf("error is %s\n", strerror(errno));
//	}
//	else
//	{
//		//打印文件描述符号
//		printf("success fd = %d\n", fd);
//		char buf[200], * next_deli=NULL,*delimiter=",";
//		long ip_list[200];
//		int i = 0, str_len;
//		read(fd, buf, 200);
//		str_len= strlen(buf);
//		
//		if ((buf[str_len- 1]) == '\n')
//			(buf[str_len - 1]) ='\0';
//		char* pToken = strtok_r(buf, delimiter, &next_deli);
//
//
//		while (pToken)
//		{
//			ip_list[i] = inet_addr(pToken);
//			i++;
//			pToken=strtok_r(NULL, delimiter, &next_deli);
//		}
//		i = 0;
//		printf("%s", buf);
//		close(fd);
//	}
//}
//int main() {
//	int pid ;
//	pid = fork();
//	if (pid < 0)
//	{
//		printf("error");
//		exit(1);
//	}
//	if (pid > 0)
//	{
//		printf("I am the parent and pid id: %d ,my pid is : %d\n", pid, getpid());
//		wait(status);
//	}
//
//	if (pid == 0)
//	{
//		printf("I am the child and pid id: %d ,fatherpid is : %d ,my pid is : %d\n", pid,getppid(),getpid());
//		exit(1);
//	}
//
//	return(1);
//
//}

/*写文件*/
void file_write(char* filename) {
	int fd = open(filename, O_CREAT | O_RDWR | O_APPEND);
	if (fd == -1)
	{
		printf("error is %s\n", strerror(errno));
	}
	else
	{
		//打印文件描述符号
		printf("success fd = %d\n", fd);
		char s[100]; char* buf; int str_len;
		while (1) {
			puts("write:");
			gets(s);
			fflush(stdin);
			if (s[0] == 'q')
				break;
			puts(s);
			str_len = strlen(s);
			buf = (char*)malloc(str_len);
			strncpy(buf, s, str_len);
			puts(buf);
			write(fd, buf, str_len);
			printf("%s", buf);
			free(buf);
	
			
		}
		close(fd);

		

	}
}
/*读文件*/
void file_read(char* filename) {
	int fd = open(filename, O_CREAT | O_RDWR | O_APPEND);
	if (fd == -1)
	{
		printf("error is %s\n", strerror(errno));
	}
	else
	{
		//打印文件描述符号
		printf("success fd = %d\n", fd);
		char buf[200];
		read(fd, buf, 200);
		printf("%s", buf);
		close(fd);
	}
}
/*删除文件*/
void file_delete(char * filename) {
	if (remove(filename) == 0)
		printf("Removed %s.", filename);
	else
		perror("remove");
}
