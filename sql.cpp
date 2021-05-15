#include "scan_lib.h"
#include <my_global.h>
#include <mysql.h>
MYSQL conn;
int res;
MYSQL_RES* sql_result;
MYSQL_ROW row;
int sql_init() {
    mysql_init(&conn);
    if (mysql_real_connect(&conn, "127.0.0.1", "root", "******", "scan", 0, NULL, 0))
    {
        printf("\n mysql is connected!\n");
        return 0;
    }

    else
    {
    /*    perror("\n connect mysql error\n");*/
        return -1;
    }

}

void sql_close() {
    mysql_close(&conn);
}

int sql_table_creat(char* sql_query) {
    char* insert_query = sql_query;
    printf("\nSQL语句: %s\n", insert_query);
    res = mysql_query(&conn, insert_query);
    if (!res) {
        printf("数据表创建成功\n");
        return 0;
    }
    else {
        fprintf(stderr, "创建数据表失败\n");
        return -1;
    }
}

void creat_ipaddress_table(char * row) {
    char icmp_creat_table_query[195];
    memset(icmp_creat_table_query, 0, sizeof(icmp_creat_table_query));
    strcat(icmp_creat_table_query, "CREATE TABLE IF NOT EXISTS `");
    strcat(icmp_creat_table_query, row);
    strcat(icmp_creat_table_query, "`(`port` int(4) not null primary key ,`banner` VARCHAR(4096),`protocol` VARCHAR(40),`pro_version` VARCHAR(40))ENGINE=InnoDB DEFAULT CHARSET=utf8;");
    sql_table_creat(icmp_creat_table_query);
}

int sql_insert(char * sql_query) {
    char * insert_query = sql_query;
    printf("\nSQL语句: %s\n", insert_query);
    res = mysql_query(&conn, insert_query);
    if (!res) {
        printf("数据插入成功 ：insert %lu rows\n", (unsigned long)mysql_affected_rows(&conn));
        return 0;
    }
    else {
        fprintf(stderr, "数据插入失败\n");
        return -1;
    }
}
int sql_select(char * select_query) {
    printf("SQL语句: %s\n", select_query);
    if (mysql_query(&conn, select_query) != 0) {
        fprintf(stderr, "查询失败\n");
        return -1;
    }
    else {
        if ((sql_result = mysql_store_result(&conn)) == NULL) {
            fprintf(stderr, "保存结果集失败\n");
            return -1;
        }
        else {
            printf("\n查询成功\n");
            return 0;
        }
    }
}
int sql_delete() {
    char str1[20];
    char delete_query[50] = "delete from person where name='";
    printf("姓名\n");
    scanf("%s", str1);
    strcat(delete_query, str1);
    strcat(delete_query, "'");
    printf("SQL语句: %s\n", delete_query);
    res = mysql_real_query(&conn, delete_query, (unsigned int)strlen(delete_query));
    if (!res) {
        printf("delete successful\n");
    }
    else {
        printf("delete error\n");
    }
}

int sql_pro()
{

}