#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>

int main(){
	printf("Mysql client version: %s\n", mysql_get_client_info());
	MYSQL *con = mysql_init(NULL);

	if(con == NULL){
		fprintf(stderr, "%s\n", mysql_error(con));
		exit(-1);
	}

	if(mysql_real_connect(con, "localhost", "root", "kwchen", NULL, 0, NULL, 0) == NULL){
		fprintf(stderr, "%s\n", mysql_error(con));
		exit(-1);
	}

	if(mysql_query(con, "USE dnsprofile;select * from dn_profile;")){
		fprintf(stderr, "%s\n", mysql_error(con));
		exit(-1);
	}
	
	mysql_close(con);
	return 0;
}
