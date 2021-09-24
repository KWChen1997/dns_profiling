all:caller

caller:caller.c
	gcc -g -Wall -o $@ $^ `mysql_config --cflags --libs`
