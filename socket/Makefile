CC = gcc
CFLAGS = -g -Wall
#CLIBS = -lnetfilter_queue 
PROGS = dnsparser
OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

.PRECIOUS: $(OBJS)

all: $(PROGS)

$(PROGS):$(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

clean:
	rm -f *.o $(PROGS)
