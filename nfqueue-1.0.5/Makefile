CC = gcc
CC_FLAGS = -Wall -g
CC_LIBS = -lnetfilter_queue -lmnl

PROGS = filter


all: $(PROGS)
	
$(PROGS).o: $(PROGS).c
	$(CC) $(CC_FLAGS) -c -o $@ $^ $(CC_LIBS)

$(PROGS): $(PROGS).o
	$(CC) $(CC_FLAGS) -o $@ $^ $(CC_LIBS)

clean:
	rm -rf *.o $(PROGS)
