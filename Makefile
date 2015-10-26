OBJS=main.o myprotocol.o ifutil.o netutil.o checksum.o debug.o 
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall
LDLIBS=-lpthread
TARGET=bridge
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)
