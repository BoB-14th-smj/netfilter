TARGET=netfilter
CC=gcc
CFLAGS=-g -Wall

all: $(TARGET)
	sudo iptables -F
	sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
	sudo iptables -A INPUT -j NFQUEUE --queue-num 0



$(TARGET): nfqnl_test.c pkt.c
	$(CC) $(CFLAGS) $^ -o $@ -lpcap -lnetfilter_queue

clean:
	rm -f $(TARGET) *.o
	sudo iptables -F
