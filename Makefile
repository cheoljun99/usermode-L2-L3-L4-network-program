LDLIBS=-lpcap

all: usermode_L2_L3_firewall

main.o: mac.h ip.h ethhdr.h arphdr.h iphdr.h tcphdr.h udphdr.h checksum.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

iphdr.o: ip.h iphdr.h iphdr.cpp

tcphdr.o: tcphdr.h tcphdr.cpp

udphdr.o:udphdr.h udphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

checksum.o: iphdr.h ip.h tcphdr.h udphdr.h checksum.h checksum.cpp


usermode_L2_L3_firewall: main.o arphdr.o ethhdr.o ip.o mac.o iphdr.o tcphdr.o udphdr.o checksum.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f usermode_L2_L3_firewall *.o
