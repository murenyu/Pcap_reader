all:pcap.c
	gcc pcap.c -o pcap -lpcap
clear:
	rm pcap
