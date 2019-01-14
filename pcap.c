#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#define LINE_LEN 16

void dispatcher_handler(u_char*,const struct pcap_pkthdr*,const u_char*);
int id=0;

int main(int argc,char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_app[32]={};
	struct bpf_program filter;
	bpf_u_int32 net;
	bpf_u_int32 mask;

	if(argc==1)
	{
		printf("Please input a .pcap file.\n");
		return -1;
	}

	if ((fp=pcap_open_offline(argv[1],errbuf))==NULL)
	{
		fprintf(stderr,"Unable to open the file %s.\n",argv[1]);
		return -1;
	}
	if(argc>=3)
	{
		for(int i=2;i<argc;i++)
		{
			strcat(filter_app,argv[i]);
			if(i!=argc)
				strcat(filter_app," ");
		}
		pcap_lookupnet(argv[1],&net,&mask,errbuf);
		if(pcap_compile(fp,&filter,filter_app,0,net)<0)
		{
			fprintf(stderr,"%s\n",pcap_geterr(fp));
			pcap_close(fp);
			return -1;
		}
		if(pcap_setfilter(fp,&filter)<0)
		{
			fprintf(stderr,"%s\n",pcap_geterr(fp));
			pcap_close(fp);
			return -1;
		}
	}
	pcap_loop(fp,0,dispatcher_handler,NULL);
	pcap_close(fp);
	return 0;
}	

void dispatcher_handler(u_char *temp1,const struct pcap_pkthdr *header,const u_char *pkt_data)
{
	struct in_addr addr;
	struct ether_header *eptr;
	struct iphdr *ipptr;
	struct tcphdr *tcpptr;
	u_char *ptr;
	
	id++;

	printf("ID:%d\n",id);
	printf("Packet length:\t\t%d\n",header->len);
	printf("Number of bytes:\t%d\n",header->caplen);
	printf("Recieved time:\t\t%s",ctime((const time_t*)&header->ts.tv_sec));

	eptr=(struct ether_header*)pkt_data;
	ptr=eptr->ether_dhost;
	int i=ETHER_ADDR_LEN;
	printf("Source Address:\t\t");
	do
	{
		printf("%s%x",(i==ETHER_ADDR_LEN)?"":":",*ptr++);
	}while(--i>0);
	printf("\n");
	
	/* IP packet */
//	printf("Now decoding the IP packet.\n");
	ipptr=(struct iphdr*)(pkt_data+sizeof(struct ether_header));
	printf("the IP packet total_length is:\t%d\n",ipptr->tot_len);
	printf("the IP protocol is:\t%d\n",ipptr->protocol);
	
	/* IP */
	addr.s_addr=ipptr->daddr;
	printf("Destination IP:\t\t%s\n",inet_ntoa(addr));
	addr.s_addr=ipptr->saddr;
	printf("Source IP:\t\t%s\n",inet_ntoa(addr));

	/* TCP packet */
//	printf("Now decoding the TCP packet.\n");
	tcpptr=(struct iphdr*)(pkt_data+sizeof(struct ether_header)+sizeof(struct iphdr));
	printf("Destination port:\t%d\n",ntohs(tcpptr->dest));
	printf("Source port:\t\t%d\n",ntohs(tcpptr->source));
	printf("\n");	
}
