/******************************************************************************************************************
Copyright © 2011-2012, ABM Musa, University of Illinois at Chicago. All rights reserved.

Developed by:
ABM Musa
BITS Networked Systems Laboratory
University of Illinois at Chicago
http://www.cs.uic.edu/Bits

Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
and associated documentation files (the “Software”), to deal with the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions: -Redistributions of source code must retain the above copyright 
notice, this list of conditions and the following disclaimers. -Redistributions in binary form must 
reproduce the above copyright notice, this list of conditions and the following disclaimers in the 
documentation and/or other materials provided with the distribution. Neither the names of BITS Networked 
Systems Laboratory, University of Illinois at Chicago, nor the names of its contributors may be used 
to endorse or promote products derived from this Software without specific prior written permission.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT 
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
OR THE USE OR OTHER DEALINGS WITH THE SOFTWARE.
********************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <sys/socket.h>
#include <features.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <string.h>
#include <err.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "typedef.h"
#include "injector_data.h"


void create_ethernet_header(unsigned char *packet, u8 mac[])
{
	struct ethhdr *eth_hdr = (struct ethhdr*)packet;

	int i;

	eth_hdr->h_source[0] = 0xf7;
	for(i=1; i<6; i++)
		eth_hdr->h_source[i] = mac[i];

   	for(i=0; i<6; i++)
		eth_hdr->h_dest[i] = mac[i];

	eth_hdr->h_proto = htons(ETH_P_IP);
}


void create_ip_header(unsigned char *packet)
{
	struct iphdr *ip_header = (struct iphdr*)packet;

	ip_header->version = 4;
	ip_header->ihl = (sizeof(struct iphdr))/4 ;
	ip_header->tos = 0;
	ip_header->tot_len = htons(sizeof(struct iphdr)+sizeof(struct udphdr)+PAYLOAD_SIZE);
	ip_header->id = htons(111);
	ip_header->frag_off = 0;
	ip_header->ttl = 111;
	ip_header->protocol = IPPROTO_UDP;
	ip_header->saddr = inet_addr("192.168.1.1");
	ip_header->daddr = inet_addr("255.255.255.255");

	//compute checksum at the end
	ip_header->check = compute_ip_checksum((unsigned char *)ip_header, ip_header->ihl*4);
}


void create_udp_header(unsigned char *packet, int length){
	struct udphdr *udp_header = (struct udphdr*)packet;
	udp_header->source = htons(8000);
	udp_header->dest = htons(7); 
	udp_header->len = length;
	udp_header->check = 0; //not calculating checksum 	   
}


//Ref: richard stevens' book
unsigned short compute_ip_checksum(unsigned char *header, int len)
{
	long sum = 0;  /* assume 32 bit long, 16 bit short */
	unsigned short *ip_header = (unsigned short *)header;

	while(len > 1){
		sum += *((unsigned short*) ip_header)++;
		if(sum & 0x80000000)   /* if high order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if(len)       /* take care of left over byte */
		sum += (unsigned short) *(unsigned char *)ip_header;
          
	while(sum>>16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}


int inject_data_packet(pcap_t *handle, u8 mac[]){
	unsigned char payload[PAYLOAD_SIZE];
	
	int packet_len = sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr)+sizeof(payload);
	unsigned char packet[packet_len];
	memset(packet, 0, packet_len);

	create_ethernet_header( packet, mac );
	create_ip_header( packet+sizeof(struct ethhdr) );
	create_udp_header( packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct udphdr)+sizeof(payload) );
	memset(packet+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr), 'a', sizeof(payload));

	if( (pcap_inject(handle, packet, packet_len)) != packet_len ){
		perror("Error sending packet");
		return 1;
	}
	/*
	else{
		printf("sent successfully\n");
	}
	*/

	return 0;
}

