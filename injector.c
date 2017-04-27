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
#include <pcap.h>
#include <sys/socket.h>
#include <features.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <err.h>
#include <arpa/inet.h>

#include "typedef.h"
#include <mac80211/linux/ieee80211.h>

//#include "packet_structs.h"
#include "injector.h"
#include "capcom.h"


struct radiotap{
	u8 version;
	u8 pad;
	u16 header_len;
	u32 present_flags;
	u16 tx_flags;
	u8 pad_retries;
	u8 rts_retries;
}__attribute__ ((packed));



void create_radiotap(unsigned char* packet){
	struct radiotap *radiotap_header=(struct radiotap*)packet;
	
	radiotap_header->version=0x0;
	radiotap_header->pad=0x0;
	radiotap_header->header_len=0x0c00; //change the size if radiotap struct is modified

	/* 
	 * http://www.radiotap.org/suggested-fields/TX%20flags
	 * http://www.radiotap.org/defined-fields/all
	 * order is little-endian
	 */
	radiotap_header->present_flags=0x00800100;
	
	radiotap_header->tx_flags=0x0800;
	radiotap_header->pad_retries=0x0;
	radiotap_header->rts_retries=0x0;
}


void create_rts(unsigned char* packet, u8 mac[], int type){
	struct ieee80211_rts *rts_frame = (struct ieee80211_rts*)packet;
	
	rts_frame->frame_control = htonl(0xb400);
	rts_frame->duration = htonl(0x0600);

	int i;
	//RA is the exact mac address
	for(i=0; i<6; i++) rts_frame->ra[i] = mac[i];
	
	//TA is the mac address first octate replaced by f2 for local injection
	if(type == INJECTION_TYPE_LOCAL){
		rts_frame->ta[0] = 0xf2;
		for(i=1; i<6; i++) rts_frame->ta[i] = mac[i];
	}
	//TA is the mac address first octate replaced by f3 for global injection
	else if(type == INJECTION_TYPE_GLOBAL){
		rts_frame->ta[0] = 0xf3;
		for(i=1; i<6; i++) rts_frame->ta[i] = mac[i];		
	}
	//TA is the mac address first octate replaced by f6 for assoc injection
	else if(type == INJECTION_TYPE_ASSOC){
		rts_frame->ta[0] = 0xf6;
		for(i=1; i<6; i++) rts_frame->ta[i] = mac[i];
	}
}

void print_hex(unsigned char *packet, int length){
	int i;
	for(i=0; i<length; i++){
		printf("%0x ", packet[i]);
	}
	printf("\n");
}


int inject_packet(pcap_t *handle, u8 mac[], int type){
	int packet_len = sizeof(struct radiotap) + sizeof(struct ieee80211_rts);
	unsigned char packet[packet_len];
	memset(packet,0,packet_len);

	//printf("inject_mac=%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	/*create radiotap header*/
	create_radiotap( packet );
	
	/* create RTS */
	create_rts( packet+sizeof(struct radiotap), mac, type );

	//print_hex(packet, packet_len);

	if( write(rawsock, packet, packet_len) != packet_len ){
		perror("error sending packet");
		return 1;
	}
	
	return 0;
}
