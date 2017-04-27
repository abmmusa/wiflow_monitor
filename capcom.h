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


#ifndef CAPCOM_H
#define CAPCOM_H

#include "typedef.h"

//struct for command line options
struct options{
	bool display_flag; //-d flag
	
	bool recv_msg_from_fake_ap_flag; //-f flag
	
	bool local_all_injection_flag; //-I flag

	bool local_selected_injection_flag; //-J flag

	bool global_injection_flag; //-G flag
	
	bool assoc_rts_injection_flag; //-A flag

	bool assoc_data_injection_flag; //-D flag

	bool pcapread_flag; //-r option
	char *pcapread_file;
	
	bool ccapread_flag; //-R option
	char *ccapread_file;

	bool allread_flag; //-a option	
	char *allread_file;
	
	bool interface_flag; //-i option
	char *interface;
	
	bool compact_flag; //-w option
	char *compact_file;

	bool allpackets_flag; //-W option
	char *allpackets_file;
	
	bool senddata_flag; //-s option
	char *senddata_ip;
	
	bool id_flag;	//-n option
	char *id;

	bool log_flag; //-l option
	char *log_file;

	bool read_log_flag; //-L option
	char *read_log_file;

	bool allsmall_write_flag; //-c option
	char *allsmall_write_file;

	bool allsmall_read_flag; //-C option
	char *allsmall_read_file; 
	
	bool log_syslog_flag; //-y option
	char *log_syslog_file;

	bool read_syslog_flag;//-Y option
	char *read_syslog_file; 
}*options_args;


//#pragma pack(push, 1)
struct packetinfo{
	u16 caplen;
	u32 epoch;	
	unsigned datarate:6;	//change it to index of datarate later
	unsigned fcsbad:1;	//1 means bad fcs
	unsigned retry:1;	//1 means frame retransmitted
	s8 ssi;
	u8 frame_type;
	u8 frame_subtype;	
	u8 tx_addr[6];	//transmitter mac address
	u8 crc[4];
} __attribute__((packed));
//#pragma pack(pop)


struct packetinfo_small{
	u32 epoch;
	u8 frame_type;
	u8 frame_subtype;
	s8 ssi;
	u8 tx_addr[6];
}__attribute__((packed));


struct injection_log{
	u32 epoch;
	u8 addr[6];
}__attribute__((packed));


struct syslog_log{
	u32 epoch;
	u8 mac[6];
	u8 type;
	u8 wlanid;
}__attribute__((packed));

struct udp_message{
	u8 mac_addr[6];
	u8 type; //1 for association, 0 for disassociation
}__attribute__((packed));


//void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void handle_packet();
int insert_injection_data_structures(u8 addr[], int from_neighbour);
void process_args(int argc, char** argv);
void setifflags(char *ifname, int s, int value);
void alrm_handler(int sig);
void read_all_packets();
void read_all_packets_small();
void read_log();
void setup_server_connection();
void handle_lost_connection(int sig);
void *injector_thread_fun(void *arg);
void *syslog_thread_fun(void *arg);
void *periodic_task_thread_fun(void *arg);

void usage();


#define SNAPLEN 2000

#define PERIODIC_INTERVAL 60 //60 s



#define BAD_FCS_MASK 0x40
#define RETRY_MASK 0x08
#define SUBTYPE_MASK 0xf000
#define TYPE_MASK 0x0c00

#define TYPE_SUBTYPE_ACK 0xd400
#define TYPE_SUBTYPE_CTS 0xc400
#define TYPE_SUBTYPE_RTS 0xb400

#define PACKET_INJECTION_INIT_COUNT 50 //no of times a mac address will be injected
#define PACKET_INJECTION_INTERVAL 20000 //ms (interval between successive packet injection)


#define INJECTION_TYPE_LOCAL 0
#define INJECTION_TYPE_GLOBAL 1
#define INJECTION_TYPE_ASSOC 2

#define LOCAL_INJECTION_PREFIX 0xf2
#define GLOBAL_INJECTION_PREFIX 0xf3
#define ASSOC_INJECTION_PREFIX 0xf6


#define PORT_SYSLOG 8000
#define PORT_MSG_FAKE_AP 8050 


int rawsock;


#endif

