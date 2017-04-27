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


#include "typedef.h"

/*
 * record for a single mac for one second
 */
struct record{
	u32 epoch;
	s8 ssi;
	u8 frame_type;
	u8 frame_subtype;
	u8 mac[6];
};


/*
 * linked list node
 */
struct node{
	void *info; //record struct
	struct node *next;
};


/*
 * file header containing start epoch
 */
struct filehdr{
	u32 sec;
}__attribute__((packed));


/*
 * epoch value and count of macs observed in this epoch 
 */
struct epoch_info{
	u16 epoch_gap;	//gap from prev epoch, u8 may be used but little risky
	u8 count; 		//no of packets observed in this epoch
}__attribute__((packed));


struct epoch_info_abs{
	u32 epoch;	//absolute epoch
	u8 count;  //no of packets observed in this epoch
}__attribute__((packed));




/*
 * info for macs observed in an epoch
 */
struct file_info{
	u8 mac[6];
	s8 ssi;
	u8 frame_type;
	u8 frame_subtype;
	//unsigned cts:1; //if it is a cts packets; 1 means cts, 0 means other 
}__attribute__((packed));




/*
 * header of packet containing 1s info
 */
struct packet_header{
	u32 epoch;
	u8 count; 		//no of packets observed in this epoch
	u8 id;	//node name/id
}__attribute__((packed));



FILE *compact_fp; //file for compact ccap format logging
FILE *logerror_fp; //file for critical error during compact logging

void insert_tail(void *info);
int insert_info(void *info);
void *get_tail_info();
void free_list();
void display_list();
void write_to_file(int epoch_gap, int count);
void write_to_file_abs_epoch(int epoch, int count);
void read_from_file(char *filename);
void read_from_file_abs_epoch(char *filename);
//void send_data(int epoch, int count);
//void send_data_udp(char *server_ip, int epoch, int count);
void send_data_tcp(int remote_sock, int epoch, int count);
void send_data_udp(int remote_sock, struct sockaddr_in addr, int epoch, int count);
