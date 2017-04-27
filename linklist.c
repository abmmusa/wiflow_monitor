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

/*
 * Generic single linked list
 */

#include<stdio.h>
#include<string.h>
#include<stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "linklist.h"
#include "helper.h"


struct node *head=NULL;
struct node *tail=NULL;

extern int mac_count_per_epoch;
extern int prev_epoch;

//extern int remote_sock;
//extern struct sockaddr_in addr; 

extern int node_id;

/*
 * insert into the tail of linked list
 */
void insert_tail(void *info){
	struct node *temp = (struct node*)malloc(sizeof(struct node));
	if(temp==NULL){
		fprintf(stderr, "Can't allocate memory!\n");
		exit(1);
	}

	temp->info=info;
	temp->next=NULL;
	
	if(head==NULL){
		head=temp;
		tail=temp;
	}else{	
		tail->next=temp;
		tail=temp;
	}	
}


/*
 * if the mac is already inseted into the linked list then it's record is updated
 * otherwise it is inserted in the tail. return 1 if inserted in the linked list and 
 * 0 if not inserted into the linked list so that the allocated memory can be freed 
 * for the record that is not inserted into linked list
 */ 
int insert_info(void *info){	
	/*cast the void info to record struct*/
	struct record *put_info = (struct record*)info;
	
	/*linked list node for iterration*/
	struct node *temp = head;
	
	while(temp != NULL){
		struct record *list_info;
		
		list_info = (struct record*)temp->info;
	
		if( mac_equality_check(put_info->mac, list_info->mac) ){ //this mac is inserted before, so update it
			if(put_info->ssi > list_info->ssi){ //current packet ssi is lower than prev ssi
				/*modify the ssi directly at the record in linklist node*/
				((struct record*)temp->info)->ssi = put_info->ssi;  
				((struct record*)temp->info)->epoch = put_info->epoch;  
			}
			/*return without inserting again in tail by executing code below*/
			return 0; 
		}
		temp=temp->next;
	}
	
	/*while loop terminated without finding the mac, hence insert in tail*/
	insert_tail(info);
	mac_count_per_epoch++;
	return 1;
}


/*
 * return tail info of the linked list
 */
void *get_tail_info(){
	if (tail!=NULL)
		return tail->info;
	return NULL;	
}


/*
 * free the memory of every record and nodes kept in linked list
 */
void free_list(){
	struct node *current = head;
	struct node *saved_next;
	while(current != NULL){
		saved_next = current->next;
		free(current->info);
		free(current);
		current = saved_next;
	}
	head=tail=NULL;	
}


/*
 * display the content of the linked list 
 */ 
void display_list(){
	if(head==NULL){
		return;
	}
	
	char mac[17];
	struct node *temp = head;
	while(temp != NULL){
		struct record *info = (struct record*)temp->info;
		sprintf(mac, "%02x-%02x-%02x-%02x-%02x-%02x", info->mac[0], info->mac[1], info->mac[2], info->mac[3], info->mac[4], info->mac[5]);
		printf("%d %d 0x%x%x %s\n", info->epoch, info->ssi, info->frame_type, info->frame_subtype, mac);
		temp=temp->next;
	}
}



/*
 * write epoch_info and file_info to file to prduce the compact log file with differential epoch
 */ 
void write_to_file(int epoch_gap, int count){
	if(head==NULL){
		return;
	}
	
	struct epoch_info einfo;
	einfo.epoch_gap = epoch_gap;
	einfo.count = count;
	fwrite(&einfo, sizeof(struct epoch_info), 1, compact_fp);
	//printf("debug %d %d %d\n", prev_epoch, epoch_gap, count);
	
	struct node *temp = head;
	struct record *info; 
	struct file_info finfo;
	while(temp != NULL){
		info = (struct record*)temp->info;
		int i;		
		for(i=0; i<6; i++)
			finfo.mac[i]=info->mac[i];
		finfo.ssi = info->ssi;
		finfo.frame_type = info->frame_type;
		finfo.frame_subtype = info->frame_subtype;
		fwrite(&finfo, sizeof(struct file_info), 1, compact_fp);
		//fflush(compact_fp); //remove if it's ok to write large chunk at a time
		//printf("debug %s %d\n", finfo.mac, finfo.ssi);
		temp=temp->next;
	}
}



/*
 * write epoch_info and file_info to file to prduce the compact log file with absoulte epoch
 */ 
void write_to_file_abs_epoch(int epoch, int count){
	if(head==NULL){
		return;
	}
	
	struct epoch_info_abs einfo;
	einfo.epoch = epoch;
	einfo.count = count;
	fwrite(&einfo, sizeof(struct epoch_info_abs), 1, compact_fp);
	//printf("debug %d %d %d\n", prev_epoch, epoch_gap, count);
	
	struct node *temp = head;
	struct record *info; 
	struct file_info finfo;
	int counter=0;
	while(temp != NULL){
		info = (struct record*)temp->info;
		memcpy(finfo.mac, info->mac, ETH_ALEN);
		finfo.ssi = info->ssi;
		finfo.frame_type = info->frame_type;
		finfo.frame_subtype = info->frame_subtype;
		fwrite(&finfo, sizeof(struct file_info), 1, compact_fp);
		temp=temp->next;
		counter++;
	}
	if(counter != count){
		fprintf(stderr, "CRITICAL: corrupted linked list for log\n");
		fprintf(logerror_fp, "CRITICAL: corrupted linked... Expected elements: %d, Actual elements:%d\n", count, counter);
		fflush(logerror_fp);
	}

}



/*
 * Send data for this epoch to the server. A single packet is constructed from 
 * an packet_header struct and multiple file_info struct. epoch info acts 
 * as a header to the packet and contains no of macs observed in this epoch. then 
 * the packet is filled up with the info of variable no of macs
 */

//TODO: update sent data with type_subtype
void send_data_tcp(int remote_sock, int epoch, int count){
	/* fill up packet header */
	struct packet_header header;
	header.epoch = epoch;
	header.count = count;
	header.id = node_id;
	
	/* Allocate buffer with fixed size epoch info header and variable size file_info with mac info*/
	int buffer_size = sizeof(struct packet_header) + count*sizeof(struct file_info);
	char *buffer = (char *)malloc(buffer_size);

	/* fill the buffer with packet header */
	memcpy(buffer, &header, sizeof(header));
	int offset = sizeof(header);
	
	/* fill the packet body with mac infos*/
	struct node *temp = head;
	struct record *info; 
	struct file_info finfo;
	
	while(temp != NULL){
		info = (struct record*)temp->info;
		int i;		
		for(i=0; i<6; i++)
			finfo.mac[i]=info->mac[i];
		finfo.ssi = info->ssi;
		
		memcpy(buffer+offset, &finfo, sizeof(finfo));
		offset += sizeof(finfo); 
		temp=temp->next;
	}
	
	/* send the packet using TCP*/
	int res = send(remote_sock, buffer, buffer_size, MSG_DONTWAIT);
	/*printf("buffer size=%d sent=%d\n\n", buffer_size, res); TODO: take option from command line and print if necessary*/
	if( res < 0 ){
		perror("Error sending");
	}

	
	free(buffer);	
		
}

//TODO: update sent data with type_subtype
void send_data_udp(int remote_sock, struct sockaddr_in addr, int epoch, int count){
	/* fill up packet header */
	struct packet_header header;
	header.epoch = epoch;
	header.count = count;
	header.id = node_id;
	
	/* Allocate buffer with fixed size epoch info header and variable size file_info with mac info*/
	int buffer_size = sizeof(struct packet_header) + count*sizeof(struct file_info);
	char *buffer = (char *)malloc(buffer_size);

	/* fill the packet header */
	memcpy(buffer, &header, sizeof(header));
	int offset = sizeof(header);
	
	/* fill the packet body with mac infos*/
	struct node *temp = head;
	struct record *info; 
	struct file_info finfo;
	
	while(temp != NULL){
		info = (struct record*)temp->info;
		int i;		
		for(i=0; i<6; i++)
			finfo.mac[i]=info->mac[i];
		finfo.ssi = info->ssi;
		
		memcpy(buffer+offset, &finfo, sizeof(finfo));
		offset += sizeof(finfo); 
		temp=temp->next;
	}
	
	/* send the packet usign UDP*/
	int res = sendto(remote_sock, buffer, buffer_size, 0, (struct sockaddr*)&addr,sizeof(addr));
	/*printf("buffer size=%d sent=%d\n\n", buffer_size, res); TODO: take option from command line and print if necessary*/
	if( res < 0 ){
		perror("Error sending");
	}
	
	free(buffer);	
}


/*
 * read records from compact file and output to the stdout (differential epoch format)
 */ 
void read_from_file(char *filename){
	FILE *readfile = fopen(filename, "r+");
	if(readfile == NULL){
		perror("Error opening file");
		exit(1);
	}
	
	int start_epoch=0, accumulated_epoch=0;
	int readbytes;	
	
	/*get the filehdr and show info*/
	struct filehdr fileh;
	readbytes = fread(&fileh, sizeof(struct filehdr), 1, readfile);
	printf("Start epoch=%d\n", fileh.sec);
	
	
	/*get info of packets after header from file and show the info*/	
	start_epoch = fileh.sec;
	accumulated_epoch = start_epoch;
	
	struct epoch_info einfo;
	struct file_info info; 
	
	int i;
	char mac[17];
	while( (readbytes=fread(&einfo, sizeof(struct epoch_info), 1, readfile)) ){
		if(readbytes==0) printf("0 bytes read for epoch_info struct\n");
		accumulated_epoch += einfo.epoch_gap;
		printf("%d %d\n", accumulated_epoch, einfo.count ); 
		for(i=0; i<einfo.count; i++){
			readbytes=fread(&info, sizeof(struct file_info), 1, readfile);
			if(readbytes==0){ 
				printf("0 bytes read for file_info struct\n");
				continue;
			}
			sprintf(mac, "%02x-%02x-%02x-%02x-%02x-%02x", info.mac[0], info.mac[1], info.mac[2], info.mac[3], info.mac[4], info.mac[5]);
			printf("%s %d 0x%x%x\n", mac, info.ssi, info.frame_type, info.frame_subtype);
		}
	}

	fclose(readfile);
}


/*
 * read records from compact file and output to the stdout (absolute epoch format)
 */ 
void read_from_file_abs_epoch(char *filename){
	FILE *readfile = fopen(filename, "r+");
	if(readfile == NULL){
		perror("Error opening file");
		exit(1);
	}
	
	int start_epoch;
	int readbytes;	
	
	/*get the filehdr and show info*/
	struct filehdr fileh;
	readbytes = fread(&fileh, sizeof(struct filehdr), 1, readfile);
	printf("Start epoch=%d\n", fileh.sec);
	
	/*get info of packets after header from file and show the info*/	
	start_epoch = fileh.sec;
	
	
	struct epoch_info_abs einfo;
	struct file_info info; 
	
	int i;
	char mac[17];
	while( (readbytes=fread(&einfo, sizeof(struct epoch_info_abs), 1, readfile)) ){
		if(readbytes==0) printf("0 bytes read for epoch_info struct\n");
		printf("%d %d\n", einfo.epoch, einfo.count ); 

		for(i=0; i<einfo.count; i++){
			readbytes=fread(&info, sizeof(struct file_info), 1, readfile);
			if(readbytes==0){ 
				printf("0 bytes read for file_info struct\n");
				continue;
			}
			sprintf(mac, "%02x-%02x-%02x-%02x-%02x-%02x", info.mac[0], info.mac[1], info.mac[2], info.mac[3], info.mac[4], info.mac[5]);
			printf("%s %d 0x%x%x\n", mac, info.ssi, info.frame_type, info.frame_subtype);
		}
	}

	fclose(readfile);
}




