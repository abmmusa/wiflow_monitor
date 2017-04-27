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
 * Capture packets from pcap file or live interface and store various info from radiotap and 802.11 header 
 * in compact way.
 *
 * Data aggregation and blacklisting overview: 
 * Packets are captured live from a monitor interface or offline pcap log file. Then the relevant info from
 * the packets can be saved in a compact file. Compact file saving is achieved by following two heuristics
 * 1) Only the max signal strength packet from a particular mac is saved for an epoch/second rather than
 *    all packets to reduce storage
 * 2) Packets from a mac is not saved if it is stationary and hence transmitting packets all the time. Following
 *    algorithm is used for determining stationary macs
 *		
 *		if (total_epoch_observed > blacklisting time) then 
 *			blacklisted = true
 *
 *		if (current_epoch - last_epoch_of_mac > expiary time) then
 *			remove from table //reduce storage and avoid potential memory shortage 
 *
 * The implementation strategy is following. After receiving a packet it is inserted into a hashmap with chaining
 * that contain one record per mac consisting of accouting information for decision making of blacklisting of 
 * stationary nodes. If a mac is not blaclisted then it it's info is inserted into a linked list. Then at the end of
 * the epoch all the macs with info is written to disk and the linked list is freed and same thing is done for next
 * epoch. 
 *
 * Injection Overview:
 * There are two types of injection, local and global. Whenever the monitor hears a MAC, it starts sending RTS packets
 * to it so that it can get CTS packets back from it. However, CTSs don't have tx address, it is just transmitted with 
 * rx address corresponding to the tx address of RTS. So the RTS are sent with fake mac address (f2 in the first octate 
 * of the target device) and mapped back to the original address using a hashmap. For global injection, the monitor 
 * listen to neighbour RTS packets and start transmitting RTS using that. 
 *
 * ABM Musa <amusa2@uic.edu>
 *
 */

/*
 * TODO: 
 * -record is updated with type_subtype for each mac in addition of ssi. This is changed in writing to file and reading
 *  reading from file. But need to update for transmission to the server and also the server need to be updated.
 * -global rts injection logic is not totally correct. when a monitor inject by hearing from neighbour and if it get a cts back
 *  for that injected rts then it should now consider it as it's own local injection. it is not implemented yet
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <math.h>
#include <asm/byteorder.h>
#include <err.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "capcom.h"
#include <mac80211/linux/ieee80211.h>

#include "packet_structs.h"
#include "linklist.h"
#include "hashmap.h"
#include "queue.h"
#include "hashmap_generic.h"
#include "injector.h"
#include "injector_data.h"
#include "helper.h"
#include "globals.h"



/*uncomment to enable tcp connection to server instead of udp*/
//#define TCP

/*uncomment to enable differential logging of epoch is compact logging file*/
//#define DIFFERENTIAL_EPOCH_LOGGING


void handle_rts(struct ieee80211_hdr *wifi_hdr, struct packetinfo *info, u32 cur_sec){
	if(wifi_hdr->addr2[0] == LOCAL_INJECTION_PREFIX){ //RTS generated by neighbour; ignore 0xf3 as they are indirect
		//if global injection is enable then fill injection data structres
		if(options_args->global_injection_flag){
			int is_inserted=insert_injection_data_structures(wifi_hdr->addr1, 1);
			if(is_inserted){ //if inserted in injection data-structures
				if(options_args->log_flag){ //if logging is enabled
					struct injection_log inj_log;
					inj_log.epoch = cur_sec;
					memcpy(inj_log.addr, wifi_hdr->addr1, ETH_ALEN);

					fwrite(&inj_log, sizeof(struct injection_log), 1, log_fp);
				}

				if(options_args->display_flag){
					printf("******************* RTS used from neighbour: ");
					char mac[20];
					printf("%s ", hwaddr_ntoa(wifi_hdr->addr1, mac));
					printf("%s\n", hwaddr_ntoa(wifi_hdr->addr2, mac));
						
				}
			}
		}
	}
	else if(wifi_hdr->addr2[0] == GLOBAL_INJECTION_PREFIX){
		if(options_args->display_flag){
			char mac[20];
			printf("indirect ");
			printf("%s \n", hwaddr_ntoa(wifi_hdr->addr2, mac));
		}
			
		/*do nothing for indirect RTSs*/
		return;
	}
	else{ 
		/*other RTS, so just use the tx address*/
		memcpy(info->tx_addr, wifi_hdr->addr2, ETH_ALEN);
	}

}


void handle_cts(struct ieee80211_hdr *wifi_hdr, struct packetinfo *info){
	/*if CTS for local injection*/
	if( wifi_hdr->addr1[0] == LOCAL_INJECTION_PREFIX && (options_args->local_all_injection_flag || options_args->local_selected_injection_flag) ){
		char fake_mac[15];
		hwaddr_ntoa_no_colon(wifi_hdr->addr1, fake_mac);

		if( pthread_mutex_lock(&mutex_q_hmap) != 0 ) perror("mutex lock failed");
		struct entry *hm_entry = lookup_generic(H, fake_mac);
		if( pthread_mutex_unlock(&mutex_q_hmap) != 0 ) perror("mutex unlock failed");
		
		char original_first_octate[3];
		
		/*
		 *consider CTS only if this is response from our injection,
		 *ignore all other CTS as there is not tx address
		 */
		if(hm_entry!=NULL){ 
			/*get first octate from the hashmap and use rest ocatates from the packet*/
			//printf("value=%s\n", ( (struct map_info*)hm_entry->info )->value);
			strncpy(original_first_octate, ( (struct map_info*)hm_entry->info )->value, 2);
			original_first_octate[2]='\0';
			info->tx_addr[0] = strtoul(original_first_octate, NULL, 16);
			memcpy(info->tx_addr+1, wifi_hdr->addr1, ETH_ALEN-1);//addr1 is the recipient address
					
			if(options_args->display_flag){
				char mac[20];
				printf("Got a CTS for mac: %s\n", hwaddr_ntoa(info->tx_addr, mac) );
			}
		}
	}
	/*if CTS for global injection*/
	else if( wifi_hdr->addr1[0] == GLOBAL_INJECTION_PREFIX && options_args->global_injection_flag ){

	}
	/*if CTS for associated injection*/
	else if( wifi_hdr->addr1[0] == ASSOC_INJECTION_PREFIX && options_args->assoc_rts_injection_flag){
		char fake_mac[20];
		hwaddr_ntoa_no_colon(wifi_hdr->addr1, fake_mac);

		if( pthread_mutex_lock(&mutex_q_hmap_assoc) != 0 ) perror("mutex lock failed");
		struct entry *hm_entry = lookup_generic(H_assoc, fake_mac);
		if( pthread_mutex_unlock(&mutex_q_hmap_assoc) != 0 ) perror("mutex unlock failed");
		
		char original_first_octate[3];
		
		/*
		 *consider CTS only if this is response from our injection,
		 *ignore all other CTS as there is not tx address
		 */
		if(hm_entry!=NULL){ 
			/*get first octate from the hashmap and use rest ocatates from the packet*/
			//printf("value=%s\n", ( (struct map_info*)hm_entry->info )->value);
			strncpy(original_first_octate, ( (struct map_info*)hm_entry->info )->value, 2);
			original_first_octate[2]='\0';
			info->tx_addr[0] = strtoul(original_first_octate, NULL, 16);
			memcpy(info->tx_addr+1, wifi_hdr->addr1, ETH_ALEN-1);//addr1 is the recipient address
					
			if(options_args->display_flag){
				char mac[20];
				printf("Got a CTS for mac: %s [assoc injection]\n", hwaddr_ntoa(info->tx_addr, mac));
			}
		}
	}
	else{
		//all 0's in tx address for all other cts
		memset(info->tx_addr, 0x0, ETH_ALEN);
	}

}

/*
 * handles a live or offline packet from pcap file. From the packet packetinfo struct
 * is filled at first. Then packet info is put in the hashmap for blacklisting. And finally
 * the linked list is filled with epoch wise summery for all macs in that epoch
 */
//void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)

void handle_packet()
{
	u8 bytes[1000];
	struct timeval time;
	
	while(1){
		memset(bytes, 0, sizeof(bytes));
		int read_len = read(rawsock, bytes, sizeof(bytes));	

		struct radiotap *radiotap_hdr = (struct radiotap*)(bytes);
		struct ieee80211_hdr *wifi_hdr = (struct ieee80211_hdr*)(bytes+26);

		struct packetinfo info;
	
		gettimeofday(&time, NULL);
		u32 cur_sec = time.tv_sec;
	
		/*if fcs is bad then ignore this packet*/
		int fcs_bad = ((radiotap_hdr->flags & BAD_FCS_MASK) >> 6);
		if(fcs_bad) continue;
	
	
		if(first_packet_flag==0){
			/*Store the timestamp of first frame, which will go to the compact file header*/
			fileh.sec = cur_sec;

			if(options_args->compact_flag){
				if( strcmp(options_args->compact_file, "-") == 0 ) //write to stdout
					write(1, &fileh, sizeof(struct filehdr));
				else //write to file
					fwrite(&fileh, sizeof(struct filehdr), 1, compact_fp);
			}
			//else
			//	printf("Start epoch=%d\n", fileh.sec);
		
			first_packet_flag=1;
		}
		
		/*datarate mapping*/
		u8 datarate;
		switch(radiotap_hdr->rate){
		case 2: datarate = 0; break;
		case 4: datarate = 1; break;
		case 11: datarate = 2; break;
		case 12: datarate = 3; break;
		case 18: datarate = 4; break;
		case 22: datarate = 5; break;
		case 24: datarate = 6; break;
		case 36: datarate = 7; break;
		case 48: datarate = 8; break;
		case 72: datarate = 9; break;
		case 96: datarate = 10; break;
		case 108: datarate = 11; break;
		default:
			/* 
			 * if invalid datarate then most likely
			 * this is a mesh packet or 11n packet or 
			 * something that we can't handle. 
			 * so don't process further
			 */
			continue;  
		}
	
		/*fill up the packetinfo struct*/
		info.epoch = cur_sec;	
		info.caplen = read_len;
		info.datarate = datarate;
		info.fcsbad = ((radiotap_hdr->flags & BAD_FCS_MASK) >> 6);
		info.retry = (wifi_hdr->frame_control & RETRY_MASK) >>3; 
		info.ssi = (radiotap_hdr->ssi-256);
		info.frame_type = ((wifi_hdr->frame_control & TYPE_MASK) >> 10);
		info.frame_subtype = ((wifi_hdr->frame_control & SUBTYPE_MASK) >> 12); 
	
		int i;
		/*ACK doesn't have any transmitter address, so ingnore*/
		if( ((wifi_hdr->frame_control & TYPE_SUBTYPE_ACK) == TYPE_SUBTYPE_ACK) ){ 
			continue;
		}
	
		/*if RTS and starts with f2 then this RTS is transmitted by the neighbour, so start transmitting RTS too
		  otherwise, just use the tx address from it similar to other packets*/
		else if( ((wifi_hdr->frame_control & TYPE_SUBTYPE_RTS) == TYPE_SUBTYPE_RTS) ){
			handle_rts(wifi_hdr, &info, cur_sec);
		}
	
		/*If CTS for injected RTS then use RX address in place of TX address*/
		else if( ((wifi_hdr->frame_control & TYPE_SUBTYPE_CTS) == TYPE_SUBTYPE_CTS) ){
			handle_cts(wifi_hdr, &info);
		}
		else{ //just take the tx address for all other type of frames	
			memcpy(info.tx_addr, wifi_hdr->addr2, ETH_ALEN); //addr2 is the transmitter address
		}
	
		//crc
		for(i=0; i<4; i++) info.crc[i] = bytes[read_len - 4 + i];
	
		/* write whole packet info in the file if option set*/
		if(options_args->allpackets_flag) 
			fwrite(&info, sizeof(struct packetinfo), 1, allpackets_fp);

		/* if all packets compact logging is enables, write it to file*/
		if(options_args->allsmall_write_flag){
			struct packetinfo_small info_small;
			info_small.epoch = info.epoch;
			info_small.frame_type = info.frame_type;
			info_small.frame_subtype = info.frame_subtype;
			info_small.ssi = info.ssi;
			memcpy(info_small.tx_addr, info.tx_addr, ETH_ALEN);

			fwrite(&info_small, sizeof(struct packetinfo_small), 1, allpackets_small_fp);

			
		}
	
		//char mac[20];
		//printf("%d %d 0x%x%x %s\n", info.epoch, info.ssi, info.frame_type, info.frame_subtype, hwaddr_ntoa(info.tx_addr, mac));

		/*fill up the hash map with long term info for each mac*/
		struct pack_info pinfo;
		pinfo.epoch=info.epoch;
		char mac_addr[15];
		hwaddr_ntoa_no_colon(info.tx_addr, mac_addr);
		strcpy(pinfo.mac, mac_addr);
	
		put(mac_addr, pinfo);
		

		/*fill up the linked list containing per second info*/		
		current_epoch = info.epoch;
		if(first_epoch_flag==0){
			prev_epoch = current_epoch;
			first_epoch_flag=1;
		}
		
		struct record *rinfo = (struct record*)malloc(sizeof(struct record));
		rinfo->epoch=info.epoch;
		rinfo->ssi=info.ssi;
		rinfo->frame_type=info.frame_type;
		rinfo->frame_subtype=info.frame_subtype;
		memcpy(rinfo->mac, info.tx_addr, ETH_ALEN);

	
		struct nlist *np;
	
		if( prev_epoch == current_epoch ){
			if( (np=lookup(mac_addr))->info->total_epoch < BLACKLIST_TIME ){//not blacklisted, so insert
			
				/* local injection for all macs heard */
				if(options_args->local_all_injection_flag){ 
					/* insert into injection hashmap and queues */
					insert_injection_data_structures(info.tx_addr, 0);
				}
				/* 
				 * local injection for only macs that are not associated to fixed or opportunistic APs 
				 * TODO: should we also consider associated rts injection along with assoc data injection?
				 */
				else if(options_args->local_selected_injection_flag && options_args->assoc_data_injection_flag){
					/* CONCERN: is it too costly to search both of the queues for every packet? */

					int exists_fakeap;
					if(options_args->recv_msg_from_fake_ap_flag){
						if( pthread_mutex_lock(&mutex_q_assoc_fakeap) != 0 ) perror("mutex lock failed");
						exists_fakeap = lookup_q(Q_assoc_fakeap, info.tx_addr);
						if( pthread_mutex_unlock(&mutex_q_assoc_fakeap) != 0 ) perror("mutex unlock failed");

					}

					int exists_data;
					if( pthread_mutex_lock(&mutex_q_assoc_data) != 0 ) perror("mutex lock failed");
					exists_data = lookup_q(Q_assoc_data, info.tx_addr);
					if( pthread_mutex_unlock(&mutex_q_assoc_data) != 0 ) perror("mutex unlock failed");


					
					/* insert into rts injection queue only if this mac is not associated to fixed ap or opportunistic aps */
					if(options_args->recv_msg_from_fake_ap_flag){ //check both fakeap and data queue
						if( !exists_data && !exists_fakeap ){
							insert_injection_data_structures(info.tx_addr, 0);
						}
					}
					else{ //check only data queue
						if( !exists_data ){
							insert_injection_data_structures(info.tx_addr, 0);
						}
					}


				}
			
			
				if( !insert_info(rinfo) )
					free(rinfo);
			}
			else{
				free(rinfo);
				//printf("not inserted due to blacklisting: %s\n", mac_addr);
			}
		}
		else{ //epoch changed
			if( options_args->compact_flag ){ //write to file
				if( first_epoch_flag_for_gap == 0 ){ //very first epoch after program starts

#ifdef DIFFERENTIAL_EPOCH_LOGGING
					write_to_file(0, mac_count_per_epoch);
#else
					write_to_file_abs_epoch(prev_epoch, mac_count_per_epoch);
#endif
					last_written_epoch = current_epoch;
					first_epoch_flag_for_gap = 1;
				}
				else{
					if(mac_count_per_epoch > 0){ //subsequent epochs
#ifdef DIFFERENTIAL_EPOCH_LOGGING
						int epoch_gap = current_epoch - last_written_epoch;
						write_to_file(epoch_gap, mac_count_per_epoch);
#else
						write_to_file_abs_epoch(prev_epoch, mac_count_per_epoch);
#endif
						last_written_epoch = current_epoch;
					}
					//else
					//	printf("not written as no packet in this epoch: %d\n", prev_epoch);	
				}	
			}
			
			if( options_args->display_flag ){ //display on stdout 
				printf("\n");
				printf("%d %d\n", prev_epoch, mac_count_per_epoch);
				display_list(); //display linked list contents
				//display_map_all(); //display hashmap contents
				printf("\n");

				if(options_args->local_all_injection_flag || options_args->local_selected_injection_flag || options_args->global_injection_flag){
					print_queue(Q);
					display_map_all_generic(H);
				}
			
				printf("\n\n");
			}	
		
			/* Send data to the server */
			if(options_args->senddata_flag && mac_count_per_epoch > 0){ //send if option set and some data for this epoch
				//send_data(prev_epoch, mac_count_per_epoch);	
#ifdef TCP
				send_data_tcp(remote_sock, prev_epoch, mac_count_per_epoch);
#else
				send_data_udp(remote_sock, addr, prev_epoch, mac_count_per_epoch);
#endif
			}
		
			/* free the linked list and reset counter */	
			free_list();
			mac_count_per_epoch = 0;

			/* not blacklisted, so insert in hashmap */
			if((np=lookup(mac_addr))->info->total_epoch < BLACKLIST_TIME){
				if( !insert_info(rinfo) )
					free(rinfo);  
			}
			else{
				free(rinfo);
				//printf("not inserted due to blacklisting: %s\n", mac_addr);
			}	
		}
	
		prev_epoch=current_epoch;
	}
}



/*
 * Insert into injection hashmap with fake mac as key and original 
 * mac as value
 * 
 * from_neighbour=0, heard by itself, not from neighbour
 * from_neighbour=1, heard from neighbour
 *
 * return value: 1 if inserted, 0 otherwise
 */
int insert_injection_data_structures(u8 addr[], int from_neighbour){ 
	char orig_mac[15];
	char fake_mac_f2[15];
	char fake_mac_f3[15];
	hwaddr_ntoa_no_colon(addr, orig_mac);
	/* 
	 * if 2nd bit from lsb at leftmost octate is 1 then it is locallly 
	 * administrated, so this address should not be obnained in any device
	 * ref: http://en.wikipedia.org/wiki/MAC_address. Hence for first ocate
	 * of the fake mac address 0xf2 is used if this is really heard by the monitor
	 * and fake mac addrss 0xf3 is used if this is passive hearing from neighbour. 
	 * 0xf3 is used so that the RTS sending doesn't grow exponentially because of 
	 * neighbour listenning
	 */
	sprintf(fake_mac_f3, "%02x%02x%02x%02x%02x%02x", GLOBAL_INJECTION_PREFIX, addr[1], addr[2], addr[3], addr[4], addr[5]);		
	sprintf(fake_mac_f2, "%02x%02x%02x%02x%02x%02x", LOCAL_INJECTION_PREFIX, addr[1], addr[2], addr[3], addr[4], addr[5]);	

	//slight problem here. If inserted then double lookup as put also lookup before insertion
	if( pthread_mutex_lock(&mutex_q_hmap) != 0 ) perror("mutex lock failed");
	struct entry *hm_entry_f2 = lookup_generic(H, fake_mac_f2);
	struct entry *hm_entry_f3 = lookup_generic(H, fake_mac_f3);
	if( pthread_mutex_unlock(&mutex_q_hmap) != 0 ) perror("mutex unlock failed");

	//struct map_info *minfo = (struct map_info*)malloc(sizeof(struct map_info));
	//if( (minfo->value = strdup(orig_mac)) == NULL ) 
	//	perror("errory copying value into map_info struct");


	if(hm_entry_f2 == NULL && hm_entry_f3 == NULL){ //not in hashmap, so insert
		//put in hashmap
		struct map_info *minfo = (struct map_info*)malloc(sizeof(struct map_info));
		if( (minfo->value = strdup(orig_mac)) == NULL ) 
		perror("errory copying value into map_info struct");
		
		if( pthread_mutex_lock(&mutex_q_hmap) != 0 ) perror("mutex lock failed");
		if(from_neighbour)
			put_generic(H, fake_mac_f3, minfo);
		else
			put_generic(H, fake_mac_f2, minfo);
		if( pthread_mutex_unlock(&mutex_q_hmap) != 0) perror("mutex unlock failed");

		//put in the queue
		struct queue_info *q_info = (struct queue_info*)malloc(sizeof(struct queue_info));
		q_info->counter=PACKET_INJECTION_INIT_COUNT; //no of times this mac address will be injected
		memcpy(q_info->mac, addr, ETH_ALEN);

		if( pthread_mutex_lock(&mutex_q_hmap) != 0 ) perror("mutex lock failed");
		if( enqueue(Q,q_info) ) {perror("Insertion in queue failed"); free(q_info);}
		if( pthread_mutex_unlock(&mutex_q_hmap) !=0 ) perror("mutex unlock failed");

		return 1;
	}
	//else{ 
	//	/* Important: potential src of memory leak.
	//	 * free everything as not inserted into hashmap.
	//	 */
	//	free(minfo->value);
	//	free(minfo);
	//	
	//	return 0;
	//}

	return 0;

}


/* remove from injection queue and hashmap if exists */
void remove_injection_data_structures(u8 *mac_addr){
	char key[15];
	sprintf(key, "%02x%02x%02x%02x%02x%02x", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
	if( pthread_mutex_lock(&mutex_q_hmap) != 0 ) perror("mutex lock failed");
	remove_generic(H, key);
	delete_q(Q, mac_addr);
	if( pthread_mutex_unlock(&mutex_q_hmap) != 0 ) perror("mutex unlock failed");

	printf("################################# removed from injection data sturctures: %s", key);
}



/*
 * down or up the monitor interface
 */
void setifflags(char *ifname, int iface_sock, int value)
{
	struct ifreq ifreq;

	(void) strncpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name));
 	if (ioctl(iface_sock, SIOCGIFFLAGS, &ifreq) == -1)
		err(EXIT_FAILURE, "SIOCGIFFLAGS");
 	int flags = ifreq.ifr_flags;

	if (value < 0) {
		value = -value;
		flags &= ~value;
	} else
		flags |= value;
	ifreq.ifr_flags = flags;
	if (ioctl(iface_sock, SIOCSIFFLAGS, &ifreq) == -1)
		err(EXIT_FAILURE, "SIOCSIFFLAGS");
}


/*
 * read all packets from the file and output to stdout	
 */
void read_all_packets(){
	FILE *readfile = fopen(options_args->allread_file, "r+");
	if(readfile == NULL){
		perror("Error opening file");
		exit(1);
	}
	
	int readbytes;
	struct packetinfo info;
	
	while( (readbytes=fread(&info, sizeof(struct packetinfo), 1, readfile)) ){
		printf("%d %d %d %.1f %i %d 0x%x%x %d %02x-%02x-%02x-%02x-%02x-%02x 0x%02x%02x%02x%02x\n", frame++, info.caplen, info.epoch, datarates[info.datarate], info.ssi, info.fcsbad, info.frame_type, info.frame_subtype, info.retry, info.tx_addr[0], info.tx_addr[1], info.tx_addr[2], info.tx_addr[3], info.tx_addr[4], info.tx_addr[5], info.crc[0], info.crc[1], info.crc[2], info.crc[3]);
	}
	fclose(readfile);
}

/*
 * read all packets (small formatting) from the file and output to stdout	
 */
void read_all_packets_small(){
	FILE *readfile = fopen(options_args->allsmall_read_file, "r+");
	if(readfile == NULL){
		perror("Error opening file");
		exit(1);
	}
	
	int readbytes;
	struct packetinfo_small info;

	char mac[20];	
	while( (readbytes=fread(&info, sizeof(struct packetinfo_small), 1, readfile)) ){
		printf( "%d 0x%x%x %d %s\n", info.epoch, info.frame_type, info.frame_subtype, info.ssi, hwaddr_ntoa(info.tx_addr, mac) );
	}
	fclose(readfile);
}



void read_log(){
	FILE *readfile = fopen(options_args->read_log_file, "r+");
	if(readfile == NULL){
		perror("Error opening file");
		exit(1);
	}
	
	int readbytes;
	struct injection_log inj_log;
	
	while( (readbytes=fread(&inj_log, sizeof(struct injection_log), 1, readfile)) ){
		printf("%d %02x-%02x-%02x-%02x-%02x-%02x\n", inj_log.epoch, inj_log.addr[0], inj_log.addr[1], inj_log.addr[2], inj_log.addr[3], inj_log.addr[4], inj_log.addr[5]);
	}
	fclose(readfile);

}


void read_syslog_log(){
	FILE *readfile = fopen(options_args->read_syslog_file, "r+");
	if(readfile == NULL){
		perror("Error opening file");
		exit(1);
	}
	
	int readbytes;
	struct syslog_log slog;
	char mac[20];
	while( (readbytes=fread(&slog, sizeof(struct syslog_log), 1, readfile)) ){
		printf("%d %s %c %d\n", slog.epoch, hwaddr_ntoa(slog.mac, mac), slog.type, slog.wlanid);
	}

	fclose(readfile);

}

#ifdef TCP 
/*
 * try to setup connection to the server
 * again if SIGPIPE received	
 */
void handle_lost_connection(int sig){
	printf("lost connection\n");
	/* try to connect again */
	setup_server_connection();
}
#endif

/*
 * setup connection to the server	
 */
void setup_server_connection(){
#ifdef TCP
	/* create a socket for talking to remote host */
	remote_sock = socket(AF_INET, SOCK_STREAM, 0);
	if(remote_sock < 0) {
		perror("Creating socket failed: ");
		//exit(1);
	}
	
	/* populate an address struct describing who we want to talk to */
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);    // byte order is significant
	addr.sin_addr.s_addr = inet_addr(options_args->senddata_ip); 
	
	/* connect the socket to the remote host */
	int res = connect(remote_sock, (struct sockaddr*)&addr, sizeof(addr));
	if(res < 0) {
		perror("Error connecting: ");
		//exit(1);
	}
	
	/* catch SIGPIPE in case broken pipe and re-establish the connection */
	signal(SIGPIPE, handle_lost_connection);
	
#else
	remote_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(remote_sock < 0) {
		perror("Creating socket failed: ");
		//exit(1);
	}

	/* populate an address struct describing who we want to talk to */
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);    // byte order is significant
	addr.sin_addr.s_addr = inet_addr(options_args->senddata_ip); 
 #endif
}



/*
 * injector thread function that inject packets periodically [local and global injection]
 */
void *injector_thread_fun(void *arg){
	while(1){
		//printf("injection_thread_fun\n");

		//inject a RTS packet
		if( pthread_mutex_lock(&mutex_q_hmap) !=0 ) perror("mutex lock failed");
		struct queue_info *qinfo = dequeue(Q);
		if( pthread_mutex_unlock(&mutex_q_hmap) !=0 ) perror("mutex unlock failed");
		if(qinfo != NULL){
			if(options_args->display_flag){
				char mac[20];
				printf("Injected %s %d\n", hwaddr_ntoa(qinfo->mac, mac), qinfo->counter);
			}
		}

		if(qinfo != NULL){
			u8 mac_inject[6];
			memcpy(mac_inject, qinfo->mac, ETH_ALEN);
		
			char fake_mac_f2[15];
			char fake_mac_f3[15];

			sprintf(fake_mac_f3, "%02x%02x%02x%02x%02x%02x", GLOBAL_INJECTION_PREFIX, mac_inject[1], mac_inject[2], mac_inject[3], mac_inject[4], mac_inject[5]);		
			sprintf(fake_mac_f2, "%02x%02x%02x%02x%02x%02x", LOCAL_INJECTION_PREFIX, mac_inject[1], mac_inject[2], mac_inject[3], mac_inject[4], mac_inject[5]);	

			if( pthread_mutex_lock(&mutex_q_hmap) != 0 ) perror("mutex lock failed");
			struct entry *hm_entry_f2 = lookup_generic(H, fake_mac_f2);
			struct entry *hm_entry_f3 = lookup_generic(H, fake_mac_f3);
			if( pthread_mutex_unlock(&mutex_q_hmap) != 0 ) perror("mutex unlock failed");

			if(hm_entry_f2 != NULL && hm_entry_f3 == NULL){
				//inject the packet as local injection
				if(inject_packet(handle, mac_inject, INJECTION_TYPE_LOCAL)) perror("packet sending failed");
			}else if(hm_entry_f2 == NULL && hm_entry_f3 != NULL){
				//inject the packet as global injection
				if(inject_packet(handle, mac_inject, INJECTION_TYPE_GLOBAL)) perror("packet sending failed");
			}else{
				fprintf(stderr, "Error in contents of the injection hashmap\n");
			}
	   

			qinfo->counter -= 1;
			if( qinfo->counter > 0){
				if( pthread_mutex_lock(&mutex_q_hmap) !=0 ) perror("mutex lock failed");
				if( enqueue(Q, qinfo) ) {perror("Insertion in queue failed"); free(qinfo);}
				if( pthread_mutex_unlock(&mutex_q_hmap) !=0 ) perror("mutex unlock failed");
			}else{ //remove from hashmap and free qinfo
				char key[15];
				sprintf(key, "%02x%02x%02x%02x%02x%02x", LOCAL_INJECTION_PREFIX, qinfo->mac[1], qinfo->mac[2], qinfo->mac[3], qinfo->mac[4], qinfo->mac[5]);
				
				if( pthread_mutex_lock(&mutex_q_hmap) !=0 ) perror("mutex lock failed");
				remove_generic(H, key);
				if( pthread_mutex_unlock(&mutex_q_hmap) !=0 ) perror("mutex unlock failed");
				
				free(qinfo);
			}	
		}
		usleep(PACKET_INJECTION_INTERVAL); 
	}
}


/*
 * thread function that inject RTS packet periodically targetting macs that are 
 * associated with hostapd (seperate from local and global injection)
 */
void *assoc_injection_thread_fun(void *arg){
	while(1){
		//printf("assoc_injection_thread_fun\n");

		//inject a RTS packet
		if( pthread_mutex_lock(&mutex_q_hmap_assoc) !=0 ) perror("mutex lock failed");
		struct queue_info *qinfo = dequeue(Q_assoc);
		if( pthread_mutex_unlock(&mutex_q_hmap_assoc) !=0 ) perror("mutex unlock failed");

		if(qinfo != NULL){
			u8 mac_inject[6];
			memcpy(mac_inject, qinfo->mac, ETH_ALEN);
			
			//inject the packet
			if(inject_packet(handle, mac_inject, INJECTION_TYPE_ASSOC)) perror("packet sending failed");
			
			if(options_args->display_flag){
				char mac[20];
				printf("Injected for %s [assoc rts injection]\n", hwaddr_ntoa(qinfo->mac, mac));

			}
			
			if( pthread_mutex_lock(&mutex_q_hmap_assoc) !=0 ) perror("mutex lock failed");
			if( enqueue(Q_assoc, qinfo) ) {fprintf(stderr, "Insertion in queue failed"); free(qinfo);}
			if( pthread_mutex_unlock(&mutex_q_hmap_assoc) !=0 ) perror("mutex unlock failed");
		}
		usleep(PACKET_INJECTION_INTERVAL); 
	}

}


/*
 * thread function that inject DATA packet periodically targetting macs that are 
 * associated with hostapd (seperate from local and global injection)
 */
void *assoc_data_injection_thread_fun(void *arg){
	while(1){
		//printf("assoc_data_injection_thread_fun\n");

		//inject a Data packet
		if( pthread_mutex_lock(&mutex_q_assoc_data) !=0 ) perror("mutex lock failed");
		struct queue_info *qinfo = dequeue(Q_assoc_data);
		if( pthread_mutex_unlock(&mutex_q_assoc_data) !=0 ) perror("mutex unlock failed");

		if(qinfo != NULL){
			u8 mac_inject[6];
			memcpy(mac_inject, qinfo->mac, ETH_ALEN);
			
			//inject the packet
			if( inject_data_packet(ap_if_handle, mac_inject) ) perror("packet sending failed");
			
			if(options_args->display_flag){
				char mac[20];
				printf("Injected for %s [assoc data injection]\n", hwaddr_ntoa(qinfo->mac, mac));
			}
			
			if( pthread_mutex_lock(&mutex_q_assoc_data) !=0 ) perror("mutex lock failed");
			if( enqueue(Q_assoc_data, qinfo) ) {fprintf(stderr, "Insertion in queue failed"); free(qinfo);}
			if( pthread_mutex_unlock(&mutex_q_assoc_data) !=0 ) perror("mutex unlock failed");
		}
		usleep(PACKET_INJECTION_INTERVAL); 
	}

}


/*
 * Helper function used by syslog_thread_fun to get the wlan id with which a device got associated
 */
int get_wlanid(char *buffer){
	char *device = get_column(buffer, " ", 5); //we get wlan#:
	char id[5];
	memset(id, 0, sizeof(id));					
	memcpy(id, device+4, strlen(device)-5); //get the # from wlan#:
	
	return atoi(id);
}


/*
 * thread function receiving udp packets from syslogd for hostapd association 
 * and disassociation. As the macs are associated, they are put in the injection queue
 * and hashmap (seperate from logal and global injection queue and hashmap). MACs are 
 * removed from queue and hashmap when they got disassociated
 */
void *syslog_thread_fun(void *arg){
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		perror("Creating socket failed: ");
		exit(1);
	}
	
	struct sockaddr_in addr; // internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT_SYSLOG); // byte order is significant
	addr.sin_addr.s_addr = INADDR_ANY;
	
	int res = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
	if(res < 0) {
		perror("Error binding: ");
		exit(1);
	}

	/* reuse port */
	int yes=1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("setsockopt");
		exit(1);
	}

	char buffer[500], buffer1[500];
	struct timeval tv;
	
	while(1){
		/* recv udp packet */
		memset(buffer, 0 , sizeof(buffer));
		int rec_count = recv(sock, &buffer, sizeof(buffer), 0);
		memcpy(buffer1, buffer, sizeof(buffer));

		if(rec_count > 0){
			if( (strstr(buffer, "associated") != NULL) && (strstr(buffer, "disassociated") == NULL)  ){ //association
				char fake_mac[15];
				u8 mac_addr[ETH_ALEN];
				
				gettimeofday(&tv, NULL);
				char *mac = get_column(buffer, " ", 7);

				int value = hwaddr_aton(mac, mac_addr);
				if(value == -1){
					fprintf(stderr, "invalid mac address\n");
					continue;
				}

				int wlan_id = get_wlanid(buffer1);
				if(options_args->log_syslog_flag){
					struct syslog_log slog;
					slog.epoch = tv.tv_sec;
					memcpy(slog.mac, mac_addr, ETH_ALEN);
					slog.type = 'a';
					slog.wlanid = wlan_id;
					fwrite(&slog, sizeof(struct syslog_log), 1, syslog_fp);
				}

				if(options_args->display_flag)
					printf("%ld %s a %d\n", tv.tv_sec, mac, wlan_id);


				/*insert into rts injection queue*/				
				if(options_args->assoc_rts_injection_flag){
					sprintf(fake_mac, "%02x%02x%02x%02x%02x%02x", ASSOC_INJECTION_PREFIX, mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);	

					//perpare date for q insertion
					struct queue_info *q_info = (struct queue_info*)malloc(sizeof(struct queue_info));
					memcpy(q_info->mac, mac_addr, ETH_ALEN);

					//prepare data for hashmap insertion
					struct map_info *minfo = (struct map_info*)malloc(sizeof(struct map_info));
					char orig_mac[15]; 
					sprintf(orig_mac, "%02x%02x%02x%02x%02x%02x", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
					if( (minfo->value = strdup(orig_mac)) == NULL ) perror("errory copying value into map_info struct");


					if( pthread_mutex_lock(&mutex_q_hmap_assoc) != 0 ) perror("mutex lock failed");
					//put in rts injection queue
					if( enqueue(Q_assoc,q_info) ) {fprintf(stderr, "Insertion in queue failed\n"); free(q_info);}
					//put in rts injection hashmap
					if(put_generic(H_assoc, fake_mac, minfo) == NULL){
						//free memory if put in the hashmap not successfull
						free(minfo->value);
						free(minfo);
					}
					print_queue(Q_assoc);
					display_map_all_generic(H_assoc);
					if( pthread_mutex_unlock(&mutex_q_hmap_assoc) !=0 ) perror("mutex unlock failed");
				}

				/*insert into data injection queue*/
				if(options_args->assoc_data_injection_flag){
					//perpare date for q insertion
					struct queue_info *q_info_data = (struct queue_info*)malloc(sizeof(struct queue_info));
					memcpy(q_info_data->mac, mac_addr, ETH_ALEN);
					//put in the data injection queue
					if( pthread_mutex_lock(&mutex_q_assoc_data) != 0 ) perror("mutex lock failed");
					if( enqueue(Q_assoc_data,q_info_data) ) {fprintf(stderr, "Insertion in queue failed\n"); free(q_info_data);}
					if( pthread_mutex_unlock(&mutex_q_assoc_data) !=0 ) perror("mutex unlock failed");


					/* remove from injection queue and hashmap if exists */
					if(options_args->local_all_injection_flag || options_args->local_selected_injection_flag)
						remove_injection_data_structures(mac_addr);
				}

			}
			else if( strstr(buffer, "disassociated") != NULL ){ //disassociation
				u8 mac_addr[ETH_ALEN];
				
				gettimeofday(&tv, NULL);
				char *mac = get_column(buffer, " ", 7);

				int value = hwaddr_aton(mac, mac_addr);
				if(value == -1){
					fprintf(stderr, "invalid mac address\n");
					continue;
				}

				int wlan_id = get_wlanid(buffer1);
				if(options_args->log_syslog_flag){
					struct syslog_log slog;
					slog.epoch = tv.tv_sec;
					memcpy(slog.mac, mac_addr, ETH_ALEN);
					slog.type = 'd';
					slog.wlanid = wlan_id;
					fwrite(&slog, sizeof(struct syslog_log), 1, syslog_fp);
				}

				if(options_args->display_flag)
					printf("%ld %s d %d\n", tv.tv_sec, mac, wlan_id);

				/*deletion from rts injection queue*/
				if(options_args->assoc_rts_injection_flag){
					char key[15];
					sprintf(key, "%02x%02x%02x%02x%02x%02x", ASSOC_INJECTION_PREFIX, mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

					if( pthread_mutex_lock(&mutex_q_hmap_assoc) != 0 ) perror("mutex lock failed");
					//remove from queue
					if( delete_q(Q_assoc,mac_addr) ) fprintf(stderr, "Deletion from queue failed\n");
					//remove from hashmap
					remove_generic(H_assoc, key);

					print_queue(Q_assoc);
					display_map_all_generic(H_assoc);
					if( pthread_mutex_unlock(&mutex_q_hmap_assoc) !=0 ) perror("mutex unlock failed");
				}

					
				/*deletion from data injection queue*/
				if(options_args->assoc_data_injection_flag){
					if( pthread_mutex_lock(&mutex_q_assoc_data) != 0 ) perror("mutex lock failed");
					if( delete_q(Q_assoc_data,mac_addr) ) fprintf(stderr, "Deletion from queue failed\n");
					if( pthread_mutex_unlock(&mutex_q_assoc_data) !=0 ) perror("mutex unlock failed");
				}
				
			}
		}
	}
}


void *msg_from_fake_fakeap_thread_fun(void *arg){
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		perror("Creating socket failed: ");
		exit(1);
	}
	
	struct sockaddr_in addr; // internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT_MSG_FAKE_AP); // byte order is significant
	addr.sin_addr.s_addr = INADDR_ANY;
	
	int res = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
	if(res < 0) {
		perror("Error binding: ");
		exit(1);
	}

	/* reuse port */
	int yes=1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("setsockopt");
		exit(1);
	}

	struct udp_message msg;

	while(1){
		int rec_count = recv(sock, &msg, sizeof(msg), 0);
		if(rec_count == 0)
			continue;

		//char mac[20];
		//printf("mac=%s type=%d\n", hwaddr_ntoa(msg.mac_addr, mac), msg.type);

		//print_queue(Q_assoc_fakeap);

		if(msg.type == 1){//association
			/*insert into the fakeap queue*/
			struct queue_info *q_info_data = (struct queue_info*)malloc(sizeof(struct queue_info));
			memcpy(q_info_data->mac, msg.mac_addr, 6);

			if( pthread_mutex_lock(&mutex_q_assoc_fakeap) != 0 ) perror("mutex lock failed");
			if( enqueue(Q_assoc_fakeap,q_info_data) ) {fprintf(stderr, "Insertion in fakeap queue failed\n"); free(q_info_data);}
			if( pthread_mutex_unlock(&mutex_q_assoc_fakeap) !=0 ) perror("mutex unlock failed");

			/* remove from injection queue and hashmap if exists */
			remove_injection_data_structures(msg.mac_addr);
			
		}
		else if(msg.type == 0){//disassociation
			/*remove from the queue*/
			if( pthread_mutex_lock(&mutex_q_assoc_fakeap) != 0 ) perror("mutex lock failed");
			if( delete_q(Q_assoc_fakeap, msg.mac_addr) ) fprintf(stderr, "Deletion from fakeap queue failed\n");
			if( pthread_mutex_unlock(&mutex_q_assoc_fakeap) !=0 ) perror("mutex unlock failed");
			
		}	
		
		//printf("-----------------------\n");
		//print_queue(Q_assoc_fakeap);
		
	}

}


void *periodic_task_thread_fun(void *arg){
	while(1){
		//printf("periodic_thread_fun\n");

		setifflags(options_args->interface, iface_sock, -IFF_UP);	//down the interface
		setifflags(options_args->interface, iface_sock, IFF_UP);	//up the interface
	
		//free the expired macs periodically
		remove_expired_macs(); 	
		
		//flush the files
		if(options_args->compact_flag)
			fflush(compact_fp); 	

		if(options_args->log_flag)
			fflush(log_fp);
		
		if(options_args->log_syslog_flag)
			fflush(syslog_fp);
	

		sleep(PERIODIC_INTERVAL);
	}
}



/*
 * process the command line arguments
 */
void process_args(int argc, char** argv){
	char *optString = "-d-f-I-J-G-A-D-i:-r:-R:-a:-w:-W:-s:-n:-l:-L:-c:-C:-y:-Y:";

	options_args = (struct options*)malloc(sizeof(struct options)); 
	int opt = getopt( argc, argv, optString );
	while( opt != -1 ) {
		switch( opt ) {      
		case 'd':
			options_args->display_flag = 1;
			break;
		    
		case 'f':
			options_args->recv_msg_from_fake_ap_flag = 1;
			break;

		case 'I':
			options_args->local_all_injection_flag = 1;
			break;

		case 'J':
			options_args->local_selected_injection_flag = 1;
			break;
		
		case 'G':
			options_args->global_injection_flag = 1;
			break;

		case 'A':
			options_args->assoc_rts_injection_flag = 1;
			break;

		case 'D':
			options_args->assoc_data_injection_flag = 1; 
			break;
	            
		case 'i':
			options_args->interface_flag = 1;
			options_args->interface = optarg;
			break;		

		case 'r':
			options_args->pcapread_flag = 1;
			options_args->pcapread_file = optarg;
			break;
                
		case 'R':
			options_args->ccapread_flag = 1;
			options_args->ccapread_file = optarg;
			break;

		case 'a':
			options_args->allread_flag = 1;
			options_args->allread_file = optarg;
			break;
 
		case 'w':
			options_args->compact_flag = 1;
			options_args->compact_file = optarg;
			break;

		case 'W':
			options_args->allpackets_flag = 1;
			options_args->allpackets_file = optarg;
			break;
                
		case 's':
			options_args->senddata_flag = 1;
			options_args->senddata_ip = optarg;
			break;
        		
		case 'n':
			options_args->id_flag=1;
			options_args->id = optarg;
			break;	

		case 'l':
			options_args->log_flag = 1;
			options_args->log_file = optarg;
			break;

		case 'L':
			options_args->read_log_flag = 1;
			options_args->read_log_file = optarg;
			break;

		case 'c':
			options_args->allsmall_write_flag = 1;
			options_args->allsmall_write_file = optarg;
			break;

		case 'C':
			options_args->allsmall_read_flag = 1;
			options_args->allsmall_read_file = optarg;
			break;

		case 'y':
			options_args->log_syslog_flag = 1;
			options_args->log_syslog_file = optarg;
			break;

		case 'Y':
			options_args->read_syslog_flag = 1;
			options_args->read_syslog_file = optarg;
			break;


		default:
			break;
		}
		opt = getopt( argc, argv, optString );
	}

}



int create_monitor_raw_socket(char *iface){

	struct sockaddr_ll sll;
	struct ifreq ifr;

	memset(&sll, 0, sizeof(sll));
	memset(&ifr, 0, sizeof(ifr));

	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))== -1){
		perror("Error creating raw socket: ");
		return 1;
	}

	strncpy((char *)ifr.ifr_name, iface, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1){
		printf("Error getting Interface index !\n");
		return 1;
	}

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	//sll.sll_protocol = htons(ETH_P_ALL); 


	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1){
		perror("Error binding raw socket to interface\n");
		return 1;
	}

	return 0;

}


void usage(){
	printf("Usage: capcom4 [-dIJGAD]\n");
	printf("\t[-s ip_address (remote server ip waiting for log data)]\n");
	printf("\t[-n node name (unique id for the node)/id]\n");
	printf("\t[-i interface (monitor interface)]\n");
	printf("\t[-r pcap_file (pcap file for decoding packets info)]\n");
	printf("\t[-R compact_file (capcom format file for decoding packets info that have aggregated info)]\n");
	printf("\t[-a read_all_packets_file (capcom format file that have individual packets)]\n");
	printf("\t[-w compact_output_file (file for writing capcom aggregated info)]\n");
	printf("\t[-W all_output_file (file for writing individual packets in capcom format)] \n");
	printf("\t[-l log_file (file for logging injection info)]\n");
	printf("\t[-L read log_file (file for reading injection info)]\n");
	printf("\t[-y filename (syslog logging file for writing)]\n");
	printf("\t[-Y filename (syslog logging file for reading)]\n");
	printf("\t[-c filename (compact all packet file for writing)]\n");
	printf("\t[-C filename (compact all packet file for reading)]\n");
	printf("\n");

	printf("\tOptions:\n");
	printf("\t\t-d: Display info at stdout\n");
	printf("\t\t-f: receive message from fake ap\n");
	printf("\n");

	printf("\t\t-I: Enable local RTS injection for all heard macs (injection for macs heard locally)\n");
	printf("\t\t-J: Enable local RTS injection for selected macs (injection for macs heard locally and not associated with fake fixed or opportunistic APs)\n");
	printf("\t\t-G: Enable global RTS injection (injection for macs heard from neighbours)\n");
	printf("\t\t-A: Associated RTS injection (injection for macs that are associated to hostapd)\n");
	printf("\t\t-D: Associated DATA injection (injection for macs that are associated to hostapd)\n");

}


int main(int argc, char** argv) {
	
	if(argc==1) {
		usage();
		exit(1);
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	

	/*process the command line arguments using get opt and fill options struct*/
	process_args(argc, argv);
	
	
	/*if node name/id is given then set it*/
	if(options_args->id_flag){
		node_id = atoi(options_args->id);
	}
	
	/*open the file for writing all packets*/
	if(options_args->allpackets_flag){
		allpackets_fp = fopen( options_args->allpackets_file, "w+");
		if(allpackets_fp == NULL){
			perror("Error opening all packets file for writing");
			exit(1);
		}
	}
	
	/*open the file for writing all packets in compact/small form*/
	if(options_args->allsmall_write_flag){
		allpackets_small_fp = fopen( options_args->allsmall_write_file, "w+");
		if(allpackets_small_fp == NULL){
			perror("Error opening all packets file for writing");
			exit(1);
		}
	}

	/*open the file for writing compact log either from live capture or pcap file*/	
	if( options_args->compact_flag ){
		compact_fp = fopen(options_args->compact_file, "w+");
		if(compact_fp == NULL){
			perror("Error opening compact file for writing");	
			exit(1);
		}

		logerror_fp = fopen("/etc/logs/logerror_critical", "w+");
		if(logerror_fp == NULL){
			perror("Error opening logerror file for writing");
			exit(1);
		}
		
	}	
	
	/*setup connection to the server for sending data*/
	if( options_args->senddata_flag ){
		setup_server_connection();
	}

	
	/*create logfile*/
	if(options_args->log_flag){
		log_fp = fopen(options_args->log_file, "w+");
		if(log_fp == NULL){
			perror("Error openning log file for writing");
		}
	}

	/*logging syslog messages*/
	if(options_args->log_syslog_flag){
		syslog_fp = fopen(options_args->log_syslog_file, "w+");
		if(syslog_fp == NULL){
			perror("Error openning log file for syslog");
		}
	}

	/*recv message from fake_ap_generic associations*/
	if(options_args->recv_msg_from_fake_ap_flag){
		Q_assoc_fakeap = init_queue();

		pthread_t msg_from_fakeap_thread;
		if(pthread_create(&msg_from_fakeap_thread, NULL, msg_from_fake_fakeap_thread_fun, NULL))
			perror("periodic thread creation failed");
		
	}
	
	/*live capture of packets*/
	if( options_args->interface_flag ){	
		/*Peridoic up-down of monitor interface*/
		iface_sock = socket(PF_INET, SOCK_DGRAM, 0);
		if(iface_sock < 0){
			perror("Socket creating failed");
			exit(1);
		}

		if( create_monitor_raw_socket( options_args->interface ) ){
			perror("raw socket creation failed\n");
			exit(1);
		}

		/*setup the thread for monitor interface up-down and writing to file periodically*/
		pthread_t periodic_task_thread;
		if(pthread_create(&periodic_task_thread, NULL, periodic_task_thread_fun, NULL))
			perror("periodic thread creation failed");

		/*setup the injector thread*/
		if(options_args->local_all_injection_flag || options_args->local_selected_injection_flag ){
		    /*local and global injection data structures*/
			Q = init_queue();
			H = init_hashmap_generic();
			
			pthread_t injector_thread;
			if(pthread_create(&injector_thread, NULL, injector_thread_fun, NULL))
				perror("injector thread creation failed");
		}


		/*start the syslog thread if either the associated rts or associated data injection is enabled*/
		if(options_args->assoc_rts_injection_flag || options_args->assoc_data_injection_flag){
			pthread_t syslog_thread;
			if(pthread_create(&syslog_thread, NULL, syslog_thread_fun, NULL))
				perror("syslog thread creation failed");			
		}

		if(options_args->assoc_rts_injection_flag){
			Q_assoc = init_queue();
			H_assoc = init_hashmap_generic();

			pthread_t assoc_injection_thread;
			if(pthread_create(&assoc_injection_thread, NULL, assoc_injection_thread_fun, NULL))
				perror("assoc injection thread creation failed");

		}

		if(options_args->assoc_data_injection_flag){
			Q_assoc_data = init_queue();

			/*open pcap handle for ap interface for data packet injection*/
			ap_if_handle = pcap_open_live("wlan0", SNAPLEN, 1, 1000, errbuf);
			if (ap_if_handle == NULL) {
				fprintf(stderr, "Couldn't open device wlan0: %s\n", errbuf);
				return(2);
			}
		
			pthread_t assoc_data_injection_thread;
			if(pthread_create(&assoc_data_injection_thread, NULL, assoc_data_injection_thread_fun, NULL))
				perror("assoc injection thread creation failed");

		}


		/*process live packets*/
		handle_packet();

	}
	/*offline processing of a pcap file*/
	else if(options_args->pcapread_flag){	
		pcap_t *handle=pcap_open_offline(options_args->pcapread_file,errbuf);	
		while(pcap_loop(handle,-1,&handle_packet,(unsigned char*)"me") > 0);
	}
	/*read compact file and output to stdout*/
	else if(options_args->ccapread_flag){	
#ifdef DIFFERENTIAL_EPOCH_LOGGING
		read_from_file(options_args->ccapread_file);
#else
		read_from_file_abs_epoch(options_args->ccapread_file);
#endif
	}
	/*read all packets from file that has format of capcom1*/
	else if(options_args->allread_flag){
		read_all_packets();
	}
	/*read all packets small formatted log file*/
	else if(options_args->allsmall_read_flag){
		read_all_packets_small();
	}
	/*read injection log file*/
	else if(options_args->read_log_flag){
		read_log();
	}
	/*read syslog log file*/
	else if(options_args->read_syslog_flag){
		read_syslog_log();
	}
		
	if(allpackets_fp!=NULL){
		fflush(allpackets_fp);
		fclose(allpackets_fp);
	}

	if(allpackets_small_fp!=NULL){
		fflush(allpackets_small_fp);
		fclose(allpackets_small_fp);
	}

	if(compact_fp!=NULL){
		fflush(compact_fp);
		fclose(compact_fp);
	}
	exit(0);
}
