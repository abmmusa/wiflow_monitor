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
 *
 * Hashmap with chaining
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hashmap.h"

static struct nlist *hashtab[HASHSIZE];

extern int current_epoch;

/*
 * basic hash function, scope of improvement here
 */
unsigned hash(char *s){
	unsigned hashval;
	
	for(hashval=0; *s!='\0'; s++)
		hashval=*s+31*hashval;
	return hashval % HASHSIZE;
}


/*
 * record lookup using mac
 */
struct nlist *lookup(char *s){
	struct nlist *np;
	
	for(np = hashtab[hash(s)]; np!=NULL; np=np->next)
		if(strcmp(s, np->mac)==0)
			return np;
	
	return NULL;
}


/*
 * put record for macs
 */
struct nlist *put(char *mac, struct pack_info pinfo){
	struct nlist *np;
	unsigned hashval;

	if( (np=lookup(mac)) == NULL ){	//mac not found, first entry in the linked list
		np = (struct nlist*)malloc(sizeof(struct nlist));
		if(np==NULL || (np->mac = strdup(mac)) == NULL )
			return NULL;
		struct mac_info *minfo = (struct mac_info*)malloc(sizeof(struct mac_info));
		if(minfo==NULL){
			printf("Allocation Error!\n");
			exit(1);
		}
		
		minfo->last_epoch = pinfo.epoch;
		minfo->total_epoch = 1;
		
		np->info = minfo;
		
		hashval = hash(mac);
		np->next = hashtab[hashval];
		hashtab[hashval] = np;
	}else{ //mac exists
		if(np->info->last_epoch != pinfo.epoch)
			np->info->total_epoch++;
		
		np->info->last_epoch = pinfo.epoch;
	}
	
	return np;
}


/*
 * remove expired macs from hashmap
 */
void remove_expired_macs(){
	struct nlist *np;
	
	int i;
	for(i=0; i<HASHSIZE; i++){
		for(np = hashtab[i]; np!=NULL; np=np->next){
			/*decision for removing the mac from hashmap after expiary time*/
			if( (current_epoch - np->info->last_epoch) > EXPIARY_TIME ){
				//printf("removing after expiary: %s\n", np->mac);
				remove_mac(np->mac);
			}
		}	
	}		
}


/*
 * remove a particular mac from the hashmap
 */
void remove_mac(char *mac){
	struct nlist *current, *prev;
	
	prev = NULL;
	
	for(current = hashtab[hash(mac)]; current!=NULL; prev=current, current=current->next){
		if( strcmp(mac, current->mac) == 0 ){
			if(prev == NULL)
				hashtab[hash(mac)] = current->next;
			else
				prev->next = current->next;
			
			free(current->mac);
			free(current->info);
			free(current);
		}
	}
}

/*
 * display record values for a particular key
 */
void display_mac(char *mac){
	struct nlist *np;
	np=lookup(mac);
	if(np == NULL){
		fprintf(stderr, "No Entry\n");
		return;
	}

	printf("%s %d %d\n", mac, np->info->total_epoch, np->info->last_epoch );	
}


/*
 * display record for all macs in the hashmap
 */
void display_map_all(){
	struct nlist *np;
	int count = 0;
	
	int i;
	for(i=0; i<HASHSIZE; i++){
		for(np = hashtab[i]; np!=NULL; np=np->next){
			printf("%s %d %d\n", np->mac, np->info->total_epoch, np->info->last_epoch );
			count++;
		}	
	}	
	printf("Total entry in the hashmap: %d\n", count);
}
