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
#include <string.h>

#include "hashmap_generic_private.h"
#include "hashmap_generic.h"

struct hashmap* init_hashmap_generic(){
	struct hashmap *h = (struct hashmap*)malloc(sizeof(struct hashmap));
	h->table = (struct entry**)malloc(sizeof(struct entry*)*HASHSIZE);
	return h;
}

/*
 * basic hash function, scope of improvement here
 */
unsigned hash_generic(char *s){
	unsigned hashval;
        
	for(hashval=0; *s!='\0'; s++)
		hashval=*s+31*hashval;
	return hashval % HASHSIZE;
}

/*
 * lookup using key
 */
struct entry *lookup_generic(struct hashmap *h, char *s){
	struct entry *ep;
    
	for(ep = h->table[hash_generic(s)]; ep!=NULL; ep=ep->next)
		if(strcmp(s, ep->key)==0)
			return ep;
        
	return NULL;
}

/*
 * put record for macs
 */
struct entry *put_generic(struct hashmap *h, char *key, struct map_info *minfo){
	struct entry *ep;
	unsigned hashval;
	if( (ep=lookup_generic(h, key)) == NULL ){ //key not found, first entry in the linked list
		ep = (struct entry*)malloc(sizeof(struct entry));
		if(ep==NULL || (ep->key = strdup(key)) == NULL )
			return NULL;
		
		ep->info = minfo;

		hashval = hash_generic(key);
		ep->next = h->table[hashval];
		h->table[hashval] = ep;
	}else{ //key exists, overwrite with new value
		free(ep->info); //free previous info
		ep->info = minfo; //save new info
	}

	return ep;
}


/*
 * remove entry from hashmap for a particular key
 */
void remove_generic(struct hashmap *h, char *key){
	struct entry *current, *prev;
        
	prev = NULL;
        
	for(current = h->table[hash_generic(key)]; current!=NULL; prev=current, current=current->next){
		if( strcmp(key, current->key) == 0 ){
			if(prev == NULL)
				h->table[hash_generic(key)] = current->next;
			else
				prev->next = current->next;
                        
			free(current->key);
			free(((struct map_info*)current->info)->value);
			free(current->info);
			free(current);
		}
	}
}


/*
 * display record for all keys in the hashmap
 * this is a very specific function printing all info.
 * it is not part of the hashmap in general
 */

void display_map_all_generic(struct hashmap *h){
	struct entry *ep;
	int count = 0;
	
	int i;
	for(i=0; i<HASHSIZE; i++){
		for(ep = h->table[i]; ep!=NULL; ep=ep->next){
			printf("%s %s\n", ep->key, ((struct map_info*)ep->info)->value );
			count++;
		}
	}
	printf("Total entry in injection hashmap: %d\n", count);
}


