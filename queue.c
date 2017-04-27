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

#include<stdio.h>
#include<stdlib.h>
#include<errno.h>

#include "queue_private.h"
#include "queue.h"
#include "helper.h"


int enqueue(struct queue *q, void *q_info){
	struct queue_node *node = (struct queue_node *)malloc(sizeof(struct queue_node));
	if (node == NULL) {
		perror("memory allocation for queue node failed");
		return 1;
	}
	node->qinfo = q_info;
	if (q->first == NULL)
		q->first = q->last = node;
	else {
		q->last->next = node;
		q->last = node;
	}
	node->next = NULL;
	return 0;
}
 
void *dequeue(struct queue *q)
{
	if (!q->first) {
		return NULL;
	}
	void *q_info = q->first->qinfo;
	
	struct queue_node *tmp = q->first;
	if (q->first == q->last)
		q->first = q->last = NULL;
	else
		q->first = q->first->next;
 
	free(tmp);
	return q_info;
}


int delete_q(struct queue *q, u8 mac[]){
	struct queue_node *current=NULL, *prev=NULL;
	struct queue_info *qinfo;
	
	for(current=q->first; current!=NULL; prev=current, current=current->next){
		qinfo = (struct queue_info*)current->qinfo;
		if( mac_equality_check(mac, qinfo->mac) ){
			if(prev==NULL){ //first node in the list
				q->first=current->next;
			}else{//middle or last node
				prev->next=current->next;
			}
			
			free(current->qinfo);
			free(current);
			
			return 0;
		}
	}

	return 1;
}


/*
 * return 1 if exists in q, 0 otherwise
 */
int lookup_q(struct queue *q, u8 mac[]){
	struct queue_node *current=NULL, *prev=NULL;
	struct queue_info *qinfo;
	
	for(current=q->first; current!=NULL; prev=current, current=current->next){
		qinfo = (struct queue_info*)current->qinfo;
		if( mac_equality_check(mac, qinfo->mac) ){
			return 1;
		}
	}

	return 0;
}
 
void print_queue(struct queue *q){
	struct queue_node *temp = q->first;
	struct queue_info *qinfo;
	while(temp != NULL){
		qinfo = (struct queue_info*)temp->qinfo;
		printf("%02x:%02x:%02x:%02x:%02x:%02x %d\n", qinfo->mac[0], qinfo->mac[1], qinfo->mac[2], qinfo->mac[3], qinfo->mac[4], qinfo->mac[5], qinfo->counter );
		temp = temp->next;
	}	
}

struct queue *init_queue()
{
	struct queue *q = (struct queue*)malloc(sizeof(struct queue));
	q->first = q->last = NULL;
	return q;
}
 
int queue_empty(const struct queue *q)

{
	return q->first == NULL;
}
 
