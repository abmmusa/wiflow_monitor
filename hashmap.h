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

#define BLACKLIST_TIME 300 //5 min
#define EXPIARY_TIME 600 //10 min



/*
 * packet info structure. used for keeping and passing info after 
 * reading one line from file
 */
struct pack_info{
	char mac[20];
	int epoch;
};


/*
 * primary structure containing history of a particular mac
 */
struct mac_info{
	int total_epoch;	//total epoch observed
	int last_epoch;		//last epoch observed
};


/*
 *link list for a single key of the hashmap for chaining
 *multiple macs can be matched to same key and hence this linked list
 */
struct nlist{
	char *mac;
	struct mac_info *info;
	struct nlist *next;
};


#define HASHSIZE 101


unsigned hash(char *s);
struct nlist *lookup(char *s);
struct nlist *put(char *mac, struct pack_info pinfo);
void remove_expired_macs();
void remove_mac(char *mac);
void display_mac(char *mac);
void display_map_all();
