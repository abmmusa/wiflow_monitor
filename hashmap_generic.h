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

#ifndef HASHMAP_GENERIC_H
#define HASHMAP_GENERIC_H

#include "hashmap_generic_private.h"

struct hashmap{
	struct entry **table;
};

//info of the entry in the hashmap
struct map_info{
	char *value; //original mac address, fake mac address is the key
};

struct hashmap* init_hashmap_generic();
unsigned hash_generic(char *s);
struct entry *lookup_generic(struct hashmap *h, char *s);
struct entry *put_generic(struct hashmap *h, char *key, struct map_info *minfo);
void display_map_all_generic(struct hashmap *h);
void remove_generic(struct hashmap *h, char *key);

#endif
