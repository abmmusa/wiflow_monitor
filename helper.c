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
#include<string.h>
#include<ctype.h>


#include "helper.h"

//ref: lib/hexdump.c 
/**
 * hex_to_bin - convert a hex digit to its real value
 * @ch: ascii character represents hex digit
 *
 * hex_to_bin() converts one hex digit to its actual value or -1 in case of bad
 * input.
 */
int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}


//ref: mac80211/debugfs_netdev.c
int hwaddr_aton(const char *txt, u8 *addr)
{
	int i;

	for (i = 0; i < 6; i++) {
		int a, b;

		a = hex_to_bin(*txt++);
		if (a < 0)
			return -1;
		b = hex_to_bin(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}

	return 0;
}


/*
 * return 1 if two macs are equal, 0 otherwise
 */
int mac_equality_check(u8 first_mac[], u8 second_mac[]){
	int i;
	for(i=0; i<6; i++){
		if(first_mac[i] != second_mac[i])
			return 0;
	}
	return 1;
}


/*
 * function similar to awk '{print $x}'
 */
char *get_column(char *line, char *delimeter, int column){
	char *str, *token;
	int j;
	for(j=1, str=line; ;str=NULL, j++){
		token=strtok(str, " ");

		if(token == NULL){
			break;
		}

		if(j == column){
			return token;
		}
	}

	return NULL;
}


char *hwaddr_ntoa(u8 *addr_bytes, char* addr_str){
	memset(addr_str,0,sizeof(addr_str));
	sprintf(addr_str, "%02x:%02x:%02x:%02x:%02x:%02x", addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3], addr_bytes[4], addr_bytes[5] );
	return addr_str;
}


char *hwaddr_ntoa_no_colon(u8 *addr_bytes, char* addr_str){
	memset(addr_str,0,sizeof(addr_str));
	sprintf(addr_str, "%02x%02x%02x%02x%02x%02x", addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3], addr_bytes[4], addr_bytes[5] );
	return addr_str;
}
