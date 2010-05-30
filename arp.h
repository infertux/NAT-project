/*
   Copyright (C) 2010  Infertux <infertux@infertux.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as
   published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
   */


#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IP_ALEN
#define IP_ALEN 4
#endif

#define ARP_REPLY_TIMEOUT 1000 /* timeout for waiting an ARP reply in ms */


static pthread_t thread_reply, thread_timeout;
static pcap_t *descriptor;
static char addr[18];
static char device[8];
static int sem = 1;
static int ok = 0;
static u_char eth_src[ETH_ALEN];
/* broadcast */
static u_char eth_dst[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static u_char ip_src[IP_ALEN];
static u_char ip_dst[IP_ALEN];


/* Our function prototype */
void arp_request(const char *ip, const char *interface, u_char *mac);

