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


#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

/* The two sides of the NAT */
enum interface_type {INTERFACE_INTERNAL, INTERFACE_EXTERNAL};


/* The two NAT network interfaces information */
struct interface {
    char      *device;
    u_char    mac[ETHER_ADDR_LEN];
    uint32_t  ip;
    pcap_t    *descriptor;
    pthread_t thread;
} interfaces[2];

/* The gateway information */
struct gw {
    u_char   mac[ETHER_ADDR_LEN];
    uint32_t ip;
    enum interface_type interface;
} gateway;

/* The TCP/UDP pseudo header */
struct tcp_udp_pseudo
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t length;
} pseudo_header;

/* Useful union for checksum function */
union tcp_udp_u {
    struct tcphdr tcp;
    struct udphdr udp;
};

/* The semaphore used for printing */
static sem_t mutex;


/* Our functions prototypes */
void packet_print(const struct pcap_pkthdr *packet_header,
        const u_char *packet);
void get_interface_addresses(int interface_id);

