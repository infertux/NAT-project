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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <libnet.h>
#include <pcap.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include "arp.h"


/**
 * The callback to handle the ARP reply
 *
 * @param mac           The pointer to the MAC buffer to fill
 * @param packet_header The packet header
 * @param packet        The packet data
 */
void callback(u_char *mac, const struct pcap_pkthdr* packet_header,
        const unsigned char* packet)
{
    struct arphdr *arp_header;
    char response[18];

    if(packet_header->caplen < sizeof(struct ethhdr) + sizeof(struct arphdr)) {
        fprintf(stderr, "Short packet\n");
        return;
    }

    arp_header = (struct arphdr *)(packet + sizeof(struct ethhdr));

    if(htons(arp_header->ar_op) == ARPOP_REPLY) {
        strcpy(response,
                inet_ntoa(*(struct in_addr *)(&(*(packet +
                                sizeof(struct ethhdr) + sizeof(struct arphdr) +
                                ETH_ALEN))))); /* HUGE! */

        if (strcmp(response, addr) == 0) {
            memcpy(mac, packet + sizeof(struct ethhdr) + sizeof(struct arphdr),
                    ETH_ALEN);

#ifdef DEBUG
            printf("ARP reply for %s: %s\n", addr,
                    ether_ntoa((struct ether_addr *)(&(*mac))));
#endif

            ok = 1;

            pcap_breakloop(descriptor);
            pcap_close(descriptor);
            pthread_exit(NULL);

            return;
        }
    }
}

/**
 * Listen for the ARP reply and fill the MAC
 *
 * @param mac The pointer to the MAC buffer to fill
 */
void arp_reply(u_char *mac)
{
    bpf_u_int32 subnet, netmask;
    struct bpf_program fp; /* hold compiled program */
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[] = "arp"; /* handle only ARP */


    /* ask pcap for the network subnet and mask of the interface */
    if (pcap_lookupnet(device, &subnet, &netmask, errbuf) < 0) {
        fprintf(stderr, "Could not get local IP network info: %s\n", errbuf);
        return;
    }

    /* open interface for reading in promiscuous mode */
    if ((descriptor = pcap_open_live(device, BUFSIZ, 1, -1, errbuf)) == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return;
    }

    /* let's try and compile the program */
    if (pcap_compile(descriptor, &fp, filter, 0, subnet) == -1) {
        fprintf(stderr, "Error compiling filter\n");
        return;
    }

    /* set the compiled program as the filter */
    if (pcap_setfilter(descriptor, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        return;
    }

#ifdef DEBUG
    printf("Waiting for ARP reply for %s on %s...\n", addr, device);
#endif

    /* I'm ready! */
    sem = 0;

    /* ... and loop */
    pcap_loop(descriptor, 0, callback, mac);
}

/**
 * Just a timeout who kills arp_reply and aborts waiting for a reply
 */
void timeout(void)
{
    usleep(1000 * ARP_REPLY_TIMEOUT);
    if (ok) return;

    fprintf(stderr, "ARP reply timeout\n");

    pcap_breakloop(descriptor);
    pthread_kill(thread_reply, SIGINT);
}

/**
 * Send an ARP request
 *
 * @param ip        The targeted IP address (e.g. "192.168.42.1")
 * @param interface The interface where to send the request (e.g. "ethO")
 * @param mac       The pointer to the MAC buffer to fill
 */
void arp_request(const char *ip, const char *interface, u_char *mac)
{
    libnet_t *libnet = NULL;
    char error[LIBNET_ERRBUF_SIZE];
    u_int32_t otherip, myip;
    struct libnet_ether_addr *mymac;
    libnet_ptag_t arp = 0, eth = 0;

    if (getuid() && geteuid()) { /* must be r00t to listen on interfaces */
        fprintf(stderr, "R007 M3 P13453!\n");
        exit(EXIT_FAILURE);
    }

    strcpy(device, interface);
    strcpy(addr, ip);

    memset(mac, 0, ETHER_ADDR_LEN);

    /* response handler */
    if (pthread_create(&thread_reply, NULL, arp_reply, mac)) {
        perror("pthread_create");
        return;
    }

    /* wait for reply handler is ready */
    while(sem);

    /* open libnet */
    libnet = libnet_init(LIBNET_LINK, device, error);

    /* get dst IP address */
    otherip = libnet_name2addr4(libnet, addr, LIBNET_RESOLVE);
    memcpy(ip_dst, (char*)&otherip, IP_ALEN);

    /* get hwaddr */
    mymac = libnet_get_hwaddr(libnet);
    memcpy(eth_src, mymac, ETH_ALEN);

    /* get IP address */
    myip = libnet_get_ipaddr4(libnet);
    memcpy(ip_src, (char*)&myip, IP_ALEN);

    /* print MAC address */
#ifdef DEBUG
    printf("Our MAC: %s\n", ether_ntoa((struct ether_addr *)&(eth_src)));
#endif

    arp = libnet_build_arp(
            ARPHRD_ETHER,
            ETHERTYPE_IP,
            ETH_ALEN, IP_ALEN,
            ARPOP_REQUEST,
            eth_src, ip_src,
            eth_dst, ip_dst,
            NULL, 0,
            libnet,
            arp);

    eth = libnet_build_ethernet(
            eth_dst, eth_src,
            ETHERTYPE_ARP,
            NULL, 0,
            libnet,
            eth);

    libnet_write(libnet);
    libnet_destroy(libnet);

#ifdef DEBUG
    printf("ARP request sent for %s on %s.\n", ip, interface);
#endif

    /* response handler */
    if (pthread_create(&thread_timeout, NULL, timeout, NULL)) {
        perror("timeout");
        return;
    }

    if (pthread_join(thread_reply, NULL))
        perror("pthread_join");
}

