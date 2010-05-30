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

/**********************************************************************
 * Description: Masquerading NAT application                           *
 **********************************************************************/

#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <semaphore.h>
#include <netdb.h>
#include "nat.h"
#include "table.h"
#include "arp.h"


/**
 * Return a staticly allocated string buffer containing the IP protocol name
 * from its ID
 *
 * @param protocol The IP protocol identifier
 * @return The IP protocol name (or the given ID if unknown)
 */
char *ip_protocol_ntoa(int protocol)
{
    static char str[8];


    switch (protocol) {
        case IPPROTO_ICMP: strcpy(str, "ICMP"); break;
        case IPPROTO_TCP: strcpy(str, "TCP"); break;
        case IPPROTO_UDP: strcpy(str, "UDP"); break;
        default: sprintf(str, "%d", protocol);
    }

    return str;
}

/**
 * Handle signals received by our program and quit properly if SIGINT
 *
 * @param signal The received signal ID
 */
static void signal_handler(int signal)
{
    if (signal == SIGINT) { /* exit gracefully */
        pcap_breakloop(interfaces[INTERFACE_INTERNAL].descriptor);
        pcap_breakloop(interfaces[INTERFACE_EXTERNAL].descriptor);

        /* stop listening */
        /*pcap_close(interfaces[INTERFACE_INTERNAL].descriptor);
          pcap_close(interfaces[INTERFACE_EXTERNAL].descriptor);*/
        /* segfault but why? */

        printf("Bye!\n");

        /* stop threads */
        pthread_kill(interfaces[INTERFACE_INTERNAL].thread, SIGKILL);
        pthread_kill(interfaces[INTERFACE_EXTERNAL].thread, SIGKILL);

        /* exit master */
        exit(EXIT_SUCCESS);
    }

    fprintf(stderr, "Caught unknown signal %d, aborting.\n", signal);
    exit(EXIT_FAILURE);
}

/**
 * Print a IP packet
 *
 * @param packet_header The packet header
 * @param packet        The packet data
 */
void packet_print(const struct pcap_pkthdr *packet_header, const u_char *packet)
{
    const struct ethhdr *eth = (struct ethhdr *)packet;
    const struct iphdr *ip;
    char source[18], dest[18];


    /*** OSI level 2 ***/
    if (packet_header->caplen < ETHER_HDRLEN) {
        fprintf(stderr, "Packet length less than ethernet header length\n");
        return;
    }

    /* string returned by ether_ntoa() is in a statically allocated buffer */
    strcpy(source, ether_ntoa((struct ether_addr *)&(eth->h_source)));
    strcpy(dest, ether_ntoa((struct ether_addr *)&(eth->h_dest)));
    printf("ETH  src=%s dst=%s\n", source, dest);

    /*** OSI level 3 ***/
    /* jump pass the ethernet header */
    ip = (struct iphdr*)(packet + sizeof(struct ether_header));

    /* check to see we have a packet of valid length */
    if (packet_header->len - sizeof(struct ethhdr) < sizeof(struct iphdr)) {
        fprintf(stderr, "Truncated IP");
        return;
    }

    /* check header length */
    if(ip->ihl < 5) {
        printf("Bad header length: %d\n", ip->ihl);
        return;
    }

    /* check IP version */
    if(ip->version != IPVERSION) {
        fprintf(stderr, "Unknown version: IPv%d\n", ip->version);
        return;
    }

    /* string returned by inet_ntoa() is in a statically allocated buffer */
    strcpy(source, inet_ntoa(*(struct in_addr *)&ip->saddr));
    strcpy(dest, inet_ntoa(*(struct in_addr *)&ip->daddr));

    printf("IP   src=%s dst=%s\n", source, dest);
}

/**
 * Compute IP/ICMP checksum
 * Note: Before starting the calculation, the checksum field must be zero
 *
 * @param addr   The pointer on the begginning of the packet
 * @param length Length which be computed
 * @return The 16 bits unsigned integer checksum
 */
u_int16_t ip_icmp_calc_checksum(const u_int16_t *addr, int length)
{
    int left = length;
    const u_int16_t *w = addr;
    u_int16_t answer;
    register int sum = 0;

    while (left > 1)  {
        sum += *w++;
        left -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (left == 1)
        sum += htons(*(u_char *)w << 8);

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);    /* add hi 16 to low 16 */
    sum += (sum >> 16);    /* add carry */
    answer = ~sum; /* truncate to 16 bits */
    return answer;
}

/**
 * Compute TCP/UDP checksum
 * Note: Before starting the calculation, the checksum field must be zero
 *
 * @param ip       The pointer on the IP packet
 * @param tcp_udp  The pointer on the TCP/UDP packet
 * @param protocol The protocol (IPPROTO_TCP or IPPROTO_UDP)
 * @return The 16 bits unsigned integer checksum
 */
u_int16_t tcp_udp_calc_checksum(const struct iphdr *ip,
        union tcp_udp_u *tcp_udp, int protocol)
{
    uint16_t ip_tlen = ntohs(ip->tot_len);
    uint16_t tcp_udp_tlen = ip_tlen - ip->ihl * 4;
    uint16_t tcp_udp_hlen = tcp_udp_tlen - sizeof(tcp_udp);
    uint16_t tcp_udp_dlen = tcp_udp_tlen - tcp_udp_hlen;
    uint16_t new_tcp_udp_len = sizeof(pseudo_header) + sizeof(tcp_udp)
        + tcp_udp_dlen;
    unsigned short *new_tcp_udp;

    switch(protocol) {
        case IPPROTO_TCP:
            tcp_udp->tcp.check = 0;
            break;
        case IPPROTO_UDP:
            tcp_udp->udp.check = 0;
            break;
        default:
            return 0;
    }

    pseudo_header.src_addr = ip->saddr;
    pseudo_header.dst_addr = ip->daddr;
    pseudo_header.zero = 0;
    pseudo_header.proto = protocol;
    pseudo_header.length = htons(tcp_udp_tlen);

    if ((new_tcp_udp = (unsigned short *)malloc(
                    new_tcp_udp_len * sizeof(unsigned short))) == NULL) {
        perror("Unable to allocate the pseudo TCP/UDP header");
        exit(1);
    }

    memcpy((u_short *)new_tcp_udp, &pseudo_header, sizeof(pseudo_header));
    memcpy((u_short *)new_tcp_udp + sizeof(pseudo_header),
            (u_char *)tcp_udp, sizeof(tcp_udp));
    memcpy((u_short *)new_tcp_udp + sizeof(pseudo_header) + sizeof(tcp_udp),
            (u_char *)tcp_udp + sizeof(tcp_udp), tcp_udp_dlen);

    return ip_icmp_calc_checksum((const u_short *)new_tcp_udp,
            new_tcp_udp_len);
}

/**
 * Nat a packet
 *
 * @param from_interface_id The originated interface ID
 * @param packet_header     The packet header
 * @param packet            The packet data
 * @return Whether the packet has been NATed or not (1 or 0)
 */
static int packet_nat(u_char from_interface_id,
        struct pcap_pkthdr *packet_header, u_char *packet)
{
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
    u_int16_t *src_port, *dst_port;
    struct table_record *record;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;
    int natted = 0;


    /* set ports pointers */
    switch (ip->protocol) {
        case IPPROTO_TCP:
            tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) +
                    sizeof(struct iphdr));
            src_port = &(tcp->source);
            dst_port = &(tcp->dest);
            break;

        case IPPROTO_UDP:
            udp = (struct udphdr *)(packet + sizeof(struct ethhdr) +
                    sizeof(struct iphdr));
            src_port = &(udp->source);
            dst_port = &(udp->dest);
            break;

        case IPPROTO_ICMP:
            icmp = (struct icmphdr *)(packet + sizeof(struct ethhdr));
            /* hack a bit: we use ICMP "identifier" field instead of port ;) */
            src_port = dst_port = &(icmp->un.echo.id);
            break;

        default:
            fprintf(stderr, "Unknown IP protocol, do not NAT the packet\n");
            return 0;
    }


    printf("%-4s src=%u dst=%u\n", ip_protocol_ntoa(ip->protocol),
            htons(*src_port), htons(*dst_port));


    if (from_interface_id == INTERFACE_INTERNAL) {

        record = table_outbound(ip->saddr, eth->h_source, htons(*src_port),
                ip->daddr);

        /* change source MAC */
        memcpy(eth->h_source, interfaces[INTERFACE_EXTERNAL].mac, ETH_ALEN);

        /* change dest MAC */
        memcpy(eth->h_dest, gateway.mac, ETH_ALEN);

        /* change source IP */
        ip->saddr = interfaces[INTERFACE_EXTERNAL].ip;

        /* change source port */
        *src_port = ntohs(record->external_port);

        natted = 1;

    } else {

        /* if we known the sender */
        if ((record = table_inbound(ip->saddr, htons(*src_port)))) {

            /* change source MAC */
            memcpy(eth->h_source, interfaces[INTERFACE_INTERNAL].mac, ETH_ALEN);

            /* change dest MAC */
            memcpy(eth->h_dest, record->internal_mac, ETH_ALEN);

            /* change dest IP */
            ip->daddr = record->internal_ip;

            /* change dest port */
            *dst_port = ntohs(record->internal_port);

            natted = 1;

        }

    }

    if (natted) {
        /* compute TCP/UDP checksum */
        switch (ip->protocol) {
            case IPPROTO_TCP:
                tcp->check = tcp_udp_calc_checksum(ip, (union tcp_udp_u *)tcp,
                        IPPROTO_TCP);
                break;

            case IPPROTO_UDP:
                udp->check = tcp_udp_calc_checksum(ip, (union tcp_udp_u *)udp,
                        IPPROTO_UDP);
                break;

            case IPPROTO_ICMP:
                icmp->checksum = 0;
                icmp->checksum = ip_icmp_calc_checksum((u_short *)icmp,
                        ip->tot_len - ip->ihl * 4);
                break;
        }

        /* compute IP checksum */
        /* checksum field must be null before computing new checksum */
        ip->check = 0;
        ip->check = ip_icmp_calc_checksum((u_short *)ip, ip->ihl * 4);

        return 1;
    }

    return 0;
}

/**
 * Inject a packet on an interface
 *
 * @param from_interface_id The interface ID where the packet should be sent
 * @param packet_header     The packet header
 * @param packet            The packet data
 */
static void packet_inject(u_char interface_id,
        const struct pcap_pkthdr *packet_header,
        const u_char *packet)
{
    int n;

    if ((n = pcap_inject(interfaces[interface_id].descriptor, packet,
                    packet_header->len)) == -1) {
        fprintf(stderr, "Injection failure on %s\n",
                interfaces[interface_id].device);
        exit(EXIT_FAILURE);
    }
}

/**
 * Callback function for all captured packets, NAT and print them
 *
 * @param from_interface_id The interface ID from where the packet was captured
 * @param packet_header     The packet header
 * @param packet            The packet data
 */
static void callback(u_char *from_interface_id,
        const struct pcap_pkthdr *packet_header,
        const u_char *packet)
{
    sem_wait(&mutex); /* to avoid interlaced printf() on several packets */

    printf("\nNew IP packet on %s:\n", interfaces[*from_interface_id].device);
    packet_print(packet_header, packet);

    if (packet_nat(*from_interface_id, (struct pcap_pkthdr *)packet_header,
                (u_char *)packet)) { /* the packet have to be natted */
        packet_print(packet_header, packet);
        table_print(PRINT_ALL);
        packet_inject((*from_interface_id == INTERFACE_INTERNAL ?
                    INTERFACE_EXTERNAL : INTERFACE_INTERNAL),
                packet_header, packet); /* forward our natted packet */
    }

    sem_post(&mutex); /* release our semaphore */
}

/**
 * Open an interface in listening mode
 *
 * @param interface_id The interface ID
 */
static void listen_interface(int interface_id)
{
    uint32_t subnet, netmask;
    char subnet_str[18], netmask_str[18];
    struct bpf_program fp; /* hold compiled program */
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[] = "ip"; /* handle only IP packets */


    printf("Trying to listen on %s...\n", interfaces[interface_id].device);

    /* get MAC & IP addresses */
    get_interface_addresses(interface_id);

    /* ask pcap for the network subnet and mask of the interface */
    if (pcap_lookupnet(interfaces[interface_id].device, &subnet, &netmask,
                errbuf) < 0) {
        fprintf(stderr, "Could not get local IP network info: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    strcpy(subnet_str, inet_ntoa(*(struct in_addr *)&subnet));
    strcpy(netmask_str, inet_ntoa(*(struct in_addr *)&netmask));
    printf("%s: hwaddr = %16s, ipaddr = %13s,\n"
            "      subnet = %13s, netmask = %13s\n",
            interfaces[interface_id].device,
            ether_ntoa((struct ether_addr *)&(interfaces[interface_id].mac)),
            inet_ntoa(*(struct in_addr *)&(interfaces[interface_id].ip)),
            subnet_str, netmask_str);

    /* open interface for reading in promiscuous mode */
    if ((interfaces[interface_id].descriptor =
                pcap_open_live(interfaces[interface_id].device, BUFSIZ, 1, -1,
                    errbuf)) == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* lets try and compile the filter */
    if (pcap_compile(interfaces[interface_id].descriptor, &fp, filter, 0,
                subnet) == -1) {
        fprintf(stderr, "Error compiling filter\n");
        exit(EXIT_FAILURE);
    }

    /* set the compiled filter */
    if (pcap_setfilter(interfaces[interface_id].descriptor, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(EXIT_FAILURE);
    }

    /* everything is good! */
    printf("Listening on %s...\n", interfaces[interface_id].device);

    /* loop forever */
    pcap_loop(interfaces[interface_id].descriptor, 0, callback,
            (u_char *)(&interface_id));
}

/**
 * Grab and store MAC & IP addresses for an interface
 *
 * @param interface_id The ID of the NAT interface
 */
void get_interface_addresses(int interface_id)
{
    libnet_t *libnet = NULL;
    char error[LIBNET_ERRBUF_SIZE];
    struct libnet_ether_addr *mac_addr;
    u_int32_t ip_addr;

    /* open libnet */
    libnet = libnet_init(LIBNET_LINK, interfaces[interface_id].device, error);

    /* get MAC address */
    mac_addr = libnet_get_hwaddr(libnet);
    memcpy(interfaces[interface_id].mac, mac_addr, ETH_ALEN);

    /* get IP address */
    ip_addr = libnet_get_ipaddr4(libnet);
    memcpy(&(interfaces[interface_id].ip), &ip_addr, IP_ALEN);

    /* print interface addresses */
#ifdef DEBUG
    printf("%s MAC: %s\n", interfaces[interface_id].device,
            ether_ntoa((struct ether_addr *)&(interfaces[interface_id].mac)));
    printf("%s IP: %s\n", interfaces[interface_id].device,
            inet_ntoa(*(struct in_addr *)&(interfaces[interface_id].ip)));
#endif
}

/**
 * Where it all begins! :D
 */
int main(int argc, char **argv)
{
    int sig;
    struct in_addr gateway_addr;


    /* must be r00t to listen on interfaces */
    if (getuid() && geteuid()) {
        fprintf(stderr, "R007 M3 P13453!\n");
        return EXIT_FAILURE;
    }

    /* check arguments count */
    if(argc != 4) {
        printf("Usage: %s internal_interface external_interface gateway_IP\n",
                argv[0]);
        return EXIT_SUCCESS;
    }

    /* setup our signals handler */
    for (sig = 1; sig < NSIG; sig++)
        signal(SIGINT, signal_handler);

    /* store interface names (e.g. "eth0") */
    interfaces[INTERFACE_INTERNAL].device = argv[1];
    interfaces[INTERFACE_EXTERNAL].device = argv[2];

    if (inet_aton(argv[3], &gateway_addr) == 0) {
        perror("gateway");
        exit(EXIT_FAILURE);
    }

    gateway.ip = gateway_addr.s_addr;
    gateway.interface = INTERFACE_EXTERNAL;

    printf("\nRetrieving gateway addresses...\n");
    arp_request(argv[3], interfaces[gateway.interface].device,
            (u_char *)&gateway.mac);

    printf("Gateway MAC: %s\n",
            ether_ntoa((struct ether_addr *)&(gateway.mac)));
    printf("Gateway IP:  %s\n", inet_ntoa(*(struct in_addr *)&(gateway.ip)));

    printf("\n");

    /* set our semaphore for future usage */
    sem_init(&mutex, 0, 1);

    /* start our two threads for interfaces listenning */
    if (pthread_create(&(interfaces[INTERFACE_INTERNAL].thread), NULL,
                listen_interface, INTERFACE_INTERNAL)) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&(interfaces[INTERFACE_EXTERNAL].thread), NULL,
                listen_interface, INTERFACE_EXTERNAL)) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }

    /* wait for thread ending, it should never happen because they stop from
     * signals handler */
    if (pthread_join(interfaces[INTERFACE_INTERNAL].thread, NULL))
        perror("pthread_join");

    if (pthread_join(interfaces[INTERFACE_EXTERNAL].thread, NULL))
        perror("pthread_join");

    fprintf(stderr, "\nOops!\n");

    return EXIT_FAILURE;
}
