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
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <time.h>
#include "table.h"


/**
 * Print each records of the natting table
 *
 * @param mode Verbosity level (see enum print_mode)
 */
void table_print(enum print_mode mode)
{
    struct table_record *record;

    if (mode == PRINT_ALL)
        printf("     internal MAC |");

    printf("  internal IP | in. port | ex. port |   external IP");

    if (mode == PRINT_ALL)
        printf(" | touch");

    printf("\n");

    for (record = table; record; record = record->next) {
        if (mode == PRINT_ALL)
            printf("%17s |",
                    ether_ntoa((struct ether_addr *)&(record->internal_mac)));

        printf("%13s | %8u | ",
                inet_ntoa(*(struct in_addr *)&(record->internal_ip)),
                record->internal_port);
        printf("%8u | %13s",
                record->external_port,
                inet_ntoa(*(struct in_addr *)&(record->external_ip)));

        if (mode == PRINT_ALL)
            printf(" | %lu", (long unsigned)record->touch);

        printf("\n");
    }

    printf("\n");
}

/**
 * Get the mapped external port for a record
 *
 * @param internal_ip   The internal IP address
 * @param internal_port The internal port
 * @param external_ip   The external IP address
 * @return The mapped port (or 0 if not found)
 */
uint16_t table_get_external_port(uint32_t internal_ip, uint16_t internal_port,
        uint16_t external_ip)
{
    uint16_t external_port = 0;
    struct table_record *record;

    srand(time(NULL));

    do {
        external_port = rand() % (MAX_EXTERNAL_PORT - MIN_EXTERNAL_PORT)
            + MIN_EXTERNAL_PORT;
        for (record = table; record && record->external_port != external_port;
                record = record->next);
    } while (record);

    return external_port;
}

/**
 * Adds a record in the table
 *
 * @param internal_ip   The internal IP address
 * @param internal_mac  The internal MAC address
 * @param internal_port The internal port
 * @param external_ip   The external IP address
 * @return The new added record (beginning of the table)
 */
struct table_record *table_add(uint32_t internal_ip, uint8_t *internal_mac,
        uint16_t internal_port, uint32_t external_ip)
{
    struct table_record *record;

    if ((record = (struct table_record *)malloc(sizeof(struct table_record)))
            == NULL) {
        perror("Unable to allocate a new record");
        return NULL;
    }

    memcpy(record->internal_mac, internal_mac, ETH_ALEN); /* broadcast */
    record->internal_ip = internal_ip;
    record->internal_port = internal_port;
    record->external_ip = external_ip;
    record->external_port = table_get_external_port(internal_ip, internal_port,
            external_ip);
    record->touch = time(NULL); /* current timestamp */

    if (table) {
        record->next = table;
        table = record;
    } else {
        table = record;
    }

    return table;
}

/**
 * Proccess an outcomming packet and delete old records
 *
 * @param internal_ip   The internal IP address
 * @param internal_mac  The internal MAC address
 * @param internal_port The internal port
 * @param external_ip   The external IP address
 * @return The corresponding record
 */
struct table_record *table_outbound(uint32_t internal_ip,
        uint8_t *internal_mac,
        uint16_t internal_port,
        uint32_t external_ip)
{
    struct table_record *record = table;
    struct table_record *before = NULL;

    while (record) {
        if (record->internal_ip == internal_ip &&
                record->internal_port == internal_port &&
                record->external_ip == external_ip) {
            record->touch = time(NULL); /* touch! */
            return record;
        }

        /* obsolete record */
        if (before && record->touch < time(NULL) + RECORD_TIMEOUT) { 
            before->next = record->next;
            free(record);
        }

        before = record;
        record = record->next;
    }

    return table_add(internal_ip, internal_mac, internal_port, external_ip);
}

/**
 * Proccess an incomming packet
 *
 * @param external_ip   The external IP address
 * @param external_port The external port
 * @return The corresponding record
 */
struct table_record *table_inbound(uint32_t external_ip,
        uint16_t external_port)
{
    struct table_record *record = table;

    while (record) {
        if (record->external_ip == external_ip &&
                record->external_port == external_port &&
                record->touch < time(NULL) + RECORD_TIMEOUT) {
            record->touch = time(NULL); /* touch! */
            return record;
        }

        record = record->next;
    }

#ifdef DEBUG
    fprintf(stderr, 
            "Warning: incomming packet from unknown tuple (IP, port)\n");
#endif

    return NULL; /* packet should be ignored or returned to sender */
}

