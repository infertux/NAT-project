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

#include <linux/types.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define MIN_EXTERNAL_PORT 1024
#define MAX_EXTERNAL_PORT 65535
#define RECORD_TIMEOUT 60 /* in seconds */


/* Verbosity level */
enum print_mode {PRINT_ALL, PRINT_BRIEF};

/* A node in our linked-list table */
struct table_record {
    uint8_t     internal_mac[ETH_ALEN];
    uint32_t    internal_ip;
    uint16_t    internal_port;
    uint32_t    external_ip;
    uint16_t    external_port;
    time_t      touch;
    struct table_record *next;
} *table;


/* Our functions prototypes */
void table_print(enum print_mode mode);
struct table_record *table_outbound(uint32_t internal_ip,
        uint8_t *internal_mac, uint16_t internal_port, uint32_t external_ip);
struct table_record *table_inbound(uint32_t external_ip,
        uint16_t external_port);

