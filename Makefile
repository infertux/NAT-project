#   Copyright (C) 2010  Infertux <infertux@infertux.com>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as
#   published by the Free Software Foundation, either version 3 of the
#   License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.


# Deps: libpcap-devel libnet-devel

CFLAGS=-Wall -pedantic
CC=gcc

all: nat

clean:
	rm -f *.o nat

nat: nat.o table.o arp.o
	$(CC) $(CFLAGS) -o nat nat.o table.o arp.o -lpcap -lnet -lpthread

nat.o: nat.h

table.o: table.h

arp.o: arp.h
