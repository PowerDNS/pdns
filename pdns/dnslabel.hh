/*
	PowerDNS Versatile Database Driven Nameserver
		Copyright (C) 2010 Netherlabs Computer Consulting BV

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License version 2
	as published by the Free Software Foundation

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <string>
#include <stdio.h>
#include <iostream>
#include <string.h>
#include <stdexcept>
using std::string;
using std::cerr;
using std::endl;


/* the idea of dnslabel is that we guard our input, and from that point
 * onwards, trust the contents of d_storage.
 *
 * On input we deal with escapes etc, on output we re-escape.
 * This can be slow since we hope with all our might not to be
 * using the 'human' interfaces too much, and keep everything as a
 * native DNS label all the time.
 *
 * The goal for DNSLabel is to be 'holier than thou' and adhere
 * to all relevant RFCs. This means implementing the really odd DNS case
 * sensitivity rules, doing all the escaping properly and deal
 * with embedded nuls.
 *
 * Design
 * As a special speedup, we implement 'chopping' by having an offset
 * counter. This means that the oft-repeated 'www.powerdns.com.'
 * 'powerdns.com.', 'com.', '.' sequence does not involve any mallocs.
 */
class DNSLabel
{
public:
	explicit DNSLabel(const char* human);
	explicit DNSLabel(const std::string& human);
	DNSLabel(const char* raw, unsigned int length);
	DNSLabel(const DNSLabel& rhs);
	DNSLabel(const char* raw, const char* beginPacket, unsigned int packetLength, unsigned int* len);
	DNSLabel();
	~DNSLabel();
	string human() const;
	string binary() const;
	bool endsOn(const DNSLabel& rhs) const;
	bool chopOff();
	bool operator<(const DNSLabel& rhs) const;
	bool operator==(const DNSLabel& rhs) const;
	DNSLabel& operator=(const DNSLabel& rhs);
	int project(char* target, unsigned int length);
	static int validateConsume(const char* raw, unsigned int len);
	static bool validateStrict(const char* raw, unsigned int len);

	static DNSLabel createFromBuffer(const char* raw, unsigned int* len);
private:
	char* d_storage;
	unsigned int d_fulllen;
	unsigned int d_offset;
	unsigned int d_capacity;
	void init(unsigned int len=64);
	unsigned int getLength() const
	{
		return d_fulllen - d_offset;
	}

	const char* getStart() const
	{
		return d_storage + d_offset;
	}

	void appendChar(char c)
	{
		if(d_fulllen == d_capacity)
			expandCapacity();
		d_storage[d_fulllen++]= c;
	}
	void appendRange(const char* ptr, unsigned int len)
	{
		if(d_fulllen + len > d_capacity)
			expandCapacity(len);
		memcpy(d_storage + d_fulllen, ptr, len);
		d_fulllen += len;
	}

	void expandCapacity(unsigned int len=0);
	void chaseLabel(const char* raw, const char* beginPacket, unsigned int packetLength, unsigned int* len, bool updateLen);
};
