/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
// $Id: dns.hh,v 1.1 2002/11/27 15:18:31 ahu Exp $ 
/* (C) 2002 POWERDNS.COM BV */
#ifndef DNS_HH
#define DNS_HH

#include "utility.hh"
#include "qtype.hh"
#include <time.h>
#include <sys/types.h>
class DNSBackend;

struct SOAData
{
  string qname;
  string nameserver;
  string hostmaster;
  u_int32_t ttl;
  u_int32_t serial;
  u_int32_t refresh;
  u_int32_t retry;
  u_int32_t expire;
  u_int32_t default_ttl;
  int domain_id;
  DNSBackend *db;
};


class RCode
{
public:
  enum { NoError=0, FormErr=1, ServFail=2, NXDomain=3, NotImp=4, Refused=5 };
};

class Opcode
{
public:
  enum { Query=0, IQuery=1, Status=2, Notify=4, Update=5 };
};


//! This class represents a resource record
class DNSResourceRecord
{
public:
  DNSResourceRecord() : d_place(ANSWER){};
  ~DNSResourceRecord(){};

  string serialize() const;
  int unSerialize(const string &str);

  // data
  
  QType qtype; //!< qtype of this record, ie A, CNAME, MX etc
  string qname; //!< the name of this record, for example: www.powerdns.com
  string content; //!< what this record points to. Example: 10.1.2.3
  u_int16_t priority; //!< For qtype's that support a priority or preference. Currently only MX
  u_int32_t ttl; //!< Time To Live of this record
  int domain_id; //!< If a backend implements this, the domain_id of the zone this record is in
  time_t last_modified; //!< For autocalculating SOA serial numbers - the backend needs to fill this in
  enum Place {QUESTION=0, ANSWER=1, AUTHORITY=2, ADDITIONAL=3}; //!< Type describing the positioning of a DNSResourceRecord within, say, a DNSPacket
  Place d_place; //!< This specifies where a record goes within the packet

private:
  string escape(const string &str) const;
};

#define L theL()
extern time_t s_starttime;

#endif
