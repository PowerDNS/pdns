/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "dnsseckeeper.hh"
#include "dnspacket.hh"
#include "namespaces.hh"
#include <boost/foreach.hpp>

static uint32_t localtime_format_YYYYMMDDSS(time_t t, uint32_t seq)
{
  struct tm tm;
  localtime_r(&t, &tm);
  return
      (uint32_t)(tm.tm_year+1900) * 1000000u
    + (uint32_t)(tm.tm_mon + 1) * 10000u
    + (uint32_t)tm.tm_mday * 100u
    + seq;
}

bool editSOA(DNSSECKeeper& dk, const string& qname, DNSPacket* dp)
{
  vector<DNSResourceRecord>& rrs = dp->getRRS();
  BOOST_FOREACH(DNSResourceRecord& rr, rrs) {
    if(rr.qtype.getCode() == QType::SOA && pdns_iequals(rr.qname,qname)) {
      string kind;
      dk.getFromMeta(qname, "SOA-EDIT", kind);
      if(kind.empty())
        return false;
      SOAData sd;
      fillSOAData(rr.content, sd);
      sd.serial = calculateEditSoa(sd, kind);
      rr.content = serializeSOAData(sd);      
      return true;
    }
  }
  return false;
}


uint32_t calculateEditSoa(SOAData sd, const string& kind) {
  if(pdns_iequals(kind,"INCEPTION")) {
    time_t inception = getStartOfWeek();
    return localtime_format_YYYYMMDDSS(inception, 1);
  }
  else if(pdns_iequals(kind,"INCEPTION-INCREMENT")) {
    time_t inception = getStartOfWeek();
    uint32_t inception_serial = localtime_format_YYYYMMDDSS(inception, 1);
    uint32_t dont_increment_after = localtime_format_YYYYMMDDSS(inception + 2*86400, 99);

    if(sd.serial <= dont_increment_after)
      return (sd.serial + 2); /* "day00" and "day01" are reserved for inception increasing, so increment sd.serial by two */
    else if(sd.serial < inception_serial) 
      return inception_serial;
  }
  else if(pdns_iequals(kind,"INCEPTION-WEEK")) {
    time_t inception = getStartOfWeek();
    return ( inception / (7*86400) );
  }
  else if(pdns_iequals(kind,"INCREMENT-WEEKS")) {
    time_t inception = getStartOfWeek();
    return (sd.serial + (inception / (7*86400)));
  }
  else if(pdns_iequals(kind,"EPOCH")) {
    return time(0);
  }
  else if(pdns_iequals(kind,"INCEPTION-EPOCH")) {
    time_t inception = getStartOfWeek();
    if (sd.serial < inception)
      return inception;
  }
  return sd.serial;
}
