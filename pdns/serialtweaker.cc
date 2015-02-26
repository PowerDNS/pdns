/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsseckeeper.hh"
#include "dnspacket.hh"
#include "namespaces.hh"
#include <boost/foreach.hpp>

uint32_t localtime_format_YYYYMMDDSS(time_t t, uint32_t seq)
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
      return editSOARecord(rr, kind);
    }
  }
  return false;
}

bool editSOARecord(DNSResourceRecord& rr, const string& kind) {
  if(kind.empty())
    return false;

  SOAData sd;
  fillSOAData(rr.content, sd);
  sd.serial = calculateEditSOA(sd, kind);
  rr.content = serializeSOAData(sd);
  return true;
}

uint32_t calculateEditSOA(SOAData sd, const string& kind) {
  if(pdns_iequals(kind,"INCEPTION")) {
    time_t inception = getStartOfWeek();
    return localtime_format_YYYYMMDDSS(inception, 1);
  }
  else if(pdns_iequals(kind,"INCEPTION-INCREMENT")) {
    time_t inception = getStartOfWeek();
    uint32_t inception_serial = localtime_format_YYYYMMDDSS(inception, 1);
    uint32_t dont_increment_after = localtime_format_YYYYMMDDSS(inception + 2*86400, 99);

    if(sd.serial < inception_serial - 1) { /* less than <inceptionday>00 */
      return inception_serial; /* return <inceptionday>01   (skipping <inceptionday>00 as possible value) */
    } else if(sd.serial <= dont_increment_after) { /* >= <inceptionday>00 but <= <inceptionday+2>99 */
      return (sd.serial + 2); /* "<inceptionday>00" and "<inceptionday>01" are reserved for inception increasing, so increment sd.serial by two */
    }
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
    uint32_t inception = getStartOfWeek();
    if (sd.serial < inception)
      return inception;
  }
  return sd.serial;
}

// Used for SOA-EDIT-DNSUPDATE and SOA-EDIT-API.
uint32_t calculateIncreaseSOA(SOAData sd, const string& increaseKind, const string& editKind) {
  // These only work when SOA-EDIT is set, otherwise fall back to default.
  if (!editKind.empty()) {
    if (pdns_iequals(increaseKind, "SOA-EDIT-INCREASE")) {
      uint32_t new_serial = calculateEditSOA(sd, editKind);
      if (new_serial <= sd.serial) {
        new_serial = sd.serial + 1;
      }
      return new_serial;
    }
    else if (pdns_iequals(increaseKind, "SOA-EDIT")) {
      return calculateEditSOA(sd, editKind);
    }
  }

  if (pdns_iequals(increaseKind, "INCREASE")) {
    return sd.serial + 1;
  }
  else if (pdns_iequals(increaseKind, "EPOCH")) {
    return time(0);
  }

  // DEFAULT case
  time_t now = time(0);
  struct tm tm;
  localtime_r(&now, &tm);
  boost::format fmt("%04d%02d%02d%02d");
  string newdate = (fmt % (tm.tm_year + 1900) % (tm.tm_mon + 1) % tm.tm_mday % 1).str();
  uint32_t new_serial = atol(newdate.c_str());
  if (new_serial <= sd.serial) {
    new_serial = sd.serial + 1;
  }
  return new_serial;
}

bool increaseSOARecord(DNSResourceRecord& rr, const string& increaseKind, const string& editKind) {
  if (increaseKind.empty())
    return false;

  SOAData sd;
  fillSOAData(rr.content, sd);
  sd.serial = calculateIncreaseSOA(sd, increaseKind, editKind);
  rr.content = serializeSOAData(sd);
  return true;
}
