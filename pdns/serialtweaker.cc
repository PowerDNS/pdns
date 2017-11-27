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

bool editSOA(DNSSECKeeper& dk, const DNSName& qname, DNSPacket* dp)
{
  for(auto& rr :  dp->getRRS()) {
    if(rr.dr.d_type == QType::SOA && rr.dr.d_name == qname) {
      string kind;
      dk.getSoaEdit(qname, kind);
      return editSOARecord(rr, kind);
    }
  }
  return false;
}

bool editSOARecord(DNSZoneRecord& rr, const string& kind) {
  if(kind.empty())
    return false;
  auto src = getRR<SOARecordContent>(rr.dr);
  src->d_st.serial=calculateEditSOA(rr, kind);

  return true;
}

uint32_t calculateEditSOA(const DNSZoneRecord& rr, const string& kind)
{
  auto src = getRR<SOARecordContent>(rr.dr);
  if(pdns_iequals(kind,"INCEPTION-INCREMENT")) {
    time_t inception = getStartOfWeek();
    uint32_t inception_serial = localtime_format_YYYYMMDDSS(inception, 1);
    uint32_t dont_increment_after = localtime_format_YYYYMMDDSS(inception + 2*86400, 99);

    if(src->d_st.serial < inception_serial - 1) { /* less than <inceptionday>00 */
      return inception_serial; /* return <inceptionday>01   (skipping <inceptionday>00 as possible value) */
    } else if(src->d_st.serial <= dont_increment_after) { /* >= <inceptionday>00 but <= <inceptionday+2>99 */
      return (src->d_st.serial + 2); /* "<inceptionday>00" and "<inceptionday>01" are reserved for inception increasing, so increment sd.serial by two */
    }
  }
  else if(pdns_iequals(kind,"INCREMENT-WEEKS")) {
    time_t inception = getStartOfWeek();
    return (src->d_st.serial + (inception / (7*86400)));
  }
  else if(pdns_iequals(kind,"EPOCH")) {
    return time(0);
  }
  else if(pdns_iequals(kind,"INCEPTION-EPOCH")) {
    uint32_t inception = getStartOfWeek();
    if (src->d_st.serial < inception)
      return inception;
  } else if(!kind.empty()) {
    L<<Logger::Warning<<"SOA-EDIT type '"<<kind<<"' for zone "<<rr.dr.d_name<<" is unknown."<<endl;
  }
  return src->d_st.serial;
}

uint32_t calculateEditSOA(const SOAData& sd, const string& kind)
{
  DNSZoneRecord dzr;
  dzr.dr.d_name=sd.qname;
  struct soatimes st;
  st.serial = sd.serial;
  dzr.dr.d_content = std::make_shared<SOARecordContent>(sd.nameserver, sd.hostmaster, st);
  return calculateEditSOA(dzr, kind);
}

// Used for SOA-EDIT-DNSUPDATE and SOA-EDIT-API.
uint32_t calculateIncreaseSOA(DNSZoneRecord& dzr, const string& increaseKind, const string& editKind) {
  auto src = getRR<SOARecordContent>(dzr.dr);
  // These only work when SOA-EDIT is set, otherwise fall back to default.
  if (!editKind.empty()) {
    if (pdns_iequals(increaseKind, "SOA-EDIT-INCREASE")) {
      uint32_t new_serial = calculateEditSOA(dzr, editKind);
      if (new_serial <= src->d_st.serial) {
        new_serial = src->d_st.serial + 1;
      }
      return new_serial;
    }
    else if (pdns_iequals(increaseKind, "SOA-EDIT")) {
      return calculateEditSOA(dzr, editKind);
    }
  }

  if (pdns_iequals(increaseKind, "INCREASE")) {
    return src->d_st.serial + 1;
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
  uint32_t new_serial = pdns_stou(newdate);
  if (new_serial <= src->d_st.serial) {
    new_serial = src->d_st.serial + 1;
  }
  return new_serial;
}

// Used for SOA-EDIT-DNSUPDATE and SOA-EDIT-API.
uint32_t calculateIncreaseSOA(SOAData sd, const string& increaseKind, const string& editKind) {
  DNSZoneRecord dzr;
  dzr.dr.d_name=sd.qname;
  struct soatimes st;
  st.serial = sd.serial;
  dzr.dr.d_content = std::make_shared<SOARecordContent>(sd.nameserver, sd.hostmaster, st);
  return calculateIncreaseSOA(dzr, increaseKind, editKind);
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
