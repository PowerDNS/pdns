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

uint32_t calculateEditSOA(uint32_t old_serial, const string& kind, const DNSName& zonename)
{
  if(pdns_iequals(kind,"INCEPTION-INCREMENT")) {
    time_t inception = getStartOfWeek();
    uint32_t inception_serial = localtime_format_YYYYMMDDSS(inception, 1);
    uint32_t dont_increment_after = localtime_format_YYYYMMDDSS(inception + 2*86400, 99);

    if(old_serial < inception_serial - 1) { /* less than <inceptionday>00 */
      return inception_serial; /* return <inceptionday>01   (skipping <inceptionday>00 as possible value) */
    } else if (old_serial < inception_serial+1) {
      /* "<inceptionday>00" and "<inceptionday>01" are reserved for inception increasing, so jump to "<inceptionday>02" */
      return inception_serial+1;
    } else if(old_serial <= dont_increment_after) { /* >= <inceptionday>00 but <= <inceptionday+2>99 */
      return old_serial + 1;
    }
  }
  else if(pdns_iequals(kind,"INCREMENT-WEEKS")) {
    time_t inception = getStartOfWeek();
    return (old_serial + (inception / (7*86400)));
  }
  else if(pdns_iequals(kind,"EPOCH")) {
    return time(0);
  }
  else if(pdns_iequals(kind,"INCEPTION-EPOCH")) {
    uint32_t inception = getStartOfWeek();
    if (old_serial < inception)
      return inception;
  }
  else if(pdns_iequals(kind,"NONE")) {
    // do nothing to serial. needed because a metadata of "" will use the default-soa-edit setting instead.
  }
  else if(!kind.empty()) {
    g_log<<Logger::Warning<<"SOA-EDIT type '"<<kind<<"' for zone "<<zonename<<" is unknown."<<endl;
  }
  // Seen strictly, this is a broken config: we can only come here if
  // both SOA-EDIT and default-soa-edit are set to "", but the latter
  // should be set to "NONE" instead.
  return old_serial;
}

uint32_t calculateEditSOA(uint32_t old_serial, DNSSECKeeper& dk, const DNSName& zonename) {
  string kind;
  dk.getSoaEdit(zonename, kind);
  return calculateEditSOA(old_serial, kind, zonename);
}

/** Used for SOA-EDIT-DNSUPDATE and SOA-EDIT-API. */
static uint32_t calculateIncreaseSOA(uint32_t old_serial, const string& increaseKind, const string& editKind, const DNSName& zonename) {
  if (pdns_iequals(increaseKind, "SOA-EDIT-INCREASE")) {
    uint32_t new_serial = old_serial;
    if (!editKind.empty()) {
      new_serial = calculateEditSOA(old_serial, editKind, zonename);
    }
    if (new_serial <= old_serial) {
      new_serial = old_serial + 1;
    }
    return new_serial;
  }
  else if (pdns_iequals(increaseKind, "SOA-EDIT")) {
    return calculateEditSOA(old_serial, editKind, zonename);
  }
  else if (pdns_iequals(increaseKind, "INCREASE")) {
    return old_serial + 1;
  }
  else if (pdns_iequals(increaseKind, "EPOCH")) {
    return time(0);
  }
  else if (pdns_iequals(increaseKind, "DEFAULT")) {
    time_t now = time(0);
    uint32_t new_serial = localtime_format_YYYYMMDDSS(now, 1);
    if (new_serial <= old_serial) {
        new_serial = old_serial + 1;
    }
    return new_serial;
  } else if(!increaseKind.empty()) {
    g_log<<Logger::Warning<<"SOA-EDIT-API/DNSUPDATE type '"<<increaseKind<<"' for zone "<<zonename<<" is unknown."<<endl;
  }
  return old_serial;
}

/** Used for SOA-EDIT-DNSUPDATE and SOA-EDIT-API.
 * Good if you already *have* a DNSResourceRecord.
 * Content in rr is suitable for writing into a backend.
 *
 * @return true if changes may have been made
 */
bool increaseSOARecord(DNSResourceRecord& rr, const string& increaseKind, const string& editKind) {
  if (increaseKind.empty())
    return false;

  SOAData sd;
  fillSOAData(rr.content, sd);

  sd.serial = calculateIncreaseSOA(sd.serial, increaseKind, editKind, rr.qname);
  rr.content = makeSOAContent(sd)->getZoneRepresentation(true);
  return true;
}

/** Used for SOA-EDIT-DNSUPDATE and SOA-EDIT-API.
 * Makes a mostly reset DNSResourceRecord for you in @param rrout.
 * Content in rrout is suitable for writing into a backend.
 *
 * @return true if rrout is now valid
 */
bool makeIncreasedSOARecord(SOAData& sd, const string& increaseKind, const string& editKind, DNSResourceRecord& rrout) {
  if (increaseKind.empty())
    return false;

  sd.serial = calculateIncreaseSOA(sd.serial, increaseKind, editKind, sd.qname);
  rrout.qname = sd.qname;
  rrout.content = makeSOAContent(sd)->getZoneRepresentation(true);
  rrout.qtype = QType::SOA;
  rrout.domain_id = sd.domain_id;
  rrout.auth = 1;
  rrout.ttl = sd.ttl;

  return true;
}

DNSZoneRecord makeEditedDNSZRFromSOAData(DNSSECKeeper& dk, const SOAData& sd, DNSResourceRecord::Place place) {
  SOAData edited = sd;
  edited.serial = calculateEditSOA(sd.serial, dk, sd.qname);

  DNSRecord soa;
  soa.d_name = sd.qname;
  soa.d_type = QType::SOA;
  soa.d_ttl = sd.ttl;
  soa.d_place = place;
  soa.d_content = makeSOAContent(edited);

  DNSZoneRecord dzr;
  dzr.domain_id = sd.domain_id;
  dzr.signttl = sd.ttl;
  dzr.auth = true;
  dzr.dr = soa;

  return dzr;
}
