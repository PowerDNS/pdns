/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <sys/types.h>
#include <boost/multi_index_container.hpp>
#include "dnsparser.hh"
#include "dnsrecords.hh"

using namespace boost::multi_index;

struct CIContentCompareStruct
{
  bool operator()(const shared_ptr<DNSRecordContent>&a, const shared_ptr<DNSRecordContent>& b) const
  {
    return toLower(a->getZoneRepresentation()) < toLower(b->getZoneRepresentation());
  }
};


typedef multi_index_container <
  DNSRecord,
    indexed_by<
      ordered_non_unique<
        composite_key<DNSRecord,
                      member<DNSRecord, DNSName, &DNSRecord::d_name>,
                      member<DNSRecord, uint16_t, &DNSRecord::d_type>,
                      member<DNSRecord, uint16_t, &DNSRecord::d_class>,
                      member<DNSRecord, shared_ptr<DNSRecordContent>, &DNSRecord::d_content> >,
        composite_key_compare<CanonDNSNameCompare, std::less<uint16_t>, std::less<uint16_t>, CIContentCompareStruct >
      > /* ordered_non_uniquw */
    > /* indexed_by */
> /* multi_index_container */ records_t;

uint32_t getSerialFromMaster(const ComboAddress& master, const DNSName& zone, shared_ptr<SOARecordContent>& sr, const TSIGTriplet& tt = TSIGTriplet(), const uint16_t timeout = 2);
uint32_t getSerialFromDir(const std::string& dir);
uint32_t getSerialFromRecords(const records_t& records, DNSRecord& soaret);
void writeZoneToDisk(const records_t& records, const DNSName& zone, const std::string& directory);
void loadZoneFromDisk(records_t& records, const string& fname, const DNSName& zone);
void loadSOAFromDisk(const DNSName& zone, const string& fname, shared_ptr<SOARecordContent>& soa, uint32_t& soaTTL);
