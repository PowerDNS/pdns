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
      if(pdns_iequals(kind,"INCEPTION")) {        
	time_t inception = getCurrentInception();
	struct tm tm;
	localtime_r(&inception, &tm);
	boost::format fmt("%04d%02d%02d%02d");
	
	string newserdate=(fmt % (tm.tm_year+1900) % (tm.tm_mon +1 )% tm.tm_mday % 1).str();
        sd.serial = lexical_cast<uint32_t>(newserdate);
        rr.content = serializeSOAData(sd);
      }
      else if(pdns_iequals(kind,"INCEPTION-WEEK")) {        
	time_t inception = getCurrentInception();
	sd.serial = inception / (7*86400);
        rr.content = serializeSOAData(sd);
      }
      return true;
    }
  }
  return false;
}
