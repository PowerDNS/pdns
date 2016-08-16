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
#pragma once

#include "dnsparser.hh"
#include "dnsname.hh"
#include <vector>
#include "namespaces.hh"
#include "dnsrecords.hh"
 
extern bool g_dnssecLOG;

// 4033 5
enum vState { Indeterminate, Bogus, Insecure, Secure, NTA };
extern const char *vStates[];

// NSEC(3) results
enum dState { NODATA, NXDOMAIN, ENT, INSECURE };
extern const char *dStates[];


class DNSRecordOracle
{
public:
  virtual std::vector<DNSRecord> get(const DNSName& qname, uint16_t qtype)=0;
};


struct ContentSigPair
{
  vector<shared_ptr<DNSRecordContent>> records;
  vector<shared_ptr<RRSIGRecordContent>> signatures;
  // ponder adding a validate method that accepts a key
};
typedef map<pair<DNSName,uint16_t>, ContentSigPair> cspmap_t;
typedef std::set<DSRecordContent> dsmap_t;
void validateWithKeySet(const cspmap_t& rrsets, cspmap_t& validated, const std::set<DNSKEYRecordContent>& keys);
cspmap_t harvestCSPFromRecs(const vector<DNSRecord>& recs);
vState getKeysFor(DNSRecordOracle& dro, const DNSName& zone, std::set<DNSKEYRecordContent> &keyset);

