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
extern time_t g_signatureInceptionSkew;
extern uint16_t g_maxNSEC3Iterations;

// 4033 5
enum vState { Indeterminate, Bogus, Insecure, Secure, NTA, TA };
extern const char *vStates[];

// NSEC(3) results
enum dState { NODATA, NXDOMAIN, NXQTYPE, ENT, INSECURE, OPTOUT};
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

struct sharedDNSKeyRecordContentCompare
{
  bool operator() (const shared_ptr<DNSKEYRecordContent>& a, const shared_ptr<DNSKEYRecordContent>& b) const
  {
    return *a < *b;
  }
};

typedef set<shared_ptr<DNSKEYRecordContent>, sharedDNSKeyRecordContentCompare > skeyset_t;

bool validateWithKeySet(time_t now, const DNSName& name, const vector<shared_ptr<DNSRecordContent> >& records, const vector<shared_ptr<RRSIGRecordContent> >& signatures, const skeyset_t& keys, bool validateAllSigs=true);
void validateWithKeySet(const cspmap_t& rrsets, cspmap_t& validated, const skeyset_t& keys);
cspmap_t harvestCSPFromRecs(const vector<DNSRecord>& recs);
vState getKeysFor(DNSRecordOracle& dro, const DNSName& zone, skeyset_t& keyset);
bool getTrustAnchor(const map<DNSName,dsmap_t>& anchors, const DNSName& zone, dsmap_t &res);
bool haveNegativeTrustAnchor(const map<DNSName,std::string>& negAnchors, const DNSName& zone, std::string& reason);
void validateDNSKeysAgainstDS(time_t now, const DNSName& zone, const dsmap_t& dsmap, const skeyset_t& tkeys, vector<shared_ptr<DNSRecordContent> >& toSign, const vector<shared_ptr<RRSIGRecordContent> >& sigs, skeyset_t& validkeys);
dState getDenial(const cspmap_t &validrrsets, const DNSName& qname, const uint16_t qtype, bool referralToUnsigned, bool wantsNoDataProof, bool needsWildcardProof=true, unsigned int wildcardLabelsCount=0);
bool isSupportedDS(const DSRecordContent& ds);
DNSName getSigner(const std::vector<std::shared_ptr<RRSIGRecordContent> >& signatures);
bool denialProvesNoDelegation(const DNSName& zone, const std::vector<DNSRecord>& dsrecords);
bool isRRSIGNotExpired(const time_t now, const shared_ptr<RRSIGRecordContent> sig);
bool isWildcardExpanded(unsigned int labelCount, const std::shared_ptr<RRSIGRecordContent>& sign);
bool isWildcardExpandedOntoItself(const DNSName& owner, unsigned int labelCount, const std::shared_ptr<RRSIGRecordContent>& sign);
