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
#include "dnssecinfra.hh"
#include "logger.hh"

extern time_t g_signatureInceptionSkew;
extern uint16_t g_maxNSEC3Iterations;

// 4033 5
enum class vState : uint8_t { Indeterminate, Insecure, Secure, NTA, TA, BogusNoValidDNSKEY, BogusInvalidDenial, BogusUnableToGetDSs, BogusUnableToGetDNSKEYs, BogusSelfSignedDS, BogusNoRRSIG, BogusNoValidRRSIG, BogusMissingNegativeIndication, BogusSignatureNotYetValid, BogusSignatureExpired, BogusUnsupportedDNSKEYAlgo, BogusUnsupportedDSDigestType, BogusNoZoneKeyBitSet, BogusRevokedDNSKEY, BogusInvalidDNSKEYProtocol };
const std::string& vStateToString(vState state);
inline bool vStateIsBogus(vState state)
{
  return state >= vState::BogusNoValidDNSKEY;
}

// NSEC(3) results
enum class dState : uint8_t { NODENIAL, INCONCLUSIVE, NXDOMAIN, NXQTYPE, ENT, INSECURE, OPTOUT};

std::ostream& operator<<(std::ostream &os, const vState d);
std::ostream& operator<<(std::ostream &os, const dState d);

class DNSRecordOracle
{
public:
  virtual std::vector<DNSRecord> get(const DNSName& qname, uint16_t qtype)=0;
};


struct ContentSigPair
{
  sortedRecords_t records;
  vector<shared_ptr<const RRSIGRecordContent>> signatures;
  // ponder adding a validate method that accepts a key
};
typedef map<pair<DNSName,uint16_t>, ContentSigPair> cspmap_t;
typedef std::set<DSRecordContent> dsmap_t;

struct sharedDNSKeyRecordContentCompare
{
  bool operator() (const shared_ptr<const DNSKEYRecordContent>& a, const shared_ptr<const DNSKEYRecordContent>& b) const
  {
    return *a < *b;
  }
};

typedef set<shared_ptr<const DNSKEYRecordContent>, sharedDNSKeyRecordContentCompare > skeyset_t;


vState validateWithKeySet(time_t now, const DNSName& name, const sortedRecords_t& records, const vector<shared_ptr<const RRSIGRecordContent> >& signatures, const skeyset_t& keys, const OptLog& log, bool validateAllSigs=true);
bool isCoveredByNSEC(const DNSName& name, const DNSName& begin, const DNSName& next);
bool isCoveredByNSEC3Hash(const std::string& h, const std::string& beginHash, const std::string& nextHash);
bool isCoveredByNSEC3Hash(const DNSName& h, const DNSName& beginHash, const DNSName& nextHash);
cspmap_t harvestCSPFromRecs(const vector<DNSRecord>& recs);
bool getTrustAnchor(const map<DNSName,dsmap_t>& anchors, const DNSName& zone, dsmap_t &res);
bool haveNegativeTrustAnchor(const map<DNSName,std::string>& negAnchors, const DNSName& zone, std::string& reason);
vState validateDNSKeysAgainstDS(time_t now, const DNSName& zone, const dsmap_t& dsmap, const skeyset_t& tkeys, const sortedRecords_t& toSign, const vector<shared_ptr<const RRSIGRecordContent> >& sigs, skeyset_t& validkeys, const OptLog&);
dState getDenial(const cspmap_t &validrrsets, const DNSName& qname, const uint16_t qtype, bool referralToUnsigned, bool wantsNoDataProof, const OptLog& log = std::nullopt, bool needsWildcardProof=true, unsigned int wildcardLabelsCount=0);
bool isSupportedDS(const DSRecordContent& ds, const OptLog&);
DNSName getSigner(const std::vector<std::shared_ptr<const RRSIGRecordContent> >& signatures);
bool denialProvesNoDelegation(const DNSName& zone, const std::vector<DNSRecord>& dsrecords);
bool isRRSIGNotExpired(const time_t now, const RRSIGRecordContent& sig);
bool isRRSIGIncepted(const time_t now, const RRSIGRecordContent& sig);
bool isWildcardExpanded(unsigned int labelCount, const RRSIGRecordContent& sign);
bool isWildcardExpandedOntoItself(const DNSName& owner, unsigned int labelCount, const RRSIGRecordContent& sign);
void updateDNSSECValidationState(vState& state, const vState stateUpdate);

dState matchesNSEC(const DNSName& name, uint16_t qtype, const DNSName& nsecOwner, const NSECRecordContent& nsec, const std::vector<std::shared_ptr<const RRSIGRecordContent>>& signatures, const OptLog&);

bool isNSEC3AncestorDelegation(const DNSName& signer, const DNSName& owner, const NSEC3RecordContent& nsec3);
DNSName getNSECOwnerName(const DNSName& initialOwner, const std::vector<std::shared_ptr<const RRSIGRecordContent> >& signatures);
DNSName getClosestEncloserFromNSEC(const DNSName& name, const DNSName& owner, const DNSName& next);

template <typename NSEC> bool isTypeDenied(const NSEC& nsec, const QType& type)
{
  if (nsec.isSet(type.getCode())) {
    return false;
  }

  /* RFC 6840 section 4.3 */
  if (nsec.isSet(QType::CNAME)) {
    return false;
  }

  return true;
}
