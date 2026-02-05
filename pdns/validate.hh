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

extern uint32_t g_signatureInceptionSkew;
extern uint16_t g_maxNSEC3Iterations;
extern uint16_t g_maxRRSIGsPerRecordToConsider;
extern uint16_t g_maxNSEC3sPerRecordToConsider;
extern uint16_t g_maxDNSKEYsToConsider;
extern uint16_t g_maxDSsToConsider;

// 4033 5
enum class vState : uint8_t { Indeterminate, Insecure, Secure, NTA, TA, BogusNoValidDNSKEY, BogusInvalidDenial, BogusUnableToGetDSs, BogusUnableToGetDNSKEYs, BogusSelfSignedDS, BogusNoRRSIG, BogusNoValidRRSIG, BogusMissingNegativeIndication, BogusSignatureNotYetValid, BogusSignatureExpired, BogusUnsupportedDNSKEYAlgo, BogusUnsupportedDSDigestType, BogusNoZoneKeyBitSet, BogusRevokedDNSKEY, BogusInvalidDNSKEYProtocol };
const std::string& vStateToString(vState state);
inline bool vStateIsBogus(vState state)
{
  return state >= vState::BogusNoValidDNSKEY;
}

// NSEC(3) results
enum class dState : uint8_t { NODENIAL, INCONCLUSIVE, NXDOMAIN, NXQTYPE, ENT, INSECURE, OPTOUT};

std::ostream& operator<<(std::ostream &, vState);
std::ostream& operator<<(std::ostream &, dState);

struct ContentSigPair
{
  sortedRecords_t records;
  vector<shared_ptr<const RRSIGRecordContent>> signatures;
  // ponder adding a validate method that accepts a key
};
using cspmap_t = map<pair<DNSName, uint16_t>, ContentSigPair>;
using dsset_t = std::set<DSRecordContent>;

struct sharedDNSKeyRecordContentCompare
{
  bool operator() (const shared_ptr<const DNSKEYRecordContent>& lhs, const shared_ptr<const DNSKEYRecordContent>& rhs) const
  {
    return *lhs < *rhs;
  }
};

using skeyset_t = set<shared_ptr<const DNSKEYRecordContent>, sharedDNSKeyRecordContentCompare>;

namespace pdns::validation
{
using Nsec3HashesCache = std::map<std::tuple<DNSName, std::string, uint16_t>, std::string>;

struct ValidationContext
{
  Nsec3HashesCache d_nsec3Cache;
  unsigned int d_validationsCounter{0};
  unsigned int d_nsec3IterationsRemainingQuota{0};
  bool d_limitHit{false};
};

class TooManySEC3IterationsException : public std::runtime_error
{
public:
  TooManySEC3IterationsException(): std::runtime_error("Too many NSEC3 hash computations per query")
  {
  }
};

}

vState validateWithKeySet(time_t now, const DNSName& name, const sortedRecords_t& toSign, const vector<shared_ptr<const RRSIGRecordContent> >& signatures, const skeyset_t& keys, const OptLog& log, pdns::validation::ValidationContext& context, bool validateAllSigs=true);
bool isCoveredByNSEC(const DNSName& name, const DNSName& begin, const DNSName& next);
bool isCoveredByNSEC3Hash(const std::string& hash, const std::string& beginHash, const std::string& nextHash);
bool isCoveredByNSEC3Hash(const DNSName& name, const DNSName& beginHash, const DNSName& nextHash);
bool getTrustAnchor(const map<DNSName,dsset_t>& anchors, const DNSName& zone, dsset_t &res);
bool haveNegativeTrustAnchor(const map<DNSName,std::string>& negAnchors, const DNSName& zone, std::string& reason);
vState validateDNSKeysAgainstDS(time_t now, const DNSName& zone, const dsset_t& dsset, const skeyset_t& tkeys, const sortedRecords_t& toSign, const vector<shared_ptr<const RRSIGRecordContent> >& sigs, skeyset_t& validkeys, const OptLog&, pdns::validation::ValidationContext& context);
dState getDenial(const cspmap_t &validrrsets, const DNSName& qname, uint16_t qtype, bool referralToUnsigned, bool wantsNoDataProof, pdns::validation::ValidationContext& context, const OptLog& log = std::nullopt, bool needWildcardProof=true, unsigned int wildcardLabelsCount=0);
bool isSupportedDS(const DSRecordContent& dsRecordContent, const OptLog&);
DNSName getSigner(const std::vector<std::shared_ptr<const RRSIGRecordContent> >& signatures);
bool denialProvesNoDelegation(const DNSName& zone, const std::vector<DNSRecord>& dsrecords, pdns::validation::ValidationContext& context);
bool isRRSIGNotExpired(time_t now, const RRSIGRecordContent& sig);
bool isRRSIGIncepted(time_t now, const RRSIGRecordContent& sig);
bool isWildcardExpanded(unsigned int labelCount, const RRSIGRecordContent& sign);
bool isWildcardExpandedOntoItself(const DNSName& owner, unsigned int labelCount, const RRSIGRecordContent& sign);
void updateDNSSECValidationState(vState& state, vState stateUpdate);

dState matchesNSEC(const DNSName& name, uint16_t qtype, const DNSName& nsecOwner, const NSECRecordContent& nsec, const std::vector<std::shared_ptr<const RRSIGRecordContent>>& signatures, const OptLog&);

bool isNSEC3AncestorDelegation(const DNSName& signer, const DNSName& owner, const NSEC3RecordContent& nsec3);
DNSName getNSECOwnerName(const DNSName& initialOwner, const std::vector<std::shared_ptr<const RRSIGRecordContent> >& signatures);
DNSName getClosestEncloserFromNSEC(const DNSName& name, const DNSName& owner, const DNSName& next);
[[nodiscard]] uint64_t getNSEC3DenialProofWorstCaseIterationsCount(uint8_t maxLabels, uint16_t iterations, size_t saltLength);
[[nodiscard]] std::string getHashFromNSEC3(const DNSName& qname, uint16_t iterations, const std::string& salt, pdns::validation::ValidationContext& context);

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
