#include "zonemd.hh"

#include "dnsrecords.hh"
#include "dnssecinfra.hh"
#include "sha.hh"
#include "zoneparser-tng.hh"

typedef std::pair<DNSName, QType> rrSetKey_t;
typedef std::vector<std::shared_ptr<DNSRecordContent>> rrVector_t;

struct CanonrrSetKeyCompare: public std::binary_function<rrSetKey_t, rrSetKey_t, bool>
{
  bool operator()(const rrSetKey_t&a, const rrSetKey_t& b) const
  {
    // FIXME surely we can be smarter here
    if(a.first.canonCompare(b.first)) {
      return true;
    }
    if (b.first.canonCompare(a.first)) {
      return false;
    }
    return a.second < b.second;
  }
};

typedef std::map<rrSetKey_t, rrVector_t, CanonrrSetKeyCompare> RRsetMap_t;

RRsetMap_t RRsets;
std::map<rrSetKey_t, uint32_t> RRsetTTLs;

void pdns::zonemdVerify(const DNSName& zone, ZoneParserTNG &zpt, bool& validationDone, bool& validationOK)
{
  validationDone = false;
  validationOK = false;

  DNSResourceRecord dnsrr;
  std::map<std::pair<uint8_t, uint8_t>, std::shared_ptr<ZONEMDRecordContent>> zonemdRecords;
  std::shared_ptr<SOARecordContent> soarc;

  // Get all records and remember RRSets and TTLs
  while (zpt.get(dnsrr)) {
    if (!dnsrr.qname.isPartOf(zone) && dnsrr.qname != zone) {
      continue;
    }
    if (dnsrr.qtype == QType::SOA && soarc) {
      // XXX skip extra SOA?
      continue;
    }
    std::shared_ptr<DNSRecordContent> drc;
    try {
      drc = DNSRecordContent::mastermake(dnsrr.qtype, QClass::IN, dnsrr.content);
    }
    catch (const PDNSException& pe) {
      std::string err = "Bad record content in record for '" + dnsrr.qname.toStringNoDot() + "'|" + dnsrr.qtype.toString() + ": "+ pe.reason;
      throw PDNSException(err);
    }
    catch (const std::exception& e) {
      std::string err = "Bad record content in record for '" + dnsrr.qname.toStringNoDot() + "|" + dnsrr.qtype.toString() + "': " + e.what();
      throw PDNSException(err);
    }
    if (dnsrr.qtype == QType::SOA && dnsrr.qname == zone) {
      soarc = std::dynamic_pointer_cast<SOARecordContent>(drc);
    }
    if (dnsrr.qtype == QType::ZONEMD && dnsrr.qname == zone) {
      auto zonemd = std::dynamic_pointer_cast<ZONEMDRecordContent>(drc);
      auto inserted = zonemdRecords.insert(pair(pair(zonemd->d_scheme, zonemd->d_hashalgo), zonemd)).second;
      if (!inserted) {
        throw PDNSException("Duplicate ZONEMD record");
      }
    }
    rrSetKey_t key = std::pair(dnsrr.qname, dnsrr.qtype);
    RRsets[key].push_back(drc);
    RRsetTTLs[key] = dnsrr.ttl;
  }

  // Determine which digests to compute based on accepted zonemd records present
  unique_ptr<pdns::SHADigest> sha384digest{nullptr}, sha512digest{nullptr};

  for (const auto& [k, zonemd] : zonemdRecords) {
    if (zonemd->d_serial != soarc->d_st.serial) {
      // The SOA Serial field MUST exactly match the ZONEMD Serial
      // field. If the fields do not match, digest verification MUST
      // NOT be considered successful with this ZONEMD RR.
      continue;
    }
    if (zonemd->d_scheme != 1) {
      // The Scheme field MUST be checked. If the verifier does not
      // support the given scheme, verification MUST NOT be considered
      // successful with this ZONEMD RR.
      continue;
    }
    // The Hash Algorithm field MUST be checked. If the verifier does
    // not support the given hash algorithm, verification MUST NOT be
    // considered successful with this ZONEMD RR.
    if (zonemd->d_hashalgo == 1) {
      sha384digest = make_unique<pdns::SHADigest>(384);
    }
    else if (zonemd->d_hashalgo == 2) {
      sha512digest = make_unique<pdns::SHADigest>(512);
    }
  }

  // A little helper
  auto hash = [&sha384digest, &sha512digest](const std::string& msg) {
    if (sha384digest) {
      sha384digest->process(msg, msg.size());
    }
    if (sha512digest) {
      sha512digest->process(msg, msg.size());
    }
  };

  // Compute requested digests
  for (auto& rrset: RRsets) {
    const auto& qname = rrset.first.first;
    const auto& qtype = rrset.first.second;
    if (qtype == QType::ZONEMD && qname == zone) {
      continue; // the apex ZONEMD is not digested
    }

    sortedRecords_t sorted;
    for (auto& rr: rrset.second) {
      if (qtype == QType::RRSIG) {
        const auto rrsig = std::dynamic_pointer_cast<RRSIGRecordContent>(rr);
        if (rrsig->d_type == QType::ZONEMD && qname == zone) {
          continue;
        }
      }
      sorted.insert(rr);
    }

    if (qtype != QType::RRSIG) {
      RRSIGRecordContent rrc;
      rrc.d_originalttl = RRsetTTLs[rrset.first];
      rrc.d_type = qtype;
      auto msg = getMessageForRRSET(qname, rrc, sorted, false, false);
      hash(msg);
    } else {
      // RRSIG is special, since  original TTL depends on qtype covered by RRSIG
      // which can be different per record
      for (const auto& rrsig : sorted) {
        auto rrsigc = std::dynamic_pointer_cast<RRSIGRecordContent>(rrsig);
        RRSIGRecordContent rrc;
        rrc.d_originalttl = RRsetTTLs[pair(rrset.first.first, rrsigc->d_type)];
        rrc.d_type = qtype;
        auto msg = getMessageForRRSET(qname, rrc, { rrsigc }, false, false);
        hash(msg);
      }
    }
  }

  // Final verify
  for (const auto& [k, zonemd] : zonemdRecords) {
    if (zonemd->d_serial != soarc->d_st.serial) {
      // The SOA Serial field MUST exactly match the ZONEMD Serial
      // field. If the fields do not match, digest verification MUST
      // NOT be considered successful with this ZONEMD RR.
      continue;
    }
    if (zonemd->d_scheme != 1) {
      // The Scheme field MUST be checked. If the verifier does not
      // support the given scheme, verification MUST NOT be considered
      // successful with this ZONEMD RR.
      continue;
    }
    // The Hash Algorithm field MUST be checked. If the verifier does
    // not support the given hash algorithm, verification MUST NOT be
    // considered successful with this ZONEMD RR.
    if (zonemd->d_hashalgo == 1) {
      validationDone = true;
      if (constantTimeStringEquals(zonemd->d_digest, sha384digest->digest())) {
        validationOK = true;
        break; // Per RFC: a single succeeding validation is enough
      }
    }
    else if (zonemd->d_hashalgo == 2) {
      validationDone = true;
      if (constantTimeStringEquals(zonemd->d_digest, sha512digest->digest())) {
        validationOK = true;
        break; // Per RFC: a single succeeding validation is enough
      }
    }
  }
}
