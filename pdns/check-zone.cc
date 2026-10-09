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

#include "dns.hh"
#include "dnsrecords.hh"
#include "dnsseckeeper.hh"
#include "ueberbackend.hh"

#include "check-zone.hh"

namespace Check
{

bool validateViewName(std::string_view name, std::string& error)
{
  if (name.empty()) {
    error = "Empty view names are not allowed";
    return false;
  }

  if (auto pos = name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 _-."); pos != std::string_view::npos) {
    error = std::string("View name contains forbidden character '") + name[pos] + "' at position " + std::to_string(pos);
    return false;
  }

  if (name[0] == '.') {
    error = "View names are not allowed to start with a dot";
    return false;
  }

  if (name[0] == ' ') {
    error = "View names are not allowed to start with a space";
    return false;
  }

  return true;
}

void checkRRSet(const std::vector<DNSResourceRecord>& oldrrs, std::vector<DNSResourceRecord>& newrrs, const ZoneName& zone, RRSetFlags flags, std::vector<diag>& diagnostics)
{
  // QTypes that MUST NOT have multiple records of the same type in a given RRset.
  static const std::set<uint16_t> onlyOneEntryTypes = {QType::CNAME, QType::DNAME, QType::SOA};
  // QTypes that MUST be at apex.
  static const std::set<uint16_t> atApexTypes = {QType::SOA, QType::DNSKEY};
  // QTypes that are NOT allowed at apex.
  static const std::set<uint16_t> nonApexTypes = {QType::DS};

  sort(newrrs.begin(), newrrs.end(),
       [](const DNSResourceRecord& rec_a, const DNSResourceRecord& rec_b) -> bool {
         /* we need _strict_ weak ordering */
         return std::tie(rec_a.qname, rec_a.qtype, rec_a.content) < std::tie(rec_b.qname, rec_b.qtype, rec_b.content);
       });

  DNSResourceRecord previous;
  for (const auto& rec : newrrs) {
    bool lowercase{false};
    switch (rec.qtype) {
    case QType::MX:
    case QType::PTR:
    case QType::SRV:
      lowercase = true;
      break;
    }
    std::string contentstr{rec.content};
    if (lowercase) {
      toLowerInPlace(contentstr);
    }
    if (previous.qname == rec.qname) {
      if (previous.qtype == rec.qtype) {
        if (onlyOneEntryTypes.count(rec.qtype.getCode()) != 0) {
          diagnostics.emplace_back(std::make_tuple(Logr::Error, rec.qname, rec.qtype, "only one such record allowed"));
        }
        if (previous.content == contentstr) {
          diagnostics.emplace_back(std::make_tuple(Logr::Error, rec.qname, rec.qtype, std::string{"duplicate record with content \""} + rec.content + "\""));
        }
        // Enforce identical TTLs for all records with the same name and type,
        // if required. This is optional because some callers are able to
        // compute [newrrs] in a way which already enforces this, and therefore
        // it is useless to check a second time.
        if ((flags & RRSET_CHECK_TTL) != 0) {
          if (rec.ttl != previous.ttl) {
            // This error message may be misleading if a TTL discrepancy already
            // exists in the RRset, as it might blame an existing record rather
            // than those being added. ¯\_(ツ)_/¯
            diagnostics.emplace_back(std::make_tuple(Logr::Error, rec.qname, rec.qtype, std::string{"uses a different TTL value than the remainder of the RRset"}));
          }
        }
      }
      else {
        if (QType::exclusiveEntryTypes.count(rec.qtype.getCode()) != 0
            || QType::exclusiveEntryTypes.count(previous.qtype.getCode()) != 0) {
          // The `rec' record can't be added because of `previous'. However
          // `rec' might be one of the existing records, and `previous' the
          // added one. Or they might both be new records.
          // We thus check if `rec' appears in the existing records in
          // order to decide which record to blame in order to make the error
          // message as less confusing as possible.
          if (std::find(oldrrs.begin(), oldrrs.end(), rec) != oldrrs.end()) {
            diagnostics.emplace_back(std::make_tuple(Logr::Error, previous.qname, previous.qtype, std::string{"conflicts with existing "} + rec.qtype.toString() + " RRset of the same name"));
          }
          else {
            diagnostics.emplace_back(std::make_tuple(Logr::Error, rec.qname, rec.qtype, std::string{"conflicts with existing "} + previous.qtype.toString() + " RRset of the same name"));
          }
        }
      }
    }

    if (rec.qname == zone.operator const DNSName&()) {
      if (nonApexTypes.count(rec.qtype.getCode()) != 0) {
        diagnostics.emplace_back(std::make_tuple(Logr::Warning, rec.qname, rec.qtype, "is not allowed at apex"));
      }
    }
    else if (atApexTypes.count(rec.qtype.getCode()) != 0) {
      diagnostics.emplace_back(std::make_tuple(rec.qtype == QType::SOA ? Logr::Error : Logr::Warning, rec.qname, rec.qtype, "is only allowed at apex"));
    }

    // Check if the DNSNames that should be hostnames, are hostnames
    bool allowUnderscores = (flags & RRSET_ALLOW_UNDERSCORES) != 0;
    try {
      checkHostnameCorrectness(rec, allowUnderscores);
    }
    catch (const std::exception& e) {
      diagnostics.emplace_back(std::make_tuple(Logr::Warning, rec.qname, rec.qtype, e.what()));
    }

    previous = rec;
    if (lowercase) {
      previous.content = contentstr;
    }
  }
}

static void checkZoneTLSA(const set<DNSName>& tlsas, const set<DNSName>& cnames, const set<DNSName>& noncnames, std::vector<diag>& diagnostics)
{
  for (const auto& origname : tlsas) {
    auto name = origname;
    name.trimToLabels(name.countLabels() - 2);
    if (cnames.find(name) == cnames.end() && noncnames.find(name) == noncnames.end()) {
      // No specific record for the name in the TLSA record exists, this
      // is already worth emitting a warning. Let's see if a wildcard exist.
      cout << "[Warning] ";
      DNSName wcname(name);
      wcname.chopOff();
      wcname.prependRawLabel("*");
      std::string message{"querying that name will always yield an empty response, because "};
      if (cnames.find(wcname) != cnames.end() || noncnames.find(wcname) != noncnames.end()) {
        message += "a wildcard record exists for '" + wcname.toString() + "' and ";
      }
      message += std::string("a TLSA record exists for '") + origname.toString() + "'";
      diagnostics.emplace_back(std::make_tuple(Logr::Warning, name, QType::TLSA, message));
    }
  }
}

// Record name, prio, target name, ipv4hint=auto, ipv6hint=auto
using svcbset_t = set<std::tuple<DNSName, uint16_t, DNSName, bool, bool>>;

static void checkZoneSVCB(QType type, const ZoneName& zone, const svcbset_t& targets, const set<DNSName>& aliases, const set<DNSName>& records, const set<DNSName>& arecords, const set<DNSName>& aaaarecords, const set<DNSName>& addresses, std::vector<diag>& diagnostics)
{
  for (const auto& [name, prio, target, v4hintsAuto, v6hintsAuto] : targets) {
    if (name == target) {
      diagnostics.emplace_back(std::make_tuple(Logr::Error, name, type, "has itself as target"));
    }

    if (prio == 0) {
      if (target.isPartOf(zone)) {
        if (aliases.find(target) != aliases.end()) {
          diagnostics.emplace_back(std::make_tuple(Logr::Warning, name, type, std::string("has an aliasform target (") + target.toString() + ") this is in aliasform itself"));
        }
        if (addresses.find(target) == addresses.end() && records.find(target) == records.end()) {
          diagnostics.emplace_back(std::make_tuple(Logr::Error, name, type, std::string("has a target ") + target.toString() + " that has neither address nor " + type.toString() + " records"));
        }
      }
    }

    const auto& trueTarget = target.isRoot() ? name : target;
    if (prio > 0) {
      if (v4hintsAuto && arecords.find(trueTarget) == arecords.end()) {
        diagnostics.emplace_back(std::make_tuple(Logr::Warning, name, type, std::string("has automatic IPv4 hints, but no A record for the target at ") + trueTarget.toString() + " exists"));
      }
      if (v6hintsAuto && aaaarecords.find(trueTarget) == aaaarecords.end()) {
        diagnostics.emplace_back(std::make_tuple(Logr::Warning, name, type, std::string("has automatic IPv6 hints, but no AAAA record for the target at ") + trueTarget.toString() + " exists"));
      }
    }
  }
}

static void normalizeSOARecord(DNSResourceRecord& drr, std::vector<diag>& diagnostics)
{
  vector<string> parts;
  stringtok(parts, drr.content);

  if (parts.size() < 7) {
    diagnostics.emplace_back(std::make_tuple(Logr::Info, drr.qname, drr.qtype, "SOA autocomplete is deprecated, missing field(s) in SOA content"));
  }

  if (parts.size() >= 2) {
    if (parts[1].find('@') != string::npos) {
      diagnostics.emplace_back(std::make_tuple(Logr::Warning, drr.qname, drr.qtype, "found @-sign in SOA RNAME, should probably be a dot (.)"));
    }
  }

  ostringstream ostr;
  ostr << drr.content;
  for (auto pleft = parts.size(); pleft < 7; ++pleft) {
    ostr << " 0";
  }
  drr.content = ostr.str();
}

static bool checkRecordContents(DNSResourceRecord& drr, std::vector<diag>& diagnostics)
{
  // Make sure TXT record contents are quoted
  if (drr.qtype.getCode() == QType::TXT && !drr.content.empty() && drr.content[0] != '"') {
    drr.content = "\"" + drr.content + "\"";
  }

  try {
    shared_ptr<DNSRecordContent> drc(DNSRecordContent::make(drr.qtype.getCode(), QClass::IN, drr.content));
    string tmp = drc->serialize(drr.qname);
    tmp = drc->getZoneRepresentation(true);
    if (drr.qtype.getCode() != QType::AAAA) {
      if (!pdns_iequals(tmp, drr.content)) {
        if (drr.qtype.getCode() == QType::SOA) {
          tmp = drc->getZoneRepresentation(false);
        }
        if (!pdns_iequals(tmp, drr.content)) {
          diagnostics.emplace_back(std::make_tuple(Logr::Warning, drr.qname, drr.qtype, std::string("parsed record contents (" + tmp + ") do not match original content (" + drr.content + ")")));
        }
      }
    }
    else {
      struct in6_addr tmpbuf{};
      if (inet_pton(AF_INET6, drr.content.c_str(), &tmpbuf) != 1) {
        diagnostics.emplace_back(std::make_tuple(Logr::Warning, drr.qname, drr.qtype, std::string("not a valid IPv6 address: ") + drr.content));
      }
    }
    return true;
  }
  catch (std::exception& e) {
    diagnostics.emplace_back(std::make_tuple(Logr::Error, drr.qname, drr.qtype, std::string("error processing record: ") + e.what()));
    return false;
  }
}

static void checkNSEC3Params(Logr::log_t slog, UeberBackend& ueber, DNSSECKeeper& dsk, NSEC3PARAMRecordContent& ns3pr, bool haveNSEC3, bool isSecure, const ZoneName& zone, std::vector<diag>& diagnostics)
{
  std::vector<std::string> checkKeyErrors;
  bool validKeys = dsk.checkKeys(zone, checkKeyErrors);

  if (haveNSEC3) {
    auto wirelength = zone.operator const DNSName&().wirelength();
    if (isSecure && wirelength > 222) {
      diagnostics.emplace_back(std::make_tuple(Logr::Error, zone.operator const DNSName&(), QType::SOA, std::string("zone has NSEC3 semantics but its name is too long to have the hash prepended (") + std::to_string(wirelength) + " bytes long, whereas the maximum is 222 bytes)"));
    }

    if (ns3pr.d_iterations > 0) {
      diagnostics.emplace_back(std::make_tuple(Logr::Warning, zone.operator const DNSName&(), QType::SOA, std::string("zone has ") + std::to_string(ns3pr.d_iterations) + " iterations configured for its NSEC3 parameter, 0 is the recommended value in RFC 9276"));
    }

    if (!ns3pr.d_salt.empty()) {
      diagnostics.emplace_back(std::make_tuple(Logr::Warning, zone.operator const DNSName&(), QType::SOA, "zone has a salt configured for its NSEC3 parameter, no salt ('-') is the recommended value in RFC 9276"));
    }

    vector<DNSBackend::KeyData> dbkeyset;
    ueber.getDomainKeys(zone, dbkeyset);

    for (DNSBackend::KeyData& keydata : dbkeyset) {
      DNSKEYRecordContent dkrc;
      DNSCryptoKeyEngine::makeFromISCString(slog, dkrc, keydata.content);

      if (dkrc.d_algorithm == DNSSECKeeper::RSASHA1) {
        diagnostics.emplace_back(std::make_tuple(Logr::Error, zone.operator const DNSName&(), QType::SOA, std::string("zone has NSEC3 semantics, but the ") + (keydata.active ? "active" : "inactive") + " key with id " + std::to_string(keydata.id) + " has 'Algorithm: 5'. This should be corrected to 'Algorithm: 7' in the database, or NSEC3 should be disabled"));
      }
    }
  }

  if (!validKeys) {
    diagnostics.emplace_back(std::make_tuple(Logr::Error, zone.operator const DNSName&(), QType::SOA, "zone has at least one invalid DNS Private Key"));
    for (const auto& msg : checkKeyErrors) {
      diagnostics.emplace_back(std::make_tuple(Logr::Error, zone.operator const DNSName&(), QType::SOA, msg));
    }
  }
}

static void checkParentDelegation(UeberBackend& ueber, const ZoneName& zone, std::vector<diag>& diagnostics)
{
  ZoneName parent(zone);
  while (parent.chopOff()) {
    SOAData sd_p;
    if (ueber.getSOAUncached(parent, sd_p)) {
      bool seen_ns = false;
      DNSZoneRecord dzr;
      ueber.lookup(QType(QType::ANY), zone.operator const DNSName&(), sd_p.domain_id);
      while (ueber.get(dzr)) {
        if (dzr.dr.d_type == QType::NS) {
          seen_ns = true;
          ueber.lookupEnd();
          break;
        }
      }
      if (!seen_ns) {
        diagnostics.emplace_back(std::make_tuple(Logr::Error, zone.operator const DNSName&(), QType::SOA, std::string("no delegation in parent zone '") + parent.toString() + "'"));
      }
      break;
    }
  }
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static void checkZoneRecords(std::vector<DNSResourceRecord>& records, const ZoneName& zone, DomainInfo::DomainKind kind, RRSetFlags flags, bool isExistingZone, bool canDoDNSSEC, bool presigned, bool isSecure, bool isOptOut, std::vector<diag>& diagnostics)
{
  uint32_t minimumTTL{0};
  bool hasNsAtApex = false;
  std::set<std::pair<DNSName, QType>> checkOcclusion;
  {
    std::vector<DNSResourceRecord> checkCNAME;
    std::set<DNSName> cnames;
    {
      std::set<DNSName> glue;
      std::set<DNSName> checkglue;
      {
        std::set<DNSName> arecords;
        std::set<DNSName> aaaarecords;
        std::set<DNSName> addresses;
        {
          std::set<DNSName> httpsAliases;
          std::set<DNSName> httpsRecords;
          svcbset_t httpsTargets;
          {
            std::set<DNSName> svcbAliases;
            std::set<DNSName> svcbRecords;
            svcbset_t svcbTargets;
            {
              std::set<DNSName> tlsas;
              std::set<DNSName> noncnames;

              for (auto& drr : records) { // We modify SOA and TXT record contents
                if (drr.qtype.getCode() == QType::TLSA) {
                  tlsas.insert(drr.qname);
                }
                if (drr.qtype.getCode() == QType::A || drr.qtype.getCode() == QType::AAAA) {
                  addresses.insert(drr.qname);
                }
#ifdef HAVE_LUA_RECORDS
                if (drr.qtype.getCode() == QType::LUA) {
                  shared_ptr<DNSRecordContent> drc(DNSRecordContent::make(drr.qtype.getCode(), QClass::IN, drr.content));
                  auto luarec = std::dynamic_pointer_cast<LUARecordContent>(drc);
                  QType qtype = luarec->d_type;
                  if (qtype == QType::A || qtype == QType::AAAA) {
                    addresses.insert(drr.qname);
                  }
                }
#endif
                if (drr.qtype.getCode() == QType::A) {
                  arecords.insert(drr.qname);
                }
                if (drr.qtype.getCode() == QType::AAAA) {
                  aaaarecords.insert(drr.qname);
                }
                if (drr.qtype.getCode() == QType::SOA) {
                  normalizeSOARecord(drr, diagnostics); // updates record
                  // If there are extra (bogus) SOA records, picking the TTL from the last
                  // seen might be wrong, but's a minor problem compared to the existence
                  // of spurious SOA records...
                  if (minimumTTL == 0) {
                    try {
                      SOAData soadata;
                      fillSOAData(drr.content, soadata);
                      minimumTTL = soadata.minimum;
                    }
                    catch (const PDNSException&) {
                      // ignored
                    }
                  }
                }

                if (!checkRecordContents(drr, diagnostics)) {
                  continue;
                }

                if (!drr.qname.isPartOf(zone)) {
                  diagnostics.emplace_back(std::make_tuple(Logr::Error, drr.qname, drr.qtype, "out-of-zone record"));
                  continue;
                }

                if (drr.qtype.getCode() == QType::SVCB || drr.qtype.getCode() == QType::HTTPS) {
                  shared_ptr<DNSRecordContent> drc(DNSRecordContent::make(drr.qtype.getCode(), QClass::IN, drr.content));
                  // I, too, like to live dangerously
                  auto svcbrc = std::dynamic_pointer_cast<SVCBBaseRecordContent>(drc);
                  if (svcbrc->getPriority() == 0 && svcbrc->hasParams()) {
                    diagnostics.emplace_back(std::make_tuple(Logr::Warning, drr.qname, drr.qtype, "aliasform has service parameters"));
                  }

                  if (svcbrc->getPriority() != 0) {
                    // Service Form
                    if (svcbrc->hasParam(SvcParam::no_default_alpn) && !svcbrc->hasParam(SvcParam::alpn)) {
                      /* draft-ietf-dnsop-svcb-https-03 section 6.1
                       *  When "no-default-alpn" is specified in an RR, "alpn" must
                       *  also be specified in order for the RR to be "self-consistent"
                       *  (Section 2.4.3).
                       */
                      diagnostics.emplace_back(std::make_tuple(Logr::Warning, drr.qname, drr.qtype, "not self-consistent due to 'no-default-alpn' parameter without 'alpn' parameter"));
                    }
                    if (svcbrc->hasParam(SvcParam::mandatory)) {
                      auto keys = svcbrc->getParam(SvcParam::mandatory).getMandatory();
                      for (auto const& key : keys) {
                        if (!svcbrc->hasParam(key)) {
                          diagnostics.emplace_back(std::make_tuple(Logr::Warning, drr.qname, drr.qtype, std::string("not self-consistent due to missing '") + SvcParam::keyToString(key) + "' parameter listed in 'mandatory'"));
                        }
                      }
                    }
                  }

                  bool isSvcb = drr.qtype.getCode() == QType::SVCB;
                  set<DNSName>& aliases = isSvcb ? svcbAliases : httpsAliases;
                  svcbset_t& targets = isSvcb ? svcbTargets : httpsTargets;
                  set<DNSName>& ourrecords = isSvcb ? svcbRecords : httpsRecords;

                  if (svcbrc->getPriority() == 0) {
                    if (aliases.find(drr.qname) != aliases.end()) {
                      diagnostics.emplace_back(std::make_tuple(Logr::Warning, drr.qname, drr.qtype, "more than one aliasform to this name"));
                    }
                    aliases.insert(drr.qname);
                  }
                  targets.emplace(drr.qname, svcbrc->getPriority(), svcbrc->getTarget(), svcbrc->autoHint(SvcParam::ipv4hint), svcbrc->autoHint(SvcParam::ipv6hint));
                  ourrecords.insert(drr.qname);
                }

                if (isSecure && isOptOut && (drr.qname.hasLabels() && drr.qname.getRawLabel(0) == "*")) {
                  diagnostics.emplace_back(std::make_tuple(Logr::Warning, drr.qname, drr.qtype, "wildcard records in opt-out zones are insecure, consider disabling the opt-out flag for this zone to avoid this warning"));
                }

                if (drr.qname == zone.operator const DNSName&()) {
                  // apex checks
                  if (drr.qtype.getCode() == QType::NS) {
                    hasNsAtApex = true;
                  }
                }
                else {
                  // non-apex checks
                  if (drr.qtype.getCode() == QType::NS) {
                    if (DNSName(drr.content).isPartOf(drr.qname)) {
                      checkglue.insert(DNSName(toLower(drr.content)));
                    }
                    checkOcclusion.insert({drr.qname, drr.qtype});
                  }
                  else if (drr.qtype.getCode() == QType::A || drr.qtype.getCode() == QType::AAAA) {
                    glue.insert(drr.qname);
                  }
                }

                // DNAMEs can occur both at the apex and below it
                if (drr.qtype == QType::DNAME) {
                  checkOcclusion.insert({drr.qname, drr.qtype});
                }

                if ((drr.qtype.getCode() == QType::A || drr.qtype.getCode() == QType::AAAA) && !drr.qname.isWildcard() && !drr.qname.isHostname()) {
                  diagnostics.emplace_back(std::make_tuple(Logr::Info, drr.qname, drr.qtype, "not a valid hostname"));
                }

                if (drr.qtype.getCode() == QType::CNAME) {
                  if (cnames.count(drr.qname) == 0) {
                    cnames.insert(drr.qname);
                  }
                }
                else {
                  if (drr.qtype.getCode() == QType::RRSIG) {
                    if (!presigned) {
                      diagnostics.emplace_back(std::make_tuple(Logr::Error, drr.qname, drr.qtype, "RRSIG in non-presigned zone do not belong in the database"));
                      continue;
                    }
                  }
                  else {
                    noncnames.insert(drr.qname);
                  }
                }

                if (drr.qtype == QType::MX || drr.qtype == QType::NS || drr.qtype == QType::SRV) {
                  checkCNAME.push_back(drr);
                }

                if (drr.qtype.getCode() == QType::NSEC || drr.qtype.getCode() == QType::NSEC3) {
                  diagnostics.emplace_back(std::make_tuple(Logr::Error, drr.qname, drr.qtype, "NSEC or NSEC3 records do not belong in the database"));
                  continue;
                }

                if (!presigned && drr.qtype.getCode() == QType::DNSKEY) {
                  if (::arg().mustDo("direct-dnskey")) {
                    if (drr.ttl != minimumTTL) {
                      diagnostics.emplace_back(std::make_tuple(Logr::Warning, drr.qname, drr.qtype, std::string("DNSKEY TTL of ") + std::to_string(drr.ttl) + " differs from SOA minimum of " + std::to_string(minimumTTL)));
                    }
                  }
                  else {
                    diagnostics.emplace_back(std::make_tuple(Logr::Warning, drr.qname, drr.qtype, "DNSKEY in non-presigned zone will mostly be ignored and can cause problems"));
                  }
                }
              } // end of complete records loop

              for (const auto& name : cnames) {
                if (noncnames.find(name) != noncnames.end()) {
                  diagnostics.emplace_back(std::make_tuple(Logr::Error, name, QType::CNAME, "other non-CNAME records with same label exist"));
                }
              }

              checkZoneTLSA(tlsas, cnames, noncnames, diagnostics);
            } // end of scope for tlsas and noncnames

            checkZoneSVCB(QType::SVCB, zone, svcbTargets, svcbAliases, svcbRecords, arecords, aaaarecords, addresses, diagnostics);
          } // end of scope for svcbTargets, svcbAliases and svcbRecords
          checkZoneSVCB(QType::HTTPS, zone, httpsTargets, httpsAliases, httpsRecords, arecords, aaaarecords, addresses, diagnostics);
        } // end of scope for httpsTargets, httpsAliases and httpsRecords

      } // end of scope for arecords, aaaarecords and addresses

      checkRRSet({}, records, zone, flags, diagnostics);

      bool isCatalogType = (kind == DomainInfo::Producer || kind == DomainInfo::Consumer);
      bool isSecondaryType = (kind == DomainInfo::Secondary || kind == DomainInfo::Consumer);
      if (!hasNsAtApex && !(isSecondaryType || isCatalogType)) {
        diagnostics.emplace_back(std::make_tuple(Logr::Error, zone.operator const DNSName&(), QType::SOA, "no NS record at zone apex"));
      }

      for (const auto& qname : checkglue) {
        if (glue.count(qname) == 0) {
          diagnostics.emplace_back(std::make_tuple(Logr::Warning, qname, QType::NS, "missing glue"));
        }
      }

    } // end of scope for glue and checkglue

    for (const auto& qname : checkOcclusion) {
      for (const auto& drr : records) {
        // a name does not occlude itself in the following situations:
        if (qname.first == drr.qname) {
          // NS does not occlude
          if (qname.second == QType::NS) {
            // ... DS or NS
            if (drr.qtype == QType::NS || drr.qtype == QType::DS) {
              continue;
            }
            // ... presigned if RRSIG is for DS or NSEC
            if (presigned && drr.qtype == QType::RRSIG) {
              shared_ptr<DNSRecordContent> drc(DNSRecordContent::make(drr.qtype.getCode(), QClass::IN, drr.content));
              auto rrsig = std::dynamic_pointer_cast<RRSIGRecordContent>(drc);
              QType qtype = rrsig->d_type;
              if (qtype == QType::DS || qtype == QType::NSEC) {
                continue;
              }
            }
          }
          // a DNAME does not occlude itself
          if (qname.second == QType::DNAME && drr.qtype == QType::DNAME) {
            continue;
          }
        }

        // for most types, X occludes X and (type-dependent) almost everything under X
        if (drr.qname.isPartOf(qname.first)) {

          // but a DNAME does not occlude anything at its name, only the things under it
          if (qname.second == QType::DNAME && drr.qname == qname.first) {
            continue;
          }

          // the record under inspection is:
          // occluded by a DNAME, or
          // occluded by a delegation, and is not glue or ENTs leading towards that glue
          if (qname.second == QType::DNAME || (drr.qtype != QType::ENT && drr.qtype.getCode() != QType::A && drr.qtype.getCode() != QType::AAAA)) {
            diagnostics.emplace_back(std::make_tuple(Logr::Warning, drr.qname, drr.qtype, std::string("is occluded by a ") + (qname.second == QType::NS ? "delegation" : "DNAME") + " at '" + qname.first.toString() + "'"));
          }
        }
      }
    }

    for (auto const& rec : checkCNAME) {
      DNSName target;
      shared_ptr<DNSRecordContent> drc(DNSRecordContent::make(rec.qtype.getCode(), QClass::IN, rec.content));
      switch (rec.qtype) {
      case QType::MX:
        target = std::dynamic_pointer_cast<MXRecordContent>(drc)->d_mxname;
        break;
      case QType::SRV:
        target = std::dynamic_pointer_cast<SRVRecordContent>(drc)->d_target;
        break;
      case QType::NS:
        target = std::dynamic_pointer_cast<NSRecordContent>(drc)->getNS();
        break;
      default:
        // can't happen due to the way checkCNAME is filled
        break;
      }
      if (target.isPartOf(zone) && cnames.count(target) != 0) {
        diagnostics.emplace_back(std::make_tuple(Logr::Warning, rec.qname, rec.qtype, std::string("has a target (") + target.toString() + ") that is a CNAME"));
      }
    }

  } // end of scope for checkCNAME and cnames

  for (const auto& rec : records) {
    bool report = !rec.auth;
    bool ds_ns = false;
    bool done = !canDoDNSSEC;
    for (const auto& qname : checkOcclusion) {
      if (qname.second == QType::NS) {
        if (qname.first == rec.qname) {
          ds_ns = true;
        }
        if (done) {
          continue;
        }
        if (!rec.auth) {
          if (rec.qname.isPartOf(qname.first) && (qname.first != rec.qname || rec.qtype != QType::DS)) {
            report = false;
            done = true;
          }
          if (rec.qtype == QType::ENT && qname.first.isPartOf(rec.qname)) {
            report = false;
            done = true;
          }
        }
        else if ((flags & RRSET_IGNORE_MISSING_ENT) == 0 && rec.qname.isPartOf(qname.first) && ((qname.first != rec.qname || rec.qtype != QType::DS) || rec.qtype == QType::NS)) {
          // Note that record is authoritative, but occluded.
          // TODO: This probably should have been caught by the first round of
          // occlusion checks, check if this is redundant. (Added in #6653)
          report = true;
          done = true;
        }
      }
    }
    if (!ds_ns && rec.qtype.getCode() == QType::DS && rec.qname != zone.operator const DNSName&()) {
      diagnostics.emplace_back(std::make_tuple(Logr::Warning, rec.qname, rec.qtype, "DS record without a delegation"));
    }
    // Make sure we don't suggest rectifying the zone unless it exists.
    if (report && isExistingZone) {
      if (rec.auth) {
        diagnostics.emplace_back(std::make_tuple(Logr::Error, rec.qname, rec.qtype, "occluded until empty non-terminals are added, consider rectifying zone"));
      }
      else {
        diagnostics.emplace_back(std::make_tuple(Logr::Error, rec.qname, rec.qtype, "not authoritative, consider rectifying zone"));
      }
    }
  }
}

void checkZoneMetadata(const ZoneName& zone, std::vector<diag>& diagnostics)
{
  UeberBackend ueber;
  std::map<std::string, std::vector<std::string>> metadatas;
  if (ueber.getAllDomainMetadata(zone, metadatas)) {
    for (const auto& metadata : metadatas) {
      std::set<std::string> seen;
      std::set<std::string> messaged;

      for (const auto& value : metadata.second) {
        if (seen.count(value) == 0) {
          seen.insert(value);
        }
        else if (messaged.count(value) == 0) {
          diagnostics.emplace_back(std::make_tuple(Logr::Error, zone.operator const DNSName&(), QType::SOA, std::string("duplicate metadata key value pair with key '") + metadata.first + "' and value '" + value + "'"));
          messaged.insert(value);
        }
      }
    }
  }
}

void checkZone(Logr::log_t slog, std::vector<DNSResourceRecord>& allrrs, const ZoneName& zone, DomainInfo::DomainKind kind, RRSetFlags flags, std::vector<diag>& diagnostics)
{
  UeberBackend ueber;
  DNSSECKeeper dsk(slog, &ueber);
  DomainInfo info;
  bool isDomainInfoValid{false};
  bool canDoDNSSEC{false};

  // Get zone information from the backend.
  // If no zone information is available (e.g. because the zone is being
  // checked prior to its creation), then we'll skip all the DNSSEC-related
  // processing as the zone is not signed yet.
  try {
    isDomainInfoValid = ueber.getDomainInfo(zone, info, false);
    if (isDomainInfoValid) {
      canDoDNSSEC = info.backend->doesDNSSEC();
      kind = info.kind;
    }
  }
  catch (const PDNSException& e) {
    diagnostics.emplace_back(std::make_tuple(Logr::Error, zone.operator const DNSName&(), QType::SOA, std::string("error attempting to get zone information from the backend: ") + e.reason));
  }

  NSEC3PARAMRecordContent ns3pr;
  bool haveNSEC3{false};
  bool narrow{false};
  bool isOptOut{false};
  bool isSecure{false};
  bool presigned{false};

  if (isDomainInfoValid) {
    narrow = false;
    haveNSEC3 = dsk.getNSEC3PARAM(zone, &ns3pr, &narrow);
    isOptOut = (haveNSEC3 && ns3pr.d_flags != 0);
    isSecure = dsk.isSecuredZone(zone);
    presigned = dsk.isPresigned(zone);

    checkNSEC3Params(slog, ueber, dsk, ns3pr, haveNSEC3, isSecure, zone, diagnostics);
  }

  // Check for delegation in the parent zone
  checkParentDelegation(ueber, zone, diagnostics);

  // Check records
  checkZoneRecords(allrrs, zone, kind, flags, isDomainInfoValid, canDoDNSSEC, presigned, isSecure, isOptOut, diagnostics);
}

} // namespace Check
