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
 * Foundation, Inc.
 */

#include "validate-recursor.hh"
#include "dnsparser.hh"
#include "syncres.hh"
#include "logging.hh"
#include "dnssec.hh"
#include "zoneparser-tng.hh"

DNSSECMode g_dnssecmode{DNSSECMode::ProcessNoValidate};
bool g_dnssecLogBogus;

bool checkDNSSECDisabled()
{
  return g_dnssecmode == DNSSECMode::Off;
}

bool warnIfDNSSECDisabled(const string& msg)
{
  if (g_dnssecmode == DNSSECMode::Off) {
    if (!msg.empty()) {
      auto log = g_slog->withName("config");
      log->info(Logr::Warning, msg);
    }
    return true;
  }
  return false;
}

vState increaseDNSSECStateCounter(const vState& state)
{
  t_Counters.at(rec::DNSSECHistogram::dnssec).at(state)++;
  return state;
}

vState increaseXDNSSECStateCounter(const vState& state)
{
  t_Counters.at(rec::DNSSECHistogram::xdnssec).at(state)++;
  return state;
}

// Returns true if dsAnchors were modified
bool updateTrustAnchorsFromFile(const std::string& fname, map<DNSName, dsset_t>& dsAnchors, Logr::log_t log)
{
  map<DNSName, dsset_t> newDSAnchors;
  try {
    auto zoneParser = ZoneParserTNG(fname);
    zoneParser.disableGenerate();
    DNSResourceRecord resourceRecord;
    DNSRecord dnsrecord;
    while (zoneParser.get(resourceRecord)) {
      dnsrecord = DNSRecord(resourceRecord);
      if (resourceRecord.qtype == QType::DS) {
        auto dsr = getRR<DSRecordContent>(dnsrecord);
        if (dsr == nullptr) {
          throw PDNSException("Unable to parse DS record '" + resourceRecord.qname.toString() + " " + resourceRecord.getZoneRepresentation() + "'");
        }
        newDSAnchors[resourceRecord.qname].insert(*dsr);
      }
      if (resourceRecord.qtype == QType::DNSKEY) {
        auto dnskeyr = getRR<DNSKEYRecordContent>(dnsrecord);
        if (dnskeyr == nullptr) {
          throw PDNSException("Unable to parse DNSKEY record '" + resourceRecord.qname.toString() + " " + resourceRecord.getZoneRepresentation() + "'");
        }
        auto dsr = makeDSFromDNSKey(log, resourceRecord.qname, *dnskeyr, DNSSEC::DIGEST_SHA256);
        newDSAnchors[resourceRecord.qname].insert(std::move(dsr));
      }
    }
    if (dsAnchors == newDSAnchors) {
      log->info(Logr::Debug, "Read Trust Anchors from file, no changes detected");
      return false;
    }
    log->info(Logr::Info, "Read changed Trust Anchors from file, updating");
    dsAnchors = std::move(newDSAnchors);
    return true;
  }
  catch (const std::exception& e) {
    throw PDNSException("Error while reading Trust Anchors from file '" + fname + "': " + e.what());
  }
  catch (...) {
    throw PDNSException("Error while reading Trust Anchors from file '" + fname + "'");
  }
}


std::atomic<size_t> g_UnknownRootKeys = 0;

void detectUnknownRootKeys(const dsset_t& rootAnchors, Logr::log_t logger)
{

  std::vector<DNSRecord> dnskeys;
  auto res = directResolve(g_rootdnsname, QType::DNSKEY, QClass::IN, dnskeys, nullptr, false, logger);
  if (res != 0) {
    logger->info(Logr::Warning, "Could not resolve root key set", "result", Logging::Loggable(res));
    return;
  }
  g_UnknownRootKeys = 0;
  for (const auto& key : dnskeys) {
    if (key.d_type != QType::DNSKEY) {
      continue;
    }
    const auto keyContent = getRR<DNSKEYRecordContent>(key);
    if (keyContent == nullptr) {
      logger->info(Logr::Warning, "Invalid key in root key set");
      continue;
    }
    if (!isSepKey(*keyContent) || isRevokedKey(*keyContent)) {
      continue;
    }
    bool trusted = false;
    for (const auto& dsRecord : rootAnchors) {
      const auto dsFromKey = makeDSFromDNSKey(logger, g_rootdnsname, *keyContent, dsRecord.d_digesttype);
      if (dsFromKey.d_digest == dsRecord.d_digest) {
        trusted = true;
        break;
      }
    }
    if (!trusted) {
      g_UnknownRootKeys++;
      const auto dsFromKey = makeDSFromDNSKey(logger, g_rootdnsname, *keyContent, DNSSEC::DIGEST_SHA256).getZoneRepresentation();
      logger->info(Logr::Warning, "Key signing key found in root DNSKEY set that is not in trust anchors",
                   "dnskey", Logging::Loggable(keyContent->getZoneRepresentation()),
                   "ds", Logging::Loggable(dsFromKey));
    }
  }
}
