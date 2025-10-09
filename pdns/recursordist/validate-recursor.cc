#include "validate.hh"
#include "validate-recursor.hh"
#include "syncres.hh"
#include "logger.hh"
#include "rec-lua-conf.hh"
#include "dnssecinfra.hh"
#include "dnssec.hh"
#include "zoneparser-tng.hh"
#include "rec-tcounters.hh"

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
        auto dsr = makeDSFromDNSKey(resourceRecord.qname, *dnskeyr, DNSSEC::DIGEST_SHA256);
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
