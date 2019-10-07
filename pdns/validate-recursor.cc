#include "validate.hh"
#include "validate-recursor.hh"
#include "syncres.hh"
#include "logger.hh"
#include "rec-lua-conf.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include "zoneparser-tng.hh"

DNSSECMode g_dnssecmode{DNSSECMode::ProcessNoValidate};
bool g_dnssecLogBogus;

bool checkDNSSECDisabled() {
  return warnIfDNSSECDisabled("");
}

bool warnIfDNSSECDisabled(const string& msg) {
  if(g_dnssecmode == DNSSECMode::Off) {
    if (!msg.empty())
      g_log<<Logger::Warning<<msg<<endl;
    return true;
  }
  return false;
}

vState increaseDNSSECStateCounter(const vState& state)
{
  g_stats.dnssecResults[state]++;
  return state;
}

// Returns true if dsAnchors were modified
bool updateTrustAnchorsFromFile(const std::string &fname, map<DNSName, dsmap_t> &dsAnchors) {
  map<DNSName,dsmap_t> newDSAnchors;
  try {
    auto zp = ZoneParserTNG(fname);
    DNSResourceRecord rr;
    DNSRecord dr;
    while(zp.get(rr)) {
      dr = DNSRecord(rr);
      if (rr.qtype == QType::DS) {
        auto dsr = getRR<DSRecordContent>(dr);
        if (dsr == nullptr) {
          throw PDNSException("Unable to parse DS record '" + rr.qname.toString() + " " + rr.getZoneRepresentation() + "'");
        }
        newDSAnchors[rr.qname].insert(*dsr);
      }
      if (rr.qtype == QType::DNSKEY) {
        auto dnskeyr = getRR<DNSKEYRecordContent>(dr);
        if (dnskeyr == nullptr) {
          throw PDNSException("Unable to parse DNSKEY record '" + rr.qname.toString() + " " + rr.getZoneRepresentation() +"'");
        }
        auto dsr = makeDSFromDNSKey(rr.qname, *dnskeyr, DNSSECKeeper::DIGEST_SHA256);
        newDSAnchors[rr.qname].insert(dsr);
      }
    }
    if (dsAnchors == newDSAnchors) {
      g_log<<Logger::Debug<<"Read Trust Anchors from file, no changes detected"<<endl;
      return false;
    }
    g_log<<Logger::Info<<"Read changed Trust Anchors from file, updating"<<endl;
    dsAnchors = newDSAnchors;
    return true;
  }
  catch (const std::exception &e) {
    throw PDNSException("Error while reading Trust Anchors from file '" + fname + "': " + e.what());
  }
  catch (...) {
    throw PDNSException("Error while reading Trust Anchors from file '" + fname + "'");
  }
}
