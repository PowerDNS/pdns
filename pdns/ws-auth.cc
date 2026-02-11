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
#include "dnsbackend.hh"
#include "iputils.hh"
#include "webserver.hh"
#include <array>
#include <string_view>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "utility.hh"
#include "dynlistener.hh"
#include "ws-auth.hh"
#include "json.hh"
#include "logger.hh"
#include "statbag.hh"
#include "misc.hh"
#include "base64.hh"
#include "arguments.hh"
#include "dns.hh"
#include "comment.hh"
#include "ueberbackend.hh"
#include <boost/format.hpp>

#include "namespaces.hh"
#include "ws-api.hh"
#include "version.hh"
#include "dnsseckeeper.hh"
#include <iomanip>
#include "zoneparser-tng.hh"
#include "auth-main.hh"
#include "auth-caches.hh"
#include "auth-packetcache.hh"
#include "auth-zonecache.hh"
#include "threadname.hh"
#include "tsigutils.hh"
#include "check-zone.hh"

using json11::Json;

Ewma::Ewma() { dt.set(); }

void Ewma::submit(int val)
{
  int rate = val - d_last;
  double difft = dt.udiff() / 1000000.0;
  dt.set();

  d_10 = ((600.0 - difft) * d_10 + (difft * rate)) / 600.0;
  d_5 = ((300.0 - difft) * d_5 + (difft * rate)) / 300.0;
  d_1 = ((60.0 - difft) * d_1 + (difft * rate)) / 60.0;
  d_max = max(d_1, d_max);

  d_last = val;
}

double Ewma::get10() const
{
  return d_10;
}

double Ewma::get5() const
{
  return d_5;
}

double Ewma::get1() const
{
  return d_1;
}

double Ewma::getMax() const
{
  return d_max;
}

static void patchZone(UeberBackend& backend, const ZoneName& zonename, DomainInfo& domainInfo, const vector<Json>& rrsets, HttpResponse* resp);

AuthWebServer::AuthWebServer() :
  d_start(time(nullptr))

{
  if (arg().mustDo("webserver") || arg().mustDo("api")) {
    d_ws = std::make_unique<WebServer>(arg()["webserver-address"], arg().asNum("webserver-port"));
    d_ws->setApiKey(arg()["api-key"], arg().mustDo("webserver-hash-plaintext-credentials"));
    d_ws->setPassword(arg()["webserver-password"], arg().mustDo("webserver-hash-plaintext-credentials"));
    d_ws->setLogLevel(arg()["webserver-loglevel"]);

    NetmaskGroup acl;
    acl.toMasks(::arg()["webserver-allow-from"]);
    d_ws->setACL(acl);

    d_ws->setMaxBodySize(::arg().asNum("webserver-max-bodysize"));
    d_ws->setConnectionTimeout(::arg().asNum("webserver-connection-timeout"));

    d_ws->bind();
  }
}

void AuthWebServer::go(StatBag& stats)
{
  S.doRings();
  std::thread webT([this]() { webThread(); });
  webT.detach();
  std::thread statT([this, &stats]() { statThread(stats); });
  statT.detach();
}

void AuthWebServer::statThread(StatBag& stats)
{
  try {
    setThreadName("pdns/statHelper");
    for (;;) {
      d_queries.submit(static_cast<int>(stats.read("udp-queries")));
      d_cachehits.submit(static_cast<int>(stats.read("packetcache-hit")));
      d_cachemisses.submit(static_cast<int>(stats.read("packetcache-miss")));
      d_qcachehits.submit(static_cast<int>(stats.read("query-cache-hit")));
      d_qcachemisses.submit(static_cast<int>(stats.read("query-cache-miss")));
      Utility::sleep(1);
    }
  }
  catch (...) {
    g_log << Logger::Error << "Webserver statThread caught an exception, dying" << endl;
    _exit(1);
  }
}

static string htmlescape(const string& inputString)
{
  string result;
  for (char currentChar : inputString) {
    switch (currentChar) {
    case '&':
      result += "&amp;";
      break;
    case '<':
      result += "&lt;";
      break;
    case '>':
      result += "&gt;";
      break;
    case '"':
      result += "&quot;";
      break;
    default:
      result += currentChar;
    }
  }
  return result;
}

static void printtable(ostringstream& ret, const string& ringname, const string& title, int limit = 10)
{
  unsigned int tot = 0;
  int entries = 0;
  vector<pair<string, unsigned int>> ring = S.getRing(ringname);

  for (const auto& entry : ring) {
    tot += entry.second;
    entries++;
  }

  ret << "<div class=\"panel\">";
  ret << "<span class=resetring><i></i><a href=\"?resetring=" << htmlescape(ringname) << "\">Reset</a></span>" << endl;
  ret << "<h2>" << title << "</h2>" << endl;
  ret << "<div class=ringmeta>";
  ret << "<a class=topXofY href=\"?ring=" << htmlescape(ringname) << "\">Showing: Top " << limit << " of " << entries << "</a>" << endl;
  ret << "<span class=resizering>Resize: ";
  std::vector<uint64_t> sizes{10, 100, 500, 1000, 10000, 500000, 0};
  for (int i = 0; sizes[i] != 0; ++i) {
    if (S.getRingSize(ringname) != sizes[i]) {
      ret << "<a href=\"?resizering=" << htmlescape(ringname) << "&amp;size=" << sizes[i] << "\">" << sizes[i] << "</a> ";
    }
    else {
      ret << "(" << sizes[i] << ") ";
    }
  }
  ret << "</span></div>";

  ret << "<table class=\"data\">";
  unsigned int printed = 0;
  unsigned int total = std::max(1U, tot);
  for (auto i = ring.begin(); limit != 0 && i != ring.end(); ++i, --limit) {
    ret << "<tr><td>" << htmlescape(i->first) << "</td><td>" << i->second << "</td><td align=right>" << AuthWebServer::makePercentage(i->second * 100.0 / total) << "</td>" << endl;
    printed += i->second;
  }
  ret << "<tr><td colspan=3></td></tr>" << endl;
  if (printed != tot) {
    ret << "<tr><td><b>Rest:</b></td><td><b>" << tot - printed << "</b></td><td align=right><b>" << AuthWebServer::makePercentage((tot - printed) * 100.0 / total) << "</b></td>" << endl;
  }

  ret << "<tr><td><b>Total:</b></td><td><b>" << tot << "</b></td><td align=right><b>100%</b></td>";
  ret << "</table></div>" << endl;
}

static void printvars(ostringstream& ret)
{
  ret << "<div class=panel><h2>Variables</h2><table class=\"data\">" << endl;

  vector<string> entries = S.getEntries();
  for (const auto& entry : entries) {
    ret << "<tr><td>" << entry << "</td><td>" << S.read(entry) << "</td><td>" << S.getDescrip(entry) << "</td>" << endl;
  }

  ret << "</table></div>" << endl;
}

static void printargs(ostringstream& ret)
{
  ret << R"(<table border=1><tr><td colspan=3 bgcolor="#0000ff"><font color="#ffffff">Arguments</font></td>)" << endl;

  vector<string> entries = arg().list();
  for (const auto& entry : entries) {
    ret << "<tr><td>" << entry << "</td><td>" << arg()[entry] << "</td><td>" << arg().getHelp(entry) << "</td>" << endl;
  }
}

string AuthWebServer::makePercentage(const double& val)
{
  return (boost::format("%.01f%%") % val).str();
}

void AuthWebServer::indexfunction(HttpRequest* req, HttpResponse* resp)
{
  if (!req->getvars["resetring"].empty()) {
    if (S.ringExists(req->getvars["resetring"])) {
      S.resetRing(req->getvars["resetring"]);
    }
    resp->status = 302;
    resp->headers["Location"] = req->url.path;
    return;
  }
  if (!req->getvars["resizering"].empty()) {
    int size = std::stoi(req->getvars["size"]);
    if (S.ringExists(req->getvars["resizering"]) && size > 0 && size <= 500000) {
      S.resizeRing(req->getvars["resizering"], std::stoi(req->getvars["size"]));
    }
    resp->status = 302;
    resp->headers["Location"] = req->url.path;
    return;
  }

  ostringstream ret;

  ret << "<!DOCTYPE html>" << endl;
  ret << "<html><head>" << endl;
  ret << "<title>PowerDNS Authoritative Server Monitor</title>" << endl;
  ret << R"(<link rel="stylesheet" href="style.css"/>)" << endl;
  ret << "</head><body>" << endl;

  ret << "<div class=\"row\">" << endl;
  ret << "<div class=\"headl columns\">";
  ret << R"(<a href="/" id="appname">PowerDNS )" << htmlescape(VERSION);
  if (!arg()["config-name"].empty()) {
    ret << " [" << htmlescape(arg()["config-name"]) << "]";
  }
  ret << "</a></div>" << endl;
  ret << "<div class=\"header columns\"></div></div>";
  ret << R"(<div class="row"><div class="all columns">)";

  time_t passed = time(nullptr) - g_starttime;

  ret << "<p>Uptime: " << humanDuration(passed) << "<br>" << endl;

  ret << "Queries/second, 1, 5, 10 minute averages:  " << std::setprecision(3) << (int)d_queries.get1() << ", " << (int)d_queries.get5() << ", " << (int)d_queries.get10() << ". Max queries/second: " << (int)d_queries.getMax() << "<br>" << endl;

  if (d_cachemisses.get10() + d_cachehits.get10() > 0) {
    ret << "Cache hitrate, 1, 5, 10 minute averages: " << makePercentage((d_cachehits.get1() * 100.0) / ((d_cachehits.get1()) + (d_cachemisses.get1()))) << ", " << makePercentage((d_cachehits.get5() * 100.0) / ((d_cachehits.get5()) + (d_cachemisses.get5()))) << ", " << makePercentage((d_cachehits.get10() * 100.0) / ((d_cachehits.get10()) + (d_cachemisses.get10()))) << "<br>" << endl;
  }

  if (d_qcachemisses.get10() + d_qcachehits.get10() > 0) {
    ret << "Backend query cache hitrate, 1, 5, 10 minute averages: " << std::setprecision(2) << makePercentage((d_qcachehits.get1() * 100.0) / ((d_qcachehits.get1()) + (d_qcachemisses.get1()))) << ", " << makePercentage((d_qcachehits.get5() * 100.0) / ((d_qcachehits.get5()) + (d_qcachemisses.get5()))) << ", " << makePercentage((d_qcachehits.get10() * 100.0) / ((d_qcachehits.get10()) + (d_qcachemisses.get10()))) << "<br>" << endl;
  }

  ret << "Backend query load, 1, 5, 10 minute averages: " << std::setprecision(3) << (int)d_qcachemisses.get1() << ", " << (int)d_qcachemisses.get5() << ", " << (int)d_qcachemisses.get10() << ". Max queries/second: " << (int)d_qcachemisses.getMax() << "<br>" << endl;

  ret << "Total queries: " << S.read("udp-queries") << ". Question/answer latency: " << static_cast<double>(S.read("latency")) / 1000.0 << "ms</p><br>" << endl;
  if (req->getvars["ring"].empty()) {
    auto entries = S.listRings();
    for (const auto& entry : entries) {
      printtable(ret, entry, S.getRingTitle(entry));
    }

    printvars(ret);
    if (arg().mustDo("webserver-print-arguments")) {
      printargs(ret);
    }
  }
  else if (S.ringExists(req->getvars["ring"])) {
    printtable(ret, req->getvars["ring"], S.getRingTitle(req->getvars["ring"]), 100);
  }

  ret << "</div></div>" << endl;
  ret << "<footer class=\"row\">" << fullVersionString() << "<br>&copy; <a href=\"https://www.powerdns.com/\">PowerDNS.COM BV</a>.</footer>" << endl;
  ret << "</body></html>" << endl;

  resp->body = ret.str();
  resp->status = 200;
}

/** Helper to build a record content as needed. */
static inline string makeRecordContent(const QType& qtype, const string& content, bool noDot)
{
  // noDot: for backend storage, pass true. for API users, pass false.
  auto drc = DNSRecordContent::make(qtype.getCode(), QClass::IN, content);
  return drc->getZoneRepresentation(noDot);
}

/** "Normalize" record content for API consumers. */
static inline string makeApiRecordContent(const QType& qtype, const string& content)
{
  return makeRecordContent(qtype, content, false);
}

/** "Normalize" record content for backend storage. */
static inline string makeBackendRecordContent(const QType& qtype, const string& content)
{
  return makeRecordContent(qtype, content, true);
}

static Json::object getZoneInfo(const DomainInfo& domainInfo, DNSSECKeeper* dnssecKeeper)
{
  string zoneId = apiZoneNameToId(domainInfo.zone);
  vector<string> primaries;
  primaries.reserve(domainInfo.primaries.size());
  for (const auto& primary : domainInfo.primaries) {
    primaries.push_back(primary.toStringWithPortExcept(53));
  }

  auto obj = Json::object{
    // id is the canonical lookup key, which doesn't actually match the name (in some cases)
    {"id", zoneId},
    {"url", "/api/v1/servers/localhost/zones/" + zoneId},
    {"name", domainInfo.zone.toString()},
    {"kind", domainInfo.getKindString()},
    {"catalog", (!domainInfo.catalog.empty() ? domainInfo.catalog.toString() : "")},
    {"account", domainInfo.account},
    {"masters", std::move(primaries)},
    {"serial", (double)domainInfo.serial},
    {"notified_serial", (double)domainInfo.notified_serial},
    {"last_check", (double)domainInfo.last_check}};
  if (dnssecKeeper != nullptr) {
    obj["dnssec"] = dnssecKeeper->isSecuredZone(domainInfo.zone);
    string soa_edit;
    dnssecKeeper->getSoaEdit(domainInfo.zone, soa_edit, false);
    obj["edited_serial"] = (double)calculateEditSOA(domainInfo.serial, soa_edit, domainInfo.zone);
  }
  return obj;
}

static bool boolFromHttpRequest(HttpRequest* req, const std::string& var)
{
  if (req->getvars.count(var) == 0 || req->getvars[var] == "true") {
    return true;
  }
  if (req->getvars[var] == "false") {
    return false;
  }

  throw ApiException("'" + var + "' request parameter value '" + req->getvars[var] + "' is not supported");
}

static void fillZone(UeberBackend& backend, const ZoneName& zonename, HttpResponse* resp, HttpRequest* req)
{
  DomainInfo domainInfo;

  if (!backend.getDomainInfo(zonename, domainInfo)) {
    throw HttpNotFoundException();
  }

  DNSSECKeeper dnssecKeeper(&backend);
  Json::object doc = getZoneInfo(domainInfo, &dnssecKeeper);
  // extra stuff getZoneInfo doesn't do for us (more expensive)
  string soa_edit_api;
  domainInfo.backend->getDomainMetadataOne(zonename, "SOA-EDIT-API", soa_edit_api);
  doc["soa_edit_api"] = soa_edit_api;
  string soa_edit;
  domainInfo.backend->getDomainMetadataOne(zonename, "SOA-EDIT", soa_edit);
  doc["soa_edit"] = soa_edit;

  string nsec3param;
  bool nsec3narrowbool = false;
  bool is_secured = dnssecKeeper.isSecuredZone(zonename);
  if (is_secured) { // ignore NSEC3PARAM and NSEC3NARROW metadata present in the db for unsigned zones
    domainInfo.backend->getDomainMetadataOne(zonename, "NSEC3PARAM", nsec3param);
    string nsec3narrow;
    domainInfo.backend->getDomainMetadataOne(zonename, "NSEC3NARROW", nsec3narrow);
    if (nsec3narrow == "1") {
      nsec3narrowbool = true;
    }
  }
  doc["nsec3param"] = nsec3param;
  doc["nsec3narrow"] = nsec3narrowbool;
  doc["dnssec"] = is_secured;

  string api_rectify;
  domainInfo.backend->getDomainMetadataOne(zonename, "API-RECTIFY", api_rectify);
  doc["api_rectify"] = (api_rectify == "1");

  // TSIG
  vector<string> tsig_primary;
  vector<string> tsig_secondary;
  domainInfo.backend->getDomainMetadata(zonename, "TSIG-ALLOW-AXFR", tsig_primary);
  domainInfo.backend->getDomainMetadata(zonename, "AXFR-MASTER-TSIG", tsig_secondary);

  Json::array tsig_primary_keys;
  for (const auto& keyname : tsig_primary) {
    tsig_primary_keys.emplace_back(apiNameToId(keyname));
  }
  doc["master_tsig_key_ids"] = tsig_primary_keys;

  Json::array tsig_secondary_keys;
  for (const auto& keyname : tsig_secondary) {
    tsig_secondary_keys.emplace_back(apiNameToId(keyname));
    // Although AXFR-MASTER-TSIG may contain a list of keys, the current
    // state of DNSSECKeeper::getTSIGForAccess() causes only the first one
    // to be ever used, so only return the first item here.
    break;
  }
  doc["slave_tsig_key_ids"] = tsig_secondary_keys;

  if (boolFromHttpRequest(req, "rrsets")) {
    vector<DNSResourceRecord> records;
    vector<Comment> comments;

    QType qType = QType::ANY;
    DNSName qName;

    // load all records + sort
    {
      DNSResourceRecord resourceRecord;
      if (req->getvars.count("rrset_name") == 0) {
        domainInfo.backend->list(zonename, static_cast<int>(domainInfo.id), true); // incl. disabled
      }
      else {
        qName = DNSName(req->getvars["rrset_name"]);
        if (req->getvars.count("rrset_type") != 0) {
          qType = req->getvars["rrset_type"];
        }
        bool include_disabled = boolFromHttpRequest(req, "include_disabled");
        domainInfo.backend->APILookup(qType, qName, static_cast<int>(domainInfo.id), include_disabled);
      }
      while (domainInfo.backend->get(resourceRecord)) {
        if (resourceRecord.qtype.getCode() == 0) {
          continue; // skip empty non-terminals
        }
        records.push_back(resourceRecord);
      }
      sort(records.begin(), records.end(), [](const DNSResourceRecord& rrA, const DNSResourceRecord& rrB) {
        /* if you ever want to update this comparison function,
           please be aware that you will also need to update the conditions in the code merging
           the records and comments below */
        if (rrA.qname == rrB.qname) {
          return rrB.qtype < rrA.qtype;
        }
        return rrB.qname < rrA.qname;
      });
    }

    // load all comments + sort
    {
      Comment comment;
      domainInfo.backend->listComments(domainInfo.id);
      while (domainInfo.backend->getComment(comment)) {
        if ((qName.empty() || comment.qname == qName) && (qType == QType::ANY || comment.qtype == qType)) {
          comments.push_back(comment);
        }
      }
      sort(comments.begin(), comments.end(), [](const Comment& rrA, const Comment& rrB) {
        /* if you ever want to update this comparison function,
           please be aware that you will also need to update the conditions in the code merging
           the records and comments below */
        if (rrA.qname == rrB.qname) {
          return rrB.qtype < rrA.qtype;
        }
        return rrB.qname < rrA.qname;
      });
    }

    Json::array rrsets;
    Json::object rrset;
    Json::array rrset_records;
    Json::array rrset_comments;
    DNSName current_qname;
    QType current_qtype;
    uint32_t ttl = 0;
    auto rit = records.begin();
    auto cit = comments.begin();

    while (rit != records.end() || cit != comments.end()) {
      // if you think this should be rit < cit instead of cit < rit, note the b < a instead of a < b in the sort comparison functions above
      if (cit == comments.end() || (rit != records.end() && (rit->qname == cit->qname ? (cit->qtype < rit->qtype || cit->qtype == rit->qtype) : cit->qname < rit->qname))) {
        current_qname = rit->qname;
        current_qtype = rit->qtype;
        ttl = rit->ttl;
      }
      else {
        current_qname = cit->qname;
        current_qtype = cit->qtype;
        ttl = 0;
      }

      while (rit != records.end() && rit->qname == current_qname && rit->qtype == current_qtype) {
        ttl = min(ttl, rit->ttl);
        std::string content;
        try {
          content = makeApiRecordContent(rit->qtype, rit->content);
        }
        catch (std::exception& e) {
          // makeApiRecordContent may throw an exception if the backend data
          // is not well-formed (e.g. corrupted bind zone file).
          // The exception gets caught here and rethrown as ApiException in
          // order to return a 422 error code with a (hopefully) useful error
          // message instead of a 500 error.
          throw ApiException("Ill-formed record contents found for " + current_qname.toString() + ": " + e.what());
        }
        auto object = Json::object{
          {"disabled", rit->disabled},
          {"content", content}};
        if (rit->last_modified != 0) {
          object["modified_at"] = (double)rit->last_modified;
        }
        rrset_records.push_back(object);
        rit++;
      }
      while (cit != comments.end() && cit->qname == current_qname && cit->qtype == current_qtype) {
        rrset_comments.push_back(Json::object{
          {"modified_at", (double)cit->modified_at},
          {"account", cit->account},
          {"content", cit->content}});
        cit++;
      }

      rrset["name"] = current_qname.toString();
      rrset["type"] = current_qtype.toString();
      rrset["records"] = rrset_records;
      rrset["comments"] = rrset_comments;
      rrset["ttl"] = (double)ttl;
      rrsets.emplace_back(rrset);
      rrset.clear();
      rrset_records.clear();
      rrset_comments.clear();
    }

    doc["rrsets"] = rrsets;
  }

  resp->setJsonBody(doc);
}

void productServerStatisticsFetch(map<string, string>& out)
{
  vector<string> items = S.getEntries();
  for (const string& item : items) {
    out[item] = std::to_string(S.read(item));
  }

  // add uptime
  out["uptime"] = std::to_string(time(nullptr) - g_starttime);
}

std::optional<uint64_t> productServerStatisticsFetch(const std::string& name)
{
  try {
    // ::read() calls ::exists() which throws a PDNSException when the key does not exist
    return S.read(name);
  }
  catch (...) {
    return std::nullopt;
  }
}

static void validateGatheredRRType(const DNSResourceRecord& resourceRecord)
{
  if (resourceRecord.qtype.getCode() == QType::OPT || resourceRecord.qtype.getCode() == QType::TSIG) {
    throw ApiException("RRset " + resourceRecord.qname.toString() + " IN " + resourceRecord.qtype.toString() + ": invalid type given");
  }
}

// Clean and unescape a record content string, in order to minimize the
// risk of mismatch between it and its canonical form returned by
// makeApiRecordContent().
// To do so, we remove leading and trailing whitespace, and perform
// RFC1035 processing on the data until all the chunks have been processed.
static std::string normalizeJsonString(const std::string& jsonContent)
{
  std::ostringstream ret;

  std::string copy{jsonContent};
  // Trim surrounding whitespace
  boost::trim_right(copy);
  boost::trim_left(copy);

  std::string_view input{copy};
  auto len = input.size();
  size_t pos = 0;
  while (pos < len) {
    std::string chunk;
    // Preserve quotes in the result if the chunk is quoted.
    bool quote = input[pos] == '"';
    auto chunksize = parseRFC1035CharString(input.substr(pos), chunk);
    if (quote) {
      ret << '"';
    }
    // We would love to simply feed chunk to ret here, but unfortunately
    // we need to RFC1035 escape non-printable characters again.
    for (char chr : chunk) {
      if (chr >= 0x20 && chr < 0x7f) {
        ret << chr;
      }
      else {
        ret << '\\' << std::setfill('0') << std::setw(3) << static_cast<unsigned int>(chr) << std::setw(0);
      }
    }
    if (quote) {
      ret << '"';
    }
    pos += chunksize;
    // Keep only one space for space-separated chunks.
    if (pos < len && std::isspace(static_cast<unsigned char>(input[pos])) != 0) {
      while (pos < len && std::isspace(static_cast<unsigned char>(input[pos])) != 0) {
        ++pos;
      }
      ret << ' ';
    }
  }
  return ret.str();
}

static void gatherRecords(const Json& container, const DNSName& qname, const QType& qtype, const uint32_t ttl, vector<DNSResourceRecord>& new_records)
{
  DNSResourceRecord resourceRecord;
  resourceRecord.qname = qname;
  resourceRecord.qtype = qtype;
  resourceRecord.auth = true;
  resourceRecord.ttl = ttl;

  validateGatheredRRType(resourceRecord);
  const auto& items = container["records"].array_items();
  for (const auto& record : items) {
    string content = normalizeJsonString(stringFromJson(record, "content"));
    if (record.object_items().count("priority") > 0) {
      throw std::runtime_error("`priority` element is not allowed in record");
    }
    resourceRecord.disabled = false;
    if (!record["disabled"].is_null()) {
      resourceRecord.disabled = boolFromJson(record, "disabled");
    }

    // validate that the client sent something we can actually parse, and require that data to be dotted.
    try {
      if (resourceRecord.qtype.getCode() != QType::AAAA) {
        string tmp = makeApiRecordContent(resourceRecord.qtype, content);
        if (!pdns_iequals(tmp, content)) {
          throw std::runtime_error("Not in expected format (parsed as '" + tmp + "')");
        }
      }
      else {
        struct in6_addr tmpbuf{};
        if (inet_pton(AF_INET6, content.c_str(), &tmpbuf) != 1) {
          throw std::runtime_error("Invalid IPv6 address");
        }
      }
      resourceRecord.content = makeBackendRecordContent(resourceRecord.qtype, content);
    }
    catch (std::exception& e) {
      throw ApiException("Record " + resourceRecord.qname.toString() + "/" + resourceRecord.qtype.toString() + " '" + content + "': " + e.what());
    }

    new_records.push_back(resourceRecord);
  }
}

static void gatherComments(const Json& container, const DNSName& qname, const QType& qtype, vector<Comment>& new_comments)
{
  Comment comment;
  comment.qname = qname;
  comment.qtype = qtype;

  time_t now = time(nullptr);
  for (const auto& currentComment : container["comments"].array_items()) {
    // FIXME 2036 issue internally in uintFromJson
    comment.modified_at = uintFromJson(currentComment, "modified_at", now);
    comment.content = stringFromJson(currentComment, "content");
    comment.account = stringFromJson(currentComment, "account");
    new_comments.push_back(comment);
  }
}

static void checkDefaultDNSSECAlgos()
{
  int k_algo = DNSSECKeeper::shorthand2algorithm(::arg()["default-ksk-algorithm"]);
  int z_algo = DNSSECKeeper::shorthand2algorithm(::arg()["default-zsk-algorithm"]);
  int k_size = arg().asNum("default-ksk-size");
  int z_size = arg().asNum("default-zsk-size");

  // Sanity check DNSSEC parameters
  if (!::arg()["default-zsk-algorithm"].empty()) {
    if (k_algo == -1) {
      throw ApiException("default-ksk-algorithm setting is set to unknown algorithm: " + ::arg()["default-ksk-algorithm"]);
    }
    if (k_algo <= 10 && k_size == 0) {
      throw ApiException("default-ksk-algorithm is set to an algorithm(" + ::arg()["default-ksk-algorithm"] + ") that requires a non-zero default-ksk-size!");
    }
  }

  if (!::arg()["default-zsk-algorithm"].empty()) {
    if (z_algo == -1) {
      throw ApiException("default-zsk-algorithm setting is set to unknown algorithm: " + ::arg()["default-zsk-algorithm"]);
    }
    if (z_algo <= 10 && z_size == 0) {
      throw ApiException("default-zsk-algorithm is set to an algorithm(" + ::arg()["default-zsk-algorithm"] + ") that requires a non-zero default-zsk-size!");
    }
  }
}

static void throwUnableToSecure(const ZoneName& zonename)
{
  throw ApiException("No backend was able to secure '" + zonename.toString() + "', most likely because no DNSSEC"
                     + "capable backends are loaded, or because the backends have DNSSEC disabled. Check your configuration.");
}

/*
 * Add KSK and ZSK to an existing zone. Algorithms and sizes will be chosen per configuration.
 */
static void addDefaultDNSSECKeys(DNSSECKeeper& dnssecKeeper, const ZoneName& zonename)
{
  checkDefaultDNSSECAlgos();
  int k_algo = DNSSECKeeper::shorthand2algorithm(::arg()["default-ksk-algorithm"]);
  int z_algo = DNSSECKeeper::shorthand2algorithm(::arg()["default-zsk-algorithm"]);
  int k_size = arg().asNum("default-ksk-size");
  int z_size = arg().asNum("default-zsk-size");

  if (k_algo != -1) {
    int64_t keyID{-1};
    if (!dnssecKeeper.addKey(zonename, true, k_algo, keyID, k_size)) {
      throwUnableToSecure(zonename);
    }
  }

  if (z_algo != -1) {
    int64_t keyID{-1};
    if (!dnssecKeeper.addKey(zonename, false, z_algo, keyID, z_size)) {
      throwUnableToSecure(zonename);
    }
  }
}

static bool isZoneApiRectifyEnabled(const DomainInfo& domainInfo)
{
  string api_rectify;
  domainInfo.backend->getDomainMetadataOne(domainInfo.zone, "API-RECTIFY", api_rectify);
  if (api_rectify.empty() && ::arg().mustDo("default-api-rectify")) {
    api_rectify = "1";
  }
  return api_rectify == "1";
}

static void extractDomainInfoFromDocument(const Json& document, std::optional<DomainInfo::DomainKind>& kind, std::optional<vector<ComboAddress>>& primaries, std::optional<ZoneName>& catalog, std::optional<string>& account)
{
  if (document["kind"].is_string()) {
    kind = DomainInfo::stringToKind(stringFromJson(document, "kind"));
  }
  else {
    kind = std::nullopt;
  }

  if (document["masters"].is_array()) {
    primaries = vector<ComboAddress>();
    for (const auto& value : document["masters"].array_items()) {
      string primary = value.string_value();
      if (primary.empty()) {
        throw ApiException("Primary can not be an empty string");
      }
      try {
        primaries->emplace_back(primary, 53);
      }
      catch (const PDNSException& e) {
        throw ApiException("Primary (" + primary + ") is not an IP address: " + e.reason);
      }
    }
  }
  else {
    primaries = std::nullopt;
  }

  if (document["catalog"].is_string()) {
    string catstring = document["catalog"].string_value();
    catalog = (!catstring.empty() ? ZoneName(catstring) : ZoneName());
  }
  else {
    catalog = std::nullopt;
  }

  if (document["account"].is_string()) {
    account = document["account"].string_value();
  }
  else {
    account = std::nullopt;
  }
}

/*
 * Build vector of TSIG Key ids from domain update document.
 * jsonArray: JSON array element to extract TSIG key ids from.
 * metadata: returned list of domain key ids for setDomainMetadata
 */
static void extractJsonTSIGKeyIds(UeberBackend& backend, const Json& jsonArray, vector<string>& metadata)
{
  for (const auto& value : jsonArray.array_items()) {
    DNSName keyname(apiZoneIdToName(value.string_value()));
    DNSName keyAlgo;
    string keyContent;
    if (!backend.getTSIGKey(keyname, keyAlgo, keyContent)) {
      throw ApiException("A TSIG key with the name '" + keyname.toLogString() + "' does not exist");
    }
    metadata.push_back(keyname.toString());
  }
}

// Wrapper around makeIncreasedSOARecord()
static void updateZoneSerial(DomainInfo& domainInfo, SOAData& soaData, const std::string& increaseKind, const std::string& editKind)
{
  DNSResourceRecord resourceRecord;

  if (makeIncreasedSOARecord(soaData, increaseKind, editKind, resourceRecord)) {
    if (!domainInfo.backend->replaceRRSet(domainInfo.id, resourceRecord.qname, resourceRecord.qtype, vector<DNSResourceRecord>(1, resourceRecord))) {
      throw ApiException("Hosting backend does not support editing records.");
    }
  }
}

// Must be called within backend transaction.
static void updateDomainSettingsFromDocument(UeberBackend& backend, DomainInfo& domainInfo, const ZoneName& zonename, const Json& document, bool zoneWasModified)
{
  std::optional<DomainInfo::DomainKind> kind;
  std::optional<vector<ComboAddress>> primaries;
  std::optional<ZoneName> catalog;
  std::optional<string> account;

  extractDomainInfoFromDocument(document, kind, primaries, catalog, account);

  if (kind) {
    domainInfo.backend->setKind(zonename, *kind);
    domainInfo.kind = *kind;
  }
  if (primaries) {
    domainInfo.backend->setPrimaries(zonename, *primaries);
  }
  if (catalog) {
    domainInfo.backend->setCatalog(zonename, *catalog);
  }
  if (account) {
    domainInfo.backend->setAccount(zonename, *account);
  }

  if (document["soa_edit_api"].is_string()) {
    domainInfo.backend->setDomainMetadataOne(zonename, "SOA-EDIT-API", document["soa_edit_api"].string_value());
  }
  if (document["soa_edit"].is_string()) {
    domainInfo.backend->setDomainMetadataOne(zonename, "SOA-EDIT", document["soa_edit"].string_value());
  }
  try {
    bool api_rectify = boolFromJson(document, "api_rectify");
    domainInfo.backend->setDomainMetadataOne(zonename, "API-RECTIFY", api_rectify ? "1" : "0");
  }
  catch (const JsonException&) {
  }

  DNSSECKeeper dnssecKeeper(&backend);
  bool shouldRectify = zoneWasModified;
  bool dnssecInJSON = false;
  bool dnssecDocVal = false;
  bool nsec3paramInJSON = false;
  bool updateNsec3Param = false;
  string nsec3paramDocVal;

  try {
    dnssecDocVal = boolFromJson(document, "dnssec");
    dnssecInJSON = true;
  }
  catch (const JsonException&) {
  }

  try {
    nsec3paramDocVal = stringFromJson(document, "nsec3param");
    nsec3paramInJSON = true;
  }
  catch (const JsonException&) {
  }

  bool isDNSSECZone = dnssecKeeper.isSecuredZone(zonename);
  bool isPresigned = dnssecKeeper.isPresigned(zonename);

  if (dnssecInJSON) {
    if (dnssecDocVal) {
      if (!isDNSSECZone) {
        addDefaultDNSSECKeys(dnssecKeeper, zonename);

        // Used later for NSEC3PARAM
        isDNSSECZone = dnssecKeeper.isSecuredZone(zonename);

        if (!isDNSSECZone) {
          throwUnableToSecure(zonename);
        }
        shouldRectify = true;
        updateNsec3Param = true;
      }
    }
    else {
      // "dnssec": false in json
      if (isDNSSECZone) {
        string info;
        string error;
        if (!dnssecKeeper.unSecureZone(zonename, error)) {
          throw ApiException("Error while un-securing zone '" + zonename.toString() + "': " + error);
        }
        isDNSSECZone = dnssecKeeper.isSecuredZone(zonename, false);
        if (isDNSSECZone) {
          throw ApiException("Unable to un-secure zone '" + zonename.toString() + "'");
        }
        shouldRectify = true;
        updateNsec3Param = true;
      }
    }
  }

  if (nsec3paramInJSON || updateNsec3Param) {
    shouldRectify = true;
    if (!isDNSSECZone && !nsec3paramDocVal.empty()) {
      throw ApiException("NSEC3PARAM value provided for zone '" + zonename.toString() + "', but zone is not DNSSEC secured.");
    }

    if (nsec3paramDocVal.empty()) {
      // Switch to NSEC
      if (!dnssecKeeper.unsetNSEC3PARAM(zonename)) {
        throw ApiException("Unable to remove NSEC3PARAMs from zone '" + zonename.toString());
      }
    }
    else {
      // Set the NSEC3PARAMs
      NSEC3PARAMRecordContent ns3pr(nsec3paramDocVal);
      string error_msg;
      if (!dnssecKeeper.checkNSEC3PARAM(ns3pr, error_msg)) {
        throw ApiException("NSEC3PARAMs provided for zone '" + zonename.toString() + "' are invalid. " + error_msg);
      }
      if (!dnssecKeeper.setNSEC3PARAM(zonename, ns3pr, boolFromJson(document, "nsec3narrow", false))) {
        throw ApiException("NSEC3PARAMs provided for zone '" + zonename.toString() + "' passed our basic sanity checks, but cannot be used with the current backend.");
      }
    }
  }

  if (shouldRectify && !isPresigned) {
    // Rectify
    if (isZoneApiRectifyEnabled(domainInfo)) {
      string info;
      string error_msg;
      if (!dnssecKeeper.rectifyZone(zonename, error_msg, info, false) && !domainInfo.isSecondaryType()) {
        // for Secondary zones, it is possible that rectifying was not needed (example: empty zone).
        throw ApiException("Failed to rectify '" + zonename.toString() + "' " + error_msg);
      }
    }

    // Increase serial
    string soa_edit_api_kind;
    domainInfo.backend->getDomainMetadataOne(zonename, "SOA-EDIT-API", soa_edit_api_kind);
    if (!soa_edit_api_kind.empty()) {
      SOAData soaData;
      if (!backend.getSOAUncached(zonename, soaData)) {
        return;
      }

      string soa_edit_kind;
      domainInfo.backend->getDomainMetadataOne(zonename, "SOA-EDIT", soa_edit_kind);

      updateZoneSerial(domainInfo, soaData, soa_edit_api_kind, soa_edit_kind);
    }
  }

  if (!document["master_tsig_key_ids"].is_null()) {
    vector<string> metadata;
    extractJsonTSIGKeyIds(backend, document["master_tsig_key_ids"], metadata);
    if (!domainInfo.backend->setDomainMetadata(zonename, "TSIG-ALLOW-AXFR", metadata)) {
      throw HttpInternalServerErrorException("Unable to set new TSIG primary keys for zone '" + zonename.toString() + "'");
    }
  }
  if (!document["slave_tsig_key_ids"].is_null()) {
    vector<string> metadata;
    extractJsonTSIGKeyIds(backend, document["slave_tsig_key_ids"], metadata);
    if (metadata.size() > 1) {
      throw ApiException("Only one TSIG secondary key is currently allowed");
    }
    if (!domainInfo.backend->setDomainMetadata(zonename, "AXFR-MASTER-TSIG", metadata)) {
      throw HttpInternalServerErrorException("Unable to set new TSIG secondary keys for zone '" + zonename.toString() + "'");
    }
  }
}

static bool isValidMetadataKind(const string& kind, bool readonly)
{
  const static vector<std::pair<std::string_view, bool /* readonly */>> builtinOptions{
    {"ALLOW-AXFR-FROM", false},
    {"ALLOW-DNSUPDATE-FROM", false},
    {"ALSO-NOTIFY", false},
    {"AXFR-MASTER-TSIG", true},
    {"AXFR-SOURCE", false},
    {"FORWARD-DNSUPDATE", false},
    {"GSS-ACCEPTOR-PRINCIPAL", false},
    {"GSS-ALLOW-AXFR-PRINCIPAL", false},
    {"IXFR", false},
    {"LUA-AXFR-SCRIPT", true},
    {"NOTIFY-DNSUPDATE", false},
    {"NSEC3NARROW", true},
    {"NSEC3PARAM", true},
    {"PRESIGNED", true},
    {"PUBLISH-CDNSKEY", false},
    {"PUBLISH-CDS", false},
    {"RFC1123-CONFORMANCE", false},
    {"SIGNALING-ZONE", false},
    {"SLAVE-RENOTIFY", false},
    {"SOA-EDIT", true},
    {"SOA-EDIT-DNSUPDATE", false},
    {"TSIG-ALLOW-AXFR", false},
    {"TSIG-ALLOW-DNSUPDATE", false},
  };

  if (kind.find("X-") == 0) {
    return true;
  }

  for (const auto& builtinOption : builtinOptions) {
    if (kind == builtinOption.first) {
      return readonly || !builtinOption.second;
    }
  }

  return false;
}

/* Return OpenAPI document describing the supported API.
 */
#include "apidocfiles.h"

void apiDocs(HttpRequest* req, HttpResponse* resp)
{
  if (req->accept_yaml) {
    resp->setYamlBody(g_api_swagger_yaml);
  }
  else if (req->accept_json) {
    resp->setJsonBody(g_api_swagger_json);
  }
  else {
    resp->setPlainBody(g_api_swagger_yaml);
  }
}

class ZoneData
{
public:
  ZoneData(HttpRequest* req) :
    zoneName(apiZoneIdToName((req)->parameters["id"])),
    dnssecKeeper(DNSSECKeeper{&backend})
  {
    try {
      if (!backend.getDomainInfo(zoneName, domainInfo)) {
        throw HttpNotFoundException();
      }
    }
    catch (const PDNSException& e) {
      throw HttpInternalServerErrorException("Could not retrieve Domain Info: " + e.reason);
    }
  }

  ZoneName zoneName;
  UeberBackend backend{};
  DNSSECKeeper dnssecKeeper;
  DomainInfo domainInfo{};
};

static void apiZoneMetadataGET(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};

  map<string, vector<string>> metas;
  Json::array document;

  if (!zoneData.backend.getAllDomainMetadata(zoneData.zoneName, metas)) {
    throw HttpNotFoundException();
  }

  for (const auto& meta : metas) {
    Json::array entries;
    for (const string& value : meta.second) {
      entries.emplace_back(value);
    }

    Json::object key{
      {"type", "Metadata"},
      {"kind", meta.first},
      {"metadata", entries}};
    document.emplace_back(key);
  }
  resp->setJsonBody(document);
}

static void apiZoneMetadataPOST(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};

  const auto& document = req->json();
  string kind;
  vector<string> entries;

  try {
    kind = stringFromJson(document, "kind");
  }
  catch (const JsonException&) {
    throw ApiException("kind is not specified or not a string");
  }

  if (!isValidMetadataKind(kind, false)) {
    throw ApiException("Unsupported metadata kind '" + kind + "'");
  }

  vector<string> vecMetadata;

  if (!zoneData.backend.getDomainMetadata(zoneData.zoneName, kind, vecMetadata)) {
    throw ApiException("Could not retrieve metadata entries for domain '" + zoneData.zoneName.toString() + "'");
  }

  const auto& metadata = document["metadata"];
  if (!metadata.is_array()) {
    throw ApiException("metadata is not specified or not an array");
  }

  for (const auto& value : metadata.array_items()) {
    if (!value.is_string()) {
      throw ApiException("metadata must be strings");
    }
    if (std::find(vecMetadata.cbegin(),
                  vecMetadata.cend(),
                  value.string_value())
        == vecMetadata.cend()) {
      vecMetadata.push_back(value.string_value());
    }
  }

  if (!zoneData.backend.setDomainMetadata(zoneData.zoneName, kind, vecMetadata)) {
    throw ApiException("Could not update metadata entries for domain '" + zoneData.zoneName.toString() + "'");
  }

  DNSSECKeeper::clearMetaCache(zoneData.zoneName);

  Json::array respMetadata;
  for (const string& value : vecMetadata) {
    respMetadata.emplace_back(value);
  }

  Json::object key{
    {"type", "Metadata"},
    {"kind", document["kind"]},
    {"metadata", respMetadata}};

  resp->status = 201;
  resp->setJsonBody(key);
}

static void apiZoneMetadataKindGET(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};

  string kind = req->parameters["kind"];

  vector<string> metadata;
  Json::object document;
  Json::array entries;

  if (!zoneData.backend.getDomainMetadata(zoneData.zoneName, kind, metadata)) {
    throw HttpNotFoundException();
  }
  if (!isValidMetadataKind(kind, true)) {
    throw ApiException("Unsupported metadata kind '" + kind + "'");
  }

  document["type"] = "Metadata";
  document["kind"] = kind;

  for (const string& value : metadata) {
    entries.emplace_back(value);
  }

  document["metadata"] = entries;
  resp->setJsonBody(document);
}

static void apiZoneMetadataKindPUT(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};

  string kind = req->parameters["kind"];

  const auto& document = req->json();

  if (!isValidMetadataKind(kind, false)) {
    throw ApiException("Unsupported metadata kind '" + kind + "'");
  }

  vector<string> vecMetadata;
  const auto& metadata = document["metadata"];
  if (!metadata.is_array()) {
    throw ApiException("metadata is not specified or not an array");
  }
  for (const auto& value : metadata.array_items()) {
    if (!value.is_string()) {
      throw ApiException("metadata must be strings");
    }
    vecMetadata.push_back(value.string_value());
  }

  if (!zoneData.backend.setDomainMetadata(zoneData.zoneName, kind, vecMetadata)) {
    throw ApiException("Could not update metadata entries for domain '" + zoneData.zoneName.toString() + "'");
  }

  DNSSECKeeper::clearMetaCache(zoneData.zoneName);

  Json::object key{
    {"type", "Metadata"},
    {"kind", kind},
    {"metadata", metadata}};

  resp->setJsonBody(key);
}

static void apiZoneMetadataKindDELETE(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};

  const string& kind = req->parameters["kind"];
  if (!isValidMetadataKind(kind, false)) {
    throw ApiException("Unsupported metadata kind '" + kind + "'");
  }

  vector<string> metadata; // an empty vector will do it
  if (!zoneData.backend.setDomainMetadata(zoneData.zoneName, kind, metadata)) {
    throw ApiException("Could not delete metadata for domain '" + zoneData.zoneName.toString() + "' (" + kind + ")");
  }

  DNSSECKeeper::clearMetaCache(zoneData.zoneName);
  resp->status = 204;
}

// Throws 404 if the key with inquireKeyId does not exist
static void apiZoneCryptoKeysCheckKeyExists(const ZoneName& zonename, int inquireKeyId, DNSSECKeeper* dnssecKeeper)
{
  DNSSECKeeper::keyset_t keyset = dnssecKeeper->getKeys(zonename, false);
  bool found = false;
  for (const auto& value : keyset) {
    if (value.second.id == (unsigned)inquireKeyId) {
      found = true;
      break;
    }
  }
  if (!found) {
    throw HttpNotFoundException();
  }
}

static inline int getInquireKeyId(HttpRequest* req, const ZoneName& zonename, DNSSECKeeper* dnsseckeeper)
{
  int inquireKeyId = -1;
  if (req->parameters.count("key_id") == 1) {
    inquireKeyId = std::stoi(req->parameters["key_id"]);
    apiZoneCryptoKeysCheckKeyExists(zonename, inquireKeyId, dnsseckeeper);
  }
  return inquireKeyId;
}

static void apiZoneCryptokeysExport(const ZoneName& zonename, int64_t inquireKeyId, HttpResponse* resp, DNSSECKeeper* dnssec_dk)
{
  DNSSECKeeper::keyset_t keyset = dnssec_dk->getKeys(zonename, false);

  bool inquireSingleKey = inquireKeyId >= 0;

  Json::array doc;
  for (const auto& value : keyset) {
    if (inquireSingleKey && (unsigned)inquireKeyId != value.second.id) {
      continue;
    }

    string keyType;
    switch (value.second.keyType) {
    case DNSSECKeeper::KSK:
      keyType = "ksk";
      break;
    case DNSSECKeeper::ZSK:
      keyType = "zsk";
      break;
    case DNSSECKeeper::CSK:
      keyType = "csk";
      break;
    }

    Json::object key{
      {"type", "Cryptokey"},
      {"id", static_cast<int>(value.second.id)},
      {"active", value.second.active},
      {"published", value.second.published},
      {"keytype", keyType},
      {"flags", static_cast<uint16_t>(value.first.getFlags())},
      {"dnskey", value.first.getDNSKEY().getZoneRepresentation()},
      {"algorithm", DNSSECKeeper::algorithm2name(value.first.getAlgorithm())},
      {"bits", value.first.getKey()->getBits()}};

    string publishCDS;
    dnssec_dk->getPublishCDS(zonename, publishCDS);

    vector<string> digestAlgos;
    stringtok(digestAlgos, publishCDS, ", ");

    std::set<unsigned int> CDSalgos;
    for (auto const& digestAlgo : digestAlgos) {
      CDSalgos.insert(pdns::checked_stoi<unsigned int>(digestAlgo));
    }

    if (value.second.keyType == DNSSECKeeper::KSK || value.second.keyType == DNSSECKeeper::CSK) {
      Json::array cdses;
      Json::array dses;
      for (const uint8_t keyid : {DNSSECKeeper::DIGEST_SHA256, DNSSECKeeper::DIGEST_SHA384}) {
        try {
          string dsRecordContent = makeDSFromDNSKey(zonename.operator const DNSName&(), value.first.getDNSKEY(), keyid).getZoneRepresentation();

          dses.emplace_back(dsRecordContent);

          if (CDSalgos.count(keyid) != 0) {
            cdses.emplace_back(dsRecordContent);
          }
        }
        catch (...) {
        }
      }

      key["ds"] = dses;

      if (!cdses.empty()) {
        key["cds"] = cdses;
      }
    }

    if (inquireSingleKey) {
      key["privatekey"] = value.first.getKey()->convertToISC();
      resp->setJsonBody(key);
      return;
    }
    doc.emplace_back(key);
  }

  if (inquireSingleKey) {
    // we came here because we couldn't find the requested key.
    throw HttpNotFoundException();
  }
  resp->setJsonBody(doc);
}

static void apiZoneCryptokeysGET(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};
  const auto inquireKeyId = getInquireKeyId(req, zoneData.zoneName, &zoneData.dnssecKeeper);

  apiZoneCryptokeysExport(zoneData.zoneName, inquireKeyId, resp, &zoneData.dnssecKeeper);
}

// Common processing following a crypto keys operation which caused keys to be
// added or removed. If this is a primary zone, we need to increase its
// serial if configured to do so.
static void apiZoneCryptokeysPostProcessing(ZoneData& zoneData)
{
  // We do not check using isPrimaryType() because we also want to include
  // DomainInfo::Native here.
  if (!zoneData.domainInfo.isSecondaryType()) {
    UeberBackend backend;
    SOAData soaData;
    bool zone_disabled = !backend.getSOAUncached(zoneData.zoneName, soaData);

    if (!zone_disabled) {
      string soa_edit_api_kind;
      string soa_edit_kind;

      zoneData.domainInfo.backend->getDomainMetadataOne(zoneData.zoneName, "SOA-EDIT-API", soa_edit_api_kind);
      zoneData.domainInfo.backend->getDomainMetadataOne(zoneData.zoneName, "SOA-EDIT", soa_edit_kind);
      zoneData.domainInfo.backend->startTransaction(zoneData.zoneName, UnknownDomainID);
      updateZoneSerial(zoneData.domainInfo, soaData, soa_edit_api_kind, soa_edit_kind);
      zoneData.domainInfo.backend->commitTransaction();
    }
  }
}

/*
 * This method handles DELETE requests for URL /api/v1/servers/:server_id/zones/:zone_name/cryptokeys/:cryptokey_id .
 * It deletes a key from :zone_name specified by :cryptokey_id.
 * Server Answers:
 * Case 1: the backend returns true on removal. This means the key is gone.
 *      The server returns 204 No Content, no body.
 * Case 2: the backend returns false on removal. An error occurred.
 *      The server returns 422 Unprocessable Entity with message "Could not DELETE :cryptokey_id".
 * Case 3: the key or zone does not exist.
 *      The server returns 404 Not Found
 * */
static void apiZoneCryptokeysDELETE(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};
  const auto inquireKeyId = getInquireKeyId(req, zoneData.zoneName, &zoneData.dnssecKeeper);

  if (inquireKeyId == -1) {
    throw HttpBadRequestException();
  }

  if (zoneData.dnssecKeeper.removeKey(zoneData.zoneName, inquireKeyId)) {
    apiZoneCryptokeysPostProcessing(zoneData);
    resp->body = "";
    resp->status = 204;
  }
  else {
    resp->setErrorResult("Could not DELETE " + req->parameters["key_id"], 422);
  }
}

/*
 * This method adds a key to a zone by generate it or content parameter.
 * Parameter:
 *  {
 *  "privatekey" : "key The format used is compatible with BIND and NSD/LDNS" <string>
 *  "keytype" : "ksk|zsk" <string>
 *  "active"  : "true|false" <value>
 *  "algorithm" : "key generation algorithm name as default"<string> https://doc.powerdns.com/md/authoritative/dnssec/#supported-algorithms
 *  "bits" : number of bits <int>
 *  }
 *
 * Response:
 *  Case 1: keytype isn't ksk|zsk
 *    The server returns 422 Unprocessable Entity {"error" : "Invalid keytype 'keytype'"}
 *  Case 2: 'bits' must be a positive integer value.
 *    The server returns 422 Unprocessable Entity {"error" : "'bits' must be a positive integer value."}
 *  Case 3: The "algorithm" isn't supported
 *    The server returns 422 Unprocessable Entity {"error" : "Unknown algorithm: 'algo'"}
 *  Case 4: Algorithm <= 10 and no bits were passed
 *    The server returns 422 Unprocessable Entity {"error" : "Creating an algorithm algo key requires the size (in bits) to be passed"}
 *  Case 5: The wrong keysize was passed
 *    The server returns 422 Unprocessable Entity {"error" : "The algorithm does not support the given bit size."}
 *  Case 6: If the server cant guess the keysize
 *    The server returns 422 Unprocessable Entity {"error" : "Can not guess key size for algorithm"}
 *  Case 7: The key-creation failed
 *    The server returns 422 Unprocessable Entity {"error" : "Adding key failed, perhaps DNSSEC not enabled in configuration?"}
 *  Case 8: The key in content has the wrong format
 *    The server returns 422 Unprocessable Entity {"error" : "Key could not be parsed. Make sure your key format is correct."}
 *  Case 9: The wrong combination of fields is submitted
 *    The server returns 422 Unprocessable Entity {"error" : "Either you submit just the 'content' field or you leave 'content' empty and submit the other fields."}
 *  Case 10: No content and everything was fine
 *    The server returns 201 Created and all public data about the new cryptokey
 *  Case 11: With specified content
 *    The server returns 201 Created and all public data about the added cryptokey
 */

static void apiZoneCryptokeysPOST(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};

  const auto& document = req->json();
  string privatekey_fieldname = "privatekey";
  auto privatekey = document["privatekey"];
  if (privatekey.is_null()) {
    // Fallback to the old "content" behaviour
    privatekey = document["content"];
    privatekey_fieldname = "content";
  }
  bool active = boolFromJson(document, "active", false);
  bool published = boolFromJson(document, "published", true);
  bool keyOrZone = false;

  if (stringFromJson(document, "keytype") == "ksk" || stringFromJson(document, "keytype") == "csk") {
    keyOrZone = true;
  }
  else if (stringFromJson(document, "keytype") == "zsk") {
    keyOrZone = false;
  }
  else {
    throw ApiException("Invalid keytype " + stringFromJson(document, "keytype"));
  }

  int64_t insertedId = -1;

  if (privatekey.is_null()) {
    int bits = keyOrZone ? ::arg().asNum("default-ksk-size") : ::arg().asNum("default-zsk-size");
    auto docbits = document["bits"];
    if (!docbits.is_null()) {
      if (!docbits.is_number() || (fmod(docbits.number_value(), 1.0) != 0) || docbits.int_value() < 0) {
        throw ApiException("'bits' must be a positive integer value");
      }

      bits = docbits.int_value();
    }
    int algorithm = DNSSECKeeper::shorthand2algorithm(keyOrZone ? ::arg()["default-ksk-algorithm"] : ::arg()["default-zsk-algorithm"]);
    const auto& providedAlgo = document["algorithm"];
    if (providedAlgo.is_string()) {
      algorithm = DNSSECKeeper::shorthand2algorithm(providedAlgo.string_value());
      if (algorithm == -1) {
        throw ApiException("Unknown algorithm: " + providedAlgo.string_value());
      }
    }
    else if (providedAlgo.is_number()) {
      algorithm = providedAlgo.int_value();
    }
    else if (!providedAlgo.is_null()) {
      throw ApiException("Unknown algorithm: " + providedAlgo.string_value());
    }

    try {
      if (!zoneData.dnssecKeeper.addKey(zoneData.zoneName, keyOrZone, algorithm, insertedId, bits, active, published)) {
        throw ApiException("Adding key failed, perhaps DNSSEC not enabled in configuration?");
      }
    }
    catch (std::runtime_error& error) {
      throw ApiException(error.what());
    }
    if (insertedId < 0) {
      throw ApiException("Adding key failed, perhaps DNSSEC not enabled in configuration?");
    }
  }
  else if (document["bits"].is_null() && document["algorithm"].is_null()) {
    const auto& keyData = stringFromJson(document, privatekey_fieldname);
    DNSKEYRecordContent dkrc;
    DNSSECPrivateKey dpk;
    try {
      shared_ptr<DNSCryptoKeyEngine> dke(DNSCryptoKeyEngine::makeFromISCString(dkrc, keyData));
      uint16_t flags = 0;
      if (keyOrZone) {
        flags = 257;
      }
      else {
        flags = 256;
      }

      uint8_t algorithm = dkrc.d_algorithm;
      // TODO remove in 4.2.0
      if (algorithm == DNSSECKeeper::RSASHA1NSEC3SHA1) {
        algorithm = DNSSECKeeper::RSASHA1;
      }
      dpk.setKey(dke, flags, algorithm);
    }
    catch (std::runtime_error& error) {
      throw ApiException("Key could not be parsed. Make sure your key format is correct.");
    }
    try {
      if (!zoneData.dnssecKeeper.addKey(zoneData.zoneName, dpk, insertedId, active, published)) {
        throw ApiException("Adding key failed, perhaps DNSSEC not enabled in configuration?");
      }
    }
    catch (std::runtime_error& error) {
      throw ApiException(error.what());
    }
    if (insertedId < 0) {
      throw ApiException("Adding key failed, perhaps DNSSEC not enabled in configuration?");
    }
  }
  else {
    throw ApiException("Either you submit just the 'privatekey' field or you leave 'privatekey' empty and submit the other fields.");
  }
  apiZoneCryptokeysPostProcessing(zoneData);
  apiZoneCryptokeysExport(zoneData.zoneName, insertedId, resp, &zoneData.dnssecKeeper);
  resp->status = 201;
}

/*
 * This method handles PUT (execute) requests for URL /api/v1/servers/:server_id/zones/:zone_name/cryptokeys/:cryptokey_id .
 * It de/activates a key from :zone_name specified by :cryptokey_id.
 * Server Answers:
 * Case 1: invalid JSON data
 *      The server returns 400 Bad Request
 * Case 2: the backend returns true on de/activation. This means the key is de/active.
 *      The server returns 204 No Content
 * Case 3: the backend returns false on de/activation. An error occurred.
 *      The sever returns 422 Unprocessable Entity with message "Could not de/activate Key: :cryptokey_id in Zone: :zone_name"
 * */
static void apiZoneCryptokeysPUT(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};
  const auto inquireKeyId = getInquireKeyId(req, zoneData.zoneName, &zoneData.dnssecKeeper);

  if (inquireKeyId == -1) {
    throw HttpBadRequestException();
  }
  // throws an exception if the Body is empty
  const auto& document = req->json();
  // throws an exception if the key does not exist or is not a bool
  bool active = boolFromJson(document, "active");
  bool published = boolFromJson(document, "published", true);
  if (active) {
    if (!zoneData.dnssecKeeper.activateKey(zoneData.zoneName, inquireKeyId)) {
      resp->setErrorResult("Could not activate Key: " + req->parameters["key_id"] + " in Zone: " + zoneData.zoneName.toString(), 422);
      return;
    }
  }
  else {
    if (!zoneData.dnssecKeeper.deactivateKey(zoneData.zoneName, inquireKeyId)) {
      resp->setErrorResult("Could not deactivate Key: " + req->parameters["key_id"] + " in Zone: " + zoneData.zoneName.toString(), 422);
      return;
    }
  }

  if (published) {
    if (!zoneData.dnssecKeeper.publishKey(zoneData.zoneName, inquireKeyId)) {
      resp->setErrorResult("Could not publish Key: " + req->parameters["key_id"] + " in Zone: " + zoneData.zoneName.toString(), 422);
      return;
    }
  }
  else {
    if (!zoneData.dnssecKeeper.unpublishKey(zoneData.zoneName, inquireKeyId)) {
      resp->setErrorResult("Could not unpublish Key: " + req->parameters["key_id"] + " in Zone: " + zoneData.zoneName.toString(), 422);
      return;
    }
  }

  apiZoneCryptokeysPostProcessing(zoneData);
  resp->body = "";
  resp->status = 204;
}

static void gatherRecordsFromZone(const std::string& zonestring, vector<DNSResourceRecord>& new_records, const ZoneName& zonename)
{
  DNSResourceRecord resourceRecord;
  vector<string> zonedata;
  stringtok(zonedata, zonestring, "\r\n");

  ZoneParserTNG zpt(zonedata, zonename);
  zpt.setMaxGenerateSteps(::arg().asNum("max-generate-steps"));
  zpt.setMaxIncludes(::arg().asNum("max-include-depth"));

  bool seenSOA = false;

  string comment = "Imported via the API";

  try {
    while (zpt.get(resourceRecord, &comment)) {
      if (seenSOA && resourceRecord.qtype.getCode() == QType::SOA) {
        continue;
      }
      if (resourceRecord.qtype.getCode() == QType::SOA) {
        seenSOA = true;
      }
      validateGatheredRRType(resourceRecord);

      new_records.push_back(resourceRecord);
    }
  }
  catch (std::exception& ae) {
    throw ApiException("An error occurred while parsing the zonedata: " + string(ae.what()));
  }
}

static bool areUnderscoresAllowed(const ZoneName& zonename, DNSBackend& backend)
{
  string underscores{};
  backend.getDomainMetadataOne(zonename, "RFC1123-CONFORMANCE", underscores);
  // Metadata absent implies strict conformance
  return underscores == "0";
}

// Wrapper around checkRRSet; returns true if all checks successful, false if
// not, in which case the response body and status have been filled up.
static bool checkNewRecords(HttpResponse* resp, vector<DNSResourceRecord>& records, const ZoneName& zone, Check::RRSetFlags flags)
{
  std::vector<std::pair<DNSResourceRecord, string>> errors;

  Check::checkRRSet({}, records, zone, flags, errors);
  if (errors.empty()) {
    return true;
  }

  Json::array errs;
  for (const auto& error : errors) {
    const auto& [rec, why] = error;
    errs.emplace_back(std::string{"RRset "} + rec.qname.toString() + " IN " + rec.qtype.toString() + ": " + why);
  }

  Json::object body;
  if (errs.size() == 1) {
    body["error"] = errs[0];
  }
  else {
    body["error"] = "Multiple errors found in RRset";
    body["errors"] = errs;
  }
  resp->setJsonBody(body);
  resp->status = 422;
  return false;
}

static void checkTSIGKey(UeberBackend& backend, const DNSName& keyname, const DNSName& algo, const string& content)
{
  DNSName algoFromDB;
  string contentFromDB;
  if (backend.getTSIGKey(keyname, algoFromDB, contentFromDB)) {
    throw HttpConflictException("A TSIG key with the name '" + keyname.toLogString() + "' already exists");
  }

  TSIGHashEnum the{};
  if (!getTSIGHashEnum(algo, the)) {
    throw ApiException("Unknown TSIG algorithm: " + algo.toLogString());
  }

  string b64out;
  if (B64Decode(content, b64out) == -1) {
    throw ApiException("TSIG content '" + content + "' cannot be base64-decoded");
  }
}

static Json::object makeJSONTSIGKey(const DNSName& keyname, const DNSName& algo, const string& content)
{
  Json::object tsigkey = {
    {"name", keyname.toStringNoDot()},
    {"id", apiNameToId(keyname.toString())},
    {"algorithm", algo.toStringNoDot()},
    {"key", content},
    {"type", "TSIGKey"}};
  return tsigkey;
}

static Json::object makeJSONTSIGKey(const struct TSIGKey& key, bool doContent = true)
{
  return makeJSONTSIGKey(key.name, key.algorithm, doContent ? key.key : "");
}

static void apiServerTSIGKeysGET(HttpRequest* /* req */, HttpResponse* resp)
{
  UeberBackend backend;
  vector<struct TSIGKey> keys;

  if (!backend.getTSIGKeys(keys)) {
    throw HttpInternalServerErrorException("Unable to retrieve TSIG keys");
  }

  Json::array doc;

  for (const auto& key : keys) {
    doc.emplace_back(makeJSONTSIGKey(key, false));
  }
  resp->setJsonBody(doc);
}

static void apiServerTSIGKeysPOST(HttpRequest* req, HttpResponse* resp)
{
  UeberBackend backend;
  const auto& document = req->json();
  DNSName keyname(stringFromJson(document, "name"));
  DNSName algo(stringFromJson(document, "algorithm"));
  string content = document["key"].string_value();

  if (content.empty()) {
    try {
      content = makeTSIGKey(algo);
    }
    catch (const PDNSException& exc) {
      throw HttpBadRequestException(exc.reason);
    }
  }

  // Will throw an ApiException or HttpConflictException on error
  checkTSIGKey(backend, keyname, algo, content);

  if (!backend.setTSIGKey(keyname, algo, content)) {
    throw HttpInternalServerErrorException("Unable to add TSIG key");
  }

  resp->status = 201;
  resp->setJsonBody(makeJSONTSIGKey(keyname, algo, content));
}

class TSIGKeyData
{
public:
  TSIGKeyData(HttpRequest* req) :
    keyName(apiZoneIdToName(req->parameters["id"]).operator const DNSName&())
  {
    try {
      if (!backend.getTSIGKey(keyName, algo, content)) {
        throw HttpNotFoundException("TSIG key with name '" + keyName.toLogString() + "' not found");
      }
    }
    catch (const PDNSException& e) {
      throw HttpInternalServerErrorException("Could not retrieve Domain Info: " + e.reason);
    }

    tsigKey.name = keyName;
    tsigKey.algorithm = algo;
    tsigKey.key = std::move(content);
  }

  UeberBackend backend;
  DNSName keyName;
  DNSName algo;
  string content;
  struct TSIGKey tsigKey;
};

static void apiServerTSIGKeyDetailGET(HttpRequest* req, HttpResponse* resp)
{
  TSIGKeyData tsigKeyData{req};

  resp->setJsonBody(makeJSONTSIGKey(tsigKeyData.tsigKey));
}

static void apiServerTSIGKeyDetailPUT(HttpRequest* req, HttpResponse* resp)
{
  TSIGKeyData tsigKeyData{req};

  const auto& document = req->json();

  if (document["name"].is_string()) {
    tsigKeyData.tsigKey.name = DNSName(document["name"].string_value());
  }
  if (document["algorithm"].is_string()) {
    tsigKeyData.tsigKey.algorithm = DNSName(document["algorithm"].string_value());

    TSIGHashEnum the{};
    if (!getTSIGHashEnum(tsigKeyData.tsigKey.algorithm, the)) {
      throw ApiException("Unknown TSIG algorithm: " + tsigKeyData.tsigKey.algorithm.toLogString());
    }
  }
  if (document["key"].is_string()) {
    string new_content = document["key"].string_value();
    string decoded;
    if (B64Decode(new_content, decoded) == -1) {
      throw ApiException("Can not base64 decode key content '" + new_content + "'");
    }
    tsigKeyData.tsigKey.key = std::move(new_content);
  }
  if (!tsigKeyData.backend.setTSIGKey(tsigKeyData.tsigKey.name, tsigKeyData.tsigKey.algorithm, tsigKeyData.tsigKey.key)) {
    throw HttpInternalServerErrorException("Unable to save TSIG Key");
  }
  if (tsigKeyData.tsigKey.name != tsigKeyData.keyName) {
    // Remove the old key
    if (!tsigKeyData.backend.deleteTSIGKey(tsigKeyData.keyName)) {
      throw HttpInternalServerErrorException("Unable to remove TSIG key '" + tsigKeyData.keyName.toStringNoDot() + "'");
    }
  }
  resp->setJsonBody(makeJSONTSIGKey(tsigKeyData.tsigKey));
}

static void apiServerTSIGKeyDetailDELETE(HttpRequest* req, HttpResponse* resp)
{
  TSIGKeyData tsigKeyData{req};
  if (!tsigKeyData.backend.deleteTSIGKey(tsigKeyData.keyName)) {
    throw HttpInternalServerErrorException("Unable to remove TSIG key '" + tsigKeyData.keyName.toStringNoDot() + "'");
  }
  resp->body = "";
  resp->status = 204;
}

static void apiServerAutoprimaryDetailDELETE(HttpRequest* req, HttpResponse* resp)
{
  UeberBackend backend;
  const AutoPrimary& primary{req->parameters["ip"], req->parameters["nameserver"], ""};
  if (!backend.autoPrimaryRemove(primary)) {
    throw HttpInternalServerErrorException("Cannot find backend with autoprimary feature");
  }
  resp->body = "";
  resp->status = 204;
}

static void apiServerAutoprimariesGET(HttpRequest* /* req */, HttpResponse* resp)
{
  UeberBackend backend;

  std::vector<AutoPrimary> primaries;
  if (!backend.autoPrimariesList(primaries)) {
    throw HttpInternalServerErrorException("Unable to retrieve autoprimaries");
  }
  Json::array doc;
  for (const auto& primary : primaries) {
    const Json::object obj = {
      {"ip", primary.ip},
      {"nameserver", primary.nameserver},
      {"account", primary.account}};
    doc.emplace_back(obj);
  }
  resp->setJsonBody(doc);
}

static void apiServerAutoprimariesPOST(HttpRequest* req, HttpResponse* resp)
{
  UeberBackend backend;

  const auto& document = req->json();

  AutoPrimary primary(stringFromJson(document, "ip"), stringFromJson(document, "nameserver"), "");

  if (document["account"].is_string()) {
    primary.account = document["account"].string_value();
  }

  if (primary.ip.empty() or primary.nameserver.empty()) {
    throw ApiException("ip and nameserver fields must be filled");
  }
  if (!backend.autoPrimaryAdd(primary)) {
    throw HttpInternalServerErrorException("Cannot find backend with autoprimary feature");
  }
  resp->body = "";
  resp->status = 201;
}

// create new zone
static void apiServerZonesPOST(HttpRequest* req, HttpResponse* resp)
{
  UeberBackend backend;
  DNSSECKeeper dnssecKeeper(&backend);
  DomainInfo domainInfo;
  const auto& document = req->json();
  ZoneName zonename = apiNameToZoneName(stringFromJson(document, "name"));
  apiCheckNameAllowedCharacters(zonename.toString());
  zonename.makeUsLowerCase();

  bool exists = backend.getDomainInfo(zonename, domainInfo);
  if (exists) {
    throw HttpConflictException();
  }

  std::optional<DomainInfo::DomainKind> kind;
  std::optional<vector<ComboAddress>> primaries;
  std::optional<ZoneName> catalog;
  std::optional<string> account;
  extractDomainInfoFromDocument(document, kind, primaries, catalog, account);

  // validate 'kind' is set
  if (!kind) {
    throw JsonException("Key 'kind' not present or not a String");
  }
  DomainInfo::DomainKind zonekind = *kind;

  string zonestring = document["zone"].string_value();
  auto rrsets = document["rrsets"];
  if (rrsets.is_array() && !zonestring.empty()) {
    throw ApiException("You cannot give rrsets AND zone data as text");
  }

  const auto& nameservers = document["nameservers"];
  if (!nameservers.is_null() && !nameservers.is_array() && zonekind != DomainInfo::Secondary && zonekind != DomainInfo::Consumer) {
    throw ApiException("Nameservers is not a list");
  }

  // if records/comments are given, load and check them
  bool have_soa = false;
  bool have_zone_ns = false;
  vector<DNSResourceRecord> new_records;
  vector<Comment> new_comments;

  try {
    if (rrsets.is_array()) {
      for (const auto& rrset : rrsets.array_items()) {
        DNSName qname = apiNameToDNSName(stringFromJson(rrset, "name"));
        apiCheckQNameAllowedCharacters(qname.toString());
        QType qtype;
        qtype = stringFromJson(rrset, "type");
        if (qtype.getCode() == 0) {
          throw ApiException("RRset " + qname.toString() + " IN " + stringFromJson(rrset, "type") + ": unknown type given");
        }
        if (rrset["records"].is_array()) {
          uint32_t ttl = uintFromJson(rrset, "ttl");
          gatherRecords(rrset, qname, qtype, ttl, new_records);
        }
        if (rrset["comments"].is_array()) {
          gatherComments(rrset, qname, qtype, new_comments);
        }
      }
    }
    else if (!zonestring.empty()) {
      gatherRecordsFromZone(zonestring, new_records, zonename);
    }
  }
  catch (const JsonException& exc) {
    throw ApiException("New RRsets are invalid: " + string(exc.what()));
  }

  if (zonekind == DomainInfo::Consumer && !new_records.empty()) {
    throw ApiException("Zone data MUST NOT be given for Consumer zones");
  }

  for (auto& resourceRecord : new_records) {
    resourceRecord.qname.makeUsLowerCase();
    if (!resourceRecord.qname.isPartOf(zonename)) {
      throw ApiException("RRset " + resourceRecord.qname.toString() + " IN " + resourceRecord.qtype.toString() + ": Name is out of zone");
    }

    apiCheckQNameAllowedCharacters(resourceRecord.qname.toString());

    if (resourceRecord.qtype.getCode() == QType::SOA && resourceRecord.qname == zonename.operator const DNSName&()) {
      have_soa = true;
    }
    if (resourceRecord.qtype.getCode() == QType::NS && resourceRecord.qname == zonename.operator const DNSName&()) {
      have_zone_ns = true;
    }
  }

  // synthesize RRs as needed
  DNSResourceRecord autorr;
  autorr.qname = zonename.operator const DNSName&();
  autorr.auth = true;
  autorr.ttl = ::arg().asNum("default-ttl");

  if (!have_soa && zonekind != DomainInfo::Secondary && zonekind != DomainInfo::Consumer) {
    // synthesize a SOA record so the zone "really" exists
    string soa = ::arg()["default-soa-content"];
    boost::replace_all(soa, "@", zonename.operator const DNSName&().toStringNoDot());
    SOAData soaData;
    fillSOAData(soa, soaData);
    soaData.serial = document["serial"].int_value();
    autorr.qtype = QType::SOA;
    autorr.content = makeSOAContent(soaData)->getZoneRepresentation(true);
    // updateDomainSettingsFromDocument will apply SOA-EDIT-API as needed
    new_records.push_back(autorr);
  }

  // create NS records if nameservers are given
  for (const auto& value : nameservers.array_items()) {
    const string& nameserver = value.string_value();
    if (nameserver.empty()) {
      throw ApiException("Nameservers must be non-empty strings");
    }
    if (zonekind == DomainInfo::Consumer) {
      throw ApiException("Nameservers MUST NOT be given for Consumer zones");
    }
    if (!isCanonical(nameserver)) {
      throw ApiException("Nameserver is not canonical: '" + nameserver + "'");
    }
    try {
      // ensure the name parses
      autorr.content = DNSName(nameserver).toStringRootDot();
    }
    catch (...) {
      throw ApiException("Unable to parse DNS Name for NS '" + nameserver + "'");
    }
    autorr.qtype = QType::NS;
    new_records.push_back(autorr);
    if (have_zone_ns) {
      throw ApiException("Nameservers list MUST NOT be mixed with zone-level NS in rrsets");
    }
  }

  // Flags = 0, as new zones do not have RFC1123-CONFORMANCE metadata yet, and
  // all records use the same default ttl value.
  if (!checkNewRecords(resp, new_records, zonename, static_cast<Check::RRSetFlags>(0))) {
    return;
  }

  if (boolFromJson(document, "dnssec", false)) {
    checkDefaultDNSSECAlgos();

    if (document["nsec3param"].string_value().length() > 0) {
      NSEC3PARAMRecordContent ns3pr(document["nsec3param"].string_value());
      string error_msg;
      if (!dnssecKeeper.checkNSEC3PARAM(ns3pr, error_msg)) {
        throw ApiException("NSEC3PARAMs provided for zone '" + zonename.toString() + "' are invalid. " + error_msg);
      }
    }
  }

  // no going back after this
  if (!backend.createDomain(zonename, kind.value_or(DomainInfo::Native), primaries.value_or(vector<ComboAddress>()), account.value_or(""))) {
    throw ApiException("Creating domain '" + zonename.toString() + "' failed: backend refused");
  }

  if (!backend.getDomainInfo(zonename, domainInfo)) {
    throw ApiException("Creating domain '" + zonename.toString() + "' failed: lookup of domain ID failed");
  }

  domainInfo.backend->startTransaction(zonename, domainInfo.id);

  try {
    // will be overridden by updateDomainSettingsFromDocument, if given in document.
    const string defaultSOAEditAPI = ::arg()["default-soa-edit-api"];
    if (!defaultSOAEditAPI.empty()) {
      domainInfo.backend->setDomainMetadataOne(zonename, "SOA-EDIT-API", defaultSOAEditAPI);
    }

    for (auto& resourceRecord : new_records) {
      resourceRecord.domain_id = static_cast<int>(domainInfo.id);
      domainInfo.backend->feedRecord(resourceRecord, DNSName());
    }
    for (Comment& comment : new_comments) {
      comment.domain_id = static_cast<int>(domainInfo.id);
      if (!domainInfo.backend->feedComment(comment)) {
        throw ApiException("Hosting backend does not support editing comments.");
      }
    }

    updateDomainSettingsFromDocument(backend, domainInfo, zonename, document, !new_records.empty());

    if (!catalog && kind == DomainInfo::Primary) {
      const auto& defaultCatalog = ::arg()["default-catalog-zone"];
      if (!defaultCatalog.empty()) {
        domainInfo.backend->setCatalog(zonename, ZoneName(defaultCatalog));
      }
    }
  }
  catch (...) {
    domainInfo.backend->abortTransaction();
    throw;
  }

  domainInfo.backend->commitTransaction();

  g_zoneCache.add(zonename, static_cast<int>(domainInfo.id)); // make new zone visible

  fillZone(backend, zonename, resp, req);
  resp->status = 201;
}

// list known zones
static void apiServerZonesGET(HttpRequest* req, HttpResponse* resp)
{
  UeberBackend backend;
  DNSSECKeeper dnssecKeeper(&backend);
  vector<DomainInfo> domains;

  if (req->getvars.count("zone") != 0) {
    string zone = req->getvars["zone"];
    apiCheckNameAllowedCharacters(zone);
    ZoneName zonename = apiNameToZoneName(zone);
    zonename.makeUsLowerCase();
    DomainInfo domainInfo;
    if (backend.getDomainInfo(zonename, domainInfo)) {
      domains.push_back(std::move(domainInfo));
    }
  }
  else {
    try {
      backend.getAllDomains(&domains, true, true); // incl. serial and disabled
    }
    catch (const PDNSException& exception) {
      throw HttpInternalServerErrorException("Could not retrieve all domain information: " + exception.reason);
    }
  }

  bool with_dnssec = true;
  if (req->getvars.count("dnssec") != 0) {
    // can send ?dnssec=false to improve performance.
    string dnssec_flag = req->getvars["dnssec"];
    if (dnssec_flag == "false") {
      with_dnssec = false;
    }
  }

  Json::array doc;
  doc.reserve(domains.size());
  for (const DomainInfo& domainInfo : domains) {
    doc.emplace_back(getZoneInfo(domainInfo, with_dnssec ? &dnssecKeeper : nullptr));
  }
  resp->setJsonBody(doc);
}

static void apiServerZoneDetailPUT(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};

  // update domain contents and/or settings
  const auto& document = req->json();

  auto rrsets = document["rrsets"];
  bool zoneWasModified = false;
  DomainInfo::DomainKind newKind = zoneData.domainInfo.kind;
  if (document["kind"].is_string()) {
    newKind = DomainInfo::stringToKind(stringFromJson(document, "kind"));
  }

  // if records/comments are given, load, check and insert them
  if (rrsets.is_array()) {
    zoneWasModified = true;
    bool haveSoa = false;
    string soaEditApiKind;
    string soaEditKind;
    zoneData.domainInfo.backend->getDomainMetadataOne(zoneData.zoneName, "SOA-EDIT-API", soaEditApiKind);
    zoneData.domainInfo.backend->getDomainMetadataOne(zoneData.zoneName, "SOA-EDIT", soaEditKind);

    vector<DNSResourceRecord> new_records;
    vector<Comment> new_comments;

    try {
      for (const auto& rrset : rrsets.array_items()) {
        DNSName qname = apiNameToDNSName(stringFromJson(rrset, "name"));
        apiCheckQNameAllowedCharacters(qname.toString());
        QType qtype;
        qtype = stringFromJson(rrset, "type");
        if (qtype.getCode() == 0) {
          throw ApiException("RRset " + qname.toString() + " IN " + stringFromJson(rrset, "type") + ": unknown type given");
        }
        if (rrset["records"].is_array()) {
          uint32_t ttl = uintFromJson(rrset, "ttl");
          gatherRecords(rrset, qname, qtype, ttl, new_records);
        }
        if (rrset["comments"].is_array()) {
          gatherComments(rrset, qname, qtype, new_comments);
        }
      }
    }
    catch (const JsonException& exc) {
      throw ApiException("New RRsets are invalid: " + string(exc.what()));
    }

    for (auto& resourceRecord : new_records) {
      resourceRecord.qname.makeUsLowerCase();
      if (!resourceRecord.qname.isPartOf(zoneData.zoneName)) {
        throw ApiException("RRset " + resourceRecord.qname.toString() + " IN " + resourceRecord.qtype.toString() + ": Name is out of zone");
      }
      apiCheckQNameAllowedCharacters(resourceRecord.qname.toString());

      if (resourceRecord.qtype.getCode() == QType::SOA && resourceRecord.qname == zoneData.zoneName.operator const DNSName&()) {
        haveSoa = true;
      }
    }

    if (!haveSoa && newKind != DomainInfo::Secondary && newKind != DomainInfo::Consumer) {
      // Require SOA if this is a primary zone.
      throw ApiException("Must give SOA record for zone when replacing all RR sets");
    }
    if (newKind == DomainInfo::Consumer && !new_records.empty()) {
      // Allow deleting all RRsets, just not modifying them.
      throw ApiException("Modifying RRsets in Consumer zones is unsupported");
    }

    bool allowUnderscores = areUnderscoresAllowed(zoneData.zoneName, *zoneData.domainInfo.backend);
    Check::RRSetFlags flags{Check::RRSET_CHECK_TTL};
    if (allowUnderscores) {
      flags = static_cast<Check::RRSetFlags>(flags | Check::RRSET_ALLOW_UNDERSCORES);
    }
    if (!checkNewRecords(resp, new_records, zoneData.zoneName, flags)) {
      return;
    }

    zoneData.domainInfo.backend->startTransaction(zoneData.zoneName, zoneData.domainInfo.id);
    for (auto& resourceRecord : new_records) {
      resourceRecord.domain_id = static_cast<int>(zoneData.domainInfo.id);
      zoneData.domainInfo.backend->feedRecord(resourceRecord, DNSName());
    }
    for (Comment& comment : new_comments) {
      comment.domain_id = static_cast<int>(zoneData.domainInfo.id);
      zoneData.domainInfo.backend->feedComment(comment);
    }

    if (!haveSoa && (newKind == DomainInfo::Secondary || newKind == DomainInfo::Consumer)) {
      zoneData.domainInfo.backend->setStale(zoneData.domainInfo.id);
    }
  }
  else {
    // avoid deleting current zone contents
    zoneData.domainInfo.backend->startTransaction(zoneData.zoneName, UnknownDomainID);
  }

  // updateDomainSettingsFromDocument will rectify the zone and update SOA serial.
  updateDomainSettingsFromDocument(zoneData.backend, zoneData.domainInfo, zoneData.zoneName, document, zoneWasModified);
  zoneData.domainInfo.backend->commitTransaction();

  purgeAuthCaches(zoneData.zoneName.operator const DNSName&().toString() + "$");

  resp->body = "";
  resp->status = 204; // No Content, but indicate success
}

static void apiServerZoneDetailDELETE(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};

  // delete domain

  zoneData.domainInfo.backend->startTransaction(zoneData.zoneName, UnknownDomainID);
  try {
    if (!zoneData.domainInfo.backend->deleteDomain(zoneData.zoneName)) {
      throw ApiException("Deleting domain '" + zoneData.zoneName.toString() + "' failed: backend delete failed/unsupported");
    }

    zoneData.domainInfo.backend->commitTransaction();

    g_zoneCache.remove(zoneData.zoneName);
  }
  catch (...) {
    zoneData.domainInfo.backend->abortTransaction();
    throw;
  }

  // clear caches
  DNSSECKeeper::clearCaches(zoneData.zoneName);
  purgeAuthCaches(zoneData.zoneName.operator const DNSName&().toString() + "$");

  // empty body on success
  resp->body = "";
  resp->status = 204; // No Content: declare that the zone is gone now
}

static void apiServerZoneDetailPATCH(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};
  Json document = req->json();

  auto rrsets = document["rrsets"];
  if (!rrsets.is_array()) {
    throw ApiException("No rrsets given in update request");
  }

  patchZone(zoneData.backend, zoneData.zoneName, zoneData.domainInfo, rrsets.array_items(), resp);
}

static void apiServerZoneDetailGET(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};
  fillZone(zoneData.backend, zoneData.zoneName, resp, req);
}

static void apiServerZoneExport(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};

  ostringstream outputStringStream;

  DNSResourceRecord resourceRecord;
  SOAData soaData;
  zoneData.domainInfo.backend->list(zoneData.zoneName, static_cast<int>(zoneData.domainInfo.id));
  while (zoneData.domainInfo.backend->get(resourceRecord)) {
    if (resourceRecord.qtype.getCode() == 0) {
      continue; // skip empty non-terminals
    }

    std::string content;
    try {
      content = makeApiRecordContent(resourceRecord.qtype, resourceRecord.content);
    }
    catch (std::exception& e) {
      // makeApiRecordContent may throw an exception if the backend data
      // is not well-formed (e.g. corrupted bind zone file).
      // The exception gets caught here and rethrown as ApiException in
      // order to return a 422 error code with a (hopefully) useful error
      // message instead of a 500 error.
      throw ApiException("Ill-formed record contents found for " + resourceRecord.qname.toString() + ": " + e.what());
    }
    outputStringStream << resourceRecord.qname.toString() << "\t" << resourceRecord.ttl << "\t"
                       << "IN"
                       << "\t" << resourceRecord.qtype.toString() << "\t" << content << endl;
  }

  if (req->accept_json) {
    resp->setJsonBody(Json::object{{"zone", outputStringStream.str()}});
  }
  else {
    resp->headers["Content-Type"] = "text/plain; charset=us-ascii";
    resp->body = outputStringStream.str();
  }
}

static void apiServerZoneAxfrRetrieve(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};

  if (zoneData.domainInfo.primaries.empty()) {
    throw ApiException("Domain '" + zoneData.zoneName.toString() + "' is not a secondary domain (or has no primary defined)");
  }

  shuffle(zoneData.domainInfo.primaries.begin(), zoneData.domainInfo.primaries.end(), pdns::dns_random_engine());
  Communicator.addSuckRequest(zoneData.zoneName, zoneData.domainInfo.primaries.front(), SuckRequest::Api);
  resp->setSuccessResult("Added retrieval request for '" + zoneData.zoneName.toString() + "' from primary " + zoneData.domainInfo.primaries.front().toLogString());
}

static void apiServerZoneNotify(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};

  if (!Communicator.notifyDomain(zoneData.zoneName, &zoneData.backend)) {
    throw ApiException("Failed to add to the queue - see server log");
  }

  resp->setSuccessResult("Notification queued");
}

static void apiServerZoneRectify(HttpRequest* req, HttpResponse* resp)
{
  ZoneData zoneData{req};

  if (zoneData.dnssecKeeper.isPresigned(zoneData.zoneName)) {
    throw ApiException("Zone '" + zoneData.zoneName.toString() + "' is pre-signed, not rectifying.");
  }

  string error_msg;
  string info;
  if (!zoneData.dnssecKeeper.rectifyZone(zoneData.zoneName, error_msg, info, true)) {
    throw ApiException("Failed to rectify '" + zoneData.zoneName.toString() + "' " + error_msg);
  }

  resp->setSuccessResult("Rectified");
}

// The allowed values for the "changetype" field of a Json patch record.
enum changeType
{
  DELETE, // delete complete RRset
  REPLACE, // replace complete RRset
  PRUNE, // remove single record from RRset if found
  EXTEND // add single record to RRset if not found
};

// Validate the "changetype" field of a Json patch record.
// Returns the recognized operation.
// Throws an exception if unrecognized.
static changeType validateChangeType(const std::string& changetype)
{
  if (changetype == "DELETE") {
    return DELETE;
  }
  if (changetype == "REPLACE") {
    return REPLACE;
  }
  if (changetype == "PRUNE") {
    return PRUNE;
  }
  if (changetype == "EXTEND") {
    return EXTEND;
  }
  throw ApiException("Changetype '" + changetype + "' is not a valid value");
}

// Replace the rrset for `qname' in zone `zonename' with the contents of
// `new_records', making sure to remove no longer needed ENT entries, and
// also enforcing the exclusivity rules (at most one CNAME, DNAME and SOA,
// etc).
static void replaceZoneRecords(const DomainInfo& domainInfo, const ZoneName& zonename, vector<DNSResourceRecord>& new_records, const DNSName& qname, const QType qtype)
{
  bool ent_present = false;
  bool dname_seen = qtype == QType::DNAME;
  bool ns_seen = qtype == QType::NS;

  domainInfo.backend->APILookup(QType(QType::ANY), qname, static_cast<int>(domainInfo.id), false);
  DNSResourceRecord resourceRecord;
  while (domainInfo.backend->get(resourceRecord)) {
    if (resourceRecord.qtype.getCode() == QType::ENT) {
      ent_present = true;
      // that's fine, we will override it
      continue;
    }
    dname_seen |= resourceRecord.qtype == QType::DNAME;
    ns_seen |= resourceRecord.qtype == QType::NS;
    if (qtype.getCode() != resourceRecord.qtype.getCode()
        && (QType::exclusiveEntryTypes.count(qtype.getCode()) != 0
            || QType::exclusiveEntryTypes.count(resourceRecord.qtype.getCode()) != 0)) {
      // leave database handle in a consistent state
      domainInfo.backend->lookupEnd();
      throw ApiException("RRset " + qname.toString() + " IN " + qtype.toString() + ": Conflicts with pre-existing RRset");
    }
  }
  if (dname_seen && ns_seen && qname != zonename.operator const DNSName&()) {
    throw ApiException("RRset " + qname.toString() + " IN " + qtype.toString() + ": Cannot have both NS and DNAME except in zone apex");
  }
  if (!new_records.empty() && ent_present) {
    QType qt_ent{QType::ENT};
    if (!domainInfo.backend->replaceRRSet(domainInfo.id, qname, qt_ent, new_records)) {
      throw ApiException("Hosting backend does not support editing records.");
    }
  }
  if (!domainInfo.backend->replaceRRSet(domainInfo.id, qname, qtype, new_records)) {
    throw ApiException("Hosting backend does not support editing records.");
  }
}

// Parse the record name and type from a Json patch record.
static void parseRecordNameAndType(const Json& rrset, DNSName& qname, QType& qtype)
{
  qname = apiNameToDNSName(stringFromJson(rrset, "name"));
  apiCheckQNameAllowedCharacters(qname.toString());
  qtype = stringFromJson(rrset, "type");
  if (qtype.getCode() == QType::ENT) {
    throw ApiException("RRset " + qname.toString() + " IN " + stringFromJson(rrset, "type") + ": unknown type given");
  }
}

// The return value of the apply* functions below
enum applyResult
{
  SUCCESS, // successful and changes performed
  NOP, // successful but no changes needed
  ABORT // failed horribly, don't process anything further
};

// Apply a DELETE changetype.
static applyResult applyDelete(const DomainInfo& domainInfo, DNSName& qname, QType& qtype, bool returnRRset, std::vector<DNSResourceRecord>& rrset)
{
  // Delete all matching qname/qtype RRs (and implicitly, comments).
  if (!domainInfo.backend->replaceRRSet(domainInfo.id, qname, qtype, {})) {
    throw ApiException("Hosting backend does not support editing records.");
  }
  // Update RRset cache if needed
  if (returnRRset) {
    rrset.clear();
  }
  return SUCCESS;
}

// Struct gathering the SOA edition details, so as not to pass too many
// billions of parameters to applyReplace() below.
struct soaEditSettings
{
  bool edit_done{false};
  string edit_api_kind;
  string edit_kind;
};

// Apply a REPLACE changetype.
static applyResult applyReplace(const DomainInfo& domainInfo, const ZoneName& zonename, const Json& container, DNSName& qname, QType& qtype, bool allowUnderscores, soaEditSettings& soa, HttpResponse* resp, bool returnRRset, std::vector<DNSResourceRecord>& rrset)
{
  bool replace_records = container["records"].is_array();
  bool replace_comments = container["comments"].is_array();

  if (!replace_records && !replace_comments) {
    throw ApiException("No change for RRset " + qname.toString() + " IN " + qtype.toString());
  }

  vector<DNSResourceRecord> new_records;
  vector<Comment> new_comments;

  try {
    if (replace_records) {
      // ttl shouldn't be required if we don't get new records.
      uint32_t ttl = uintFromJson(container, "ttl");
      gatherRecords(container, qname, qtype, ttl, new_records);

      for (DNSResourceRecord& resourceRecord : new_records) {
        resourceRecord.domain_id = static_cast<int>(domainInfo.id);
        if (resourceRecord.qtype.getCode() == QType::SOA && resourceRecord.qname == zonename.operator const DNSName&()) {
          soa.edit_done = increaseSOARecord(resourceRecord, soa.edit_api_kind, soa.edit_kind, zonename);
        }
      }
      // All records use the same TTL, no need to check for discrepancy.
      Check::RRSetFlags flags{0};
      if (allowUnderscores) {
        flags = Check::RRSET_ALLOW_UNDERSCORES;
      }
      if (!checkNewRecords(resp, new_records, zonename, flags)) {
        // Proper error response has been set up, no need to do anything further.
        return ABORT;
      }
    }

    if (replace_comments) {
      gatherComments(container, qname, qtype, new_comments);

      for (Comment& comment : new_comments) {
        comment.domain_id = static_cast<int>(domainInfo.id);
      }
    }
  }
  catch (const JsonException& e) {
    throw ApiException("New RRsets are invalid: " + string(e.what()));
  }

  if (replace_records) {
    replaceZoneRecords(domainInfo, zonename, new_records, qname, qtype);
  }
  if (replace_comments) {
    if (!domainInfo.backend->replaceComments(domainInfo.id, qname, qtype, new_comments)) {
      throw ApiException("Hosting backend does not support editing comments.");
    }
  }
  // Update RRset cache if needed
  if (returnRRset) {
    rrset = std::move(new_records);
  }
  return SUCCESS;
}

// Apply a PRUNE or EXTEND changetype.
static applyResult applyPruneOrExtend(const DomainInfo& domainInfo, const ZoneName& zonename, const Json& container, DNSName& qname, QType& qtype, bool allowUnderscores, soaEditSettings& soa, HttpResponse* resp, changeType operationType, std::vector<DNSResourceRecord>& rrset)
{
  if (!container["records"].is_array()) {
    throw ApiException("No record provided for PRUNE or EXTEND operation");
  }

  try {
    vector<DNSResourceRecord> new_records;
    uint32_t ttl = uintFromJson(container, "ttl");
    gatherRecords(container, qname, qtype, ttl, new_records);
    if (new_records.size() != 1) {
      throw ApiException("Exactly one record should be provided for PRUNE or EXTEND operation");
    }

    auto& new_record = new_records.front();
    new_record.domain_id = static_cast<int>(domainInfo.id);
    if (new_record.qtype.getCode() == QType::SOA && new_record.qname == zonename.operator const DNSName&()) {
      soa.edit_done = increaseSOARecord(new_record, soa.edit_api_kind, soa.edit_kind, zonename);
    }

    // Check if this record exists in the RRSet
    bool seenRecord{false};
    for (auto iter = rrset.begin(); iter != rrset.end(); ++iter) {
      if (iter->content == new_record.content) {
        // We found the record we've been instructed to add or delete.
        seenRecord = true;
        // If it is to be added, we don't have anything more to do.
        // If it is to be deleted, just remove it from the RRset we're building.
        if (operationType == PRUNE) {
          rrset.erase(iter);
        }
        break;
      }
    }
    // Add new record to RRset if not found.
    if (operationType == EXTEND && !seenRecord) {
      rrset.emplace_back(new_record);
    }
    bool submitChanges = (operationType == EXTEND && !seenRecord) || (operationType == PRUNE && seenRecord);
    if (!submitChanges) {
      return NOP;
    }

    // Check the updated RRSet for correctness
    Check::RRSetFlags flags{Check::RRSET_CHECK_TTL};
    if (allowUnderscores) {
      flags = static_cast<Check::RRSetFlags>(flags | Check::RRSET_ALLOW_UNDERSCORES);
    }
    if (!checkNewRecords(resp, rrset, zonename, flags)) {
      // Proper error response has been set up, no need to do anything further.
      return ABORT;
    }

    if (!domainInfo.backend->replaceRRSet(domainInfo.id, qname, qtype, rrset)) {
      throw ApiException("Hosting backend does not support editing records.");
    }
  }
  catch (const JsonException& e) {
    throw ApiException("Submitted record is invalid: " + string(e.what()));
  }
  return SUCCESS;
}

static void patchZone(UeberBackend& backend, const ZoneName& zonename, DomainInfo& domainInfo, const vector<Json>& rrsets, HttpResponse* resp)
{
  bool madeAnyChanges{false};
  domainInfo.backend->startTransaction(zonename);
  try {
    soaEditSettings soa;
    domainInfo.backend->getDomainMetadataOne(zonename, "SOA-EDIT-API", soa.edit_api_kind);
    domainInfo.backend->getDomainMetadataOne(zonename, "SOA-EDIT", soa.edit_kind);
    bool allowUnderscores = areUnderscoresAllowed(zonename, *domainInfo.backend);

    // For PRUNE and EXTEND operations, we are not being passed the complete
    // RRset, and will need to fetch it from the backend. But we may have
    // processed a DELETE or REPLACE operation for the same RRset first, in
    // which case we can't assume querying the backend will be consistent with
    // the results of that last operation, since we are within a not commited
    // yet transaction.
    // To be sure to work on consistent contents, without having to rely upon
    // specific backend behaviour, we will need to cache the RRset values
    // in this routine, but we only need to do that for RRset which are
    // subject to both PRUNE/EXTEND and DELETE/REPLACE operation.
    // That first pass over the change requests computes this (and also
    // performs basic validation).
    using key = std::pair<DNSName, QType>;
    std::map<key, unsigned int> changes;
    for (const auto& rrset : rrsets) {
      string changetype = toUpper(stringFromJson(rrset, "changetype"));
      auto operationType = validateChangeType(changetype);
      DNSName qname;
      QType qtype;
      parseRecordNameAndType(rrset, qname, qtype);

      if (operationType != DELETE) {
        if (domainInfo.kind == DomainInfo::Consumer) {
          // Allow deleting all RRsets, just not modifying them.
          throw ApiException("Modifying RRsets in Consumer zones is unsupported");
        }

        // We intentionally do not perform this check for DELETE, as it can be
        // used as a poor man's way to "fix" out-of-zone records.
        if (!qname.isPartOf(zonename)) {
          throw ApiException("RRset " + qname.toString() + " IN " + qtype.toString() + ": Name is out of zone");
        }
      }

      // At this point, we store a bitmask of the operations which will need
      // to be performed.
      unsigned int newOperation = 1U << operationType;
      key currentKey{qname, qtype};
      if (auto iter = changes.find(currentKey); iter != changes.end()) {
        auto operations = iter->second;
        // Only allow one DELETE or REPLACE operation per RRset. On the other
        // hand, it makes sense to allow multiple PRUNE or EXTEND, since the
        // individual records they'll concern might differ.
        if (operationType == DELETE || operationType == REPLACE) {
          if ((operations & newOperation) != 0) {
            throw ApiException("Duplicate RRset " + qname.toString() + " IN " + qtype.toString() + " with changetype: " + changetype);
          }
        }
        changes.insert_or_assign(currentKey, operations | newOperation);
      }
      else {
        changes.insert({currentKey, newOperation});
      }
    }

    // In this second pass, we will process the changes and maintain a cache
    // of the RRset subject to PRUNE/EXTEND operations.
    std::map<key, std::vector<DNSResourceRecord>> cache;
    for (const auto& container : rrsets) {
      string changetype = toUpper(stringFromJson(container, "changetype"));
      auto operationType = validateChangeType(changetype);
      DNSName qname;
      QType qtype;
      parseRecordNameAndType(container, qname, qtype);

      key currentKey{qname, qtype};
      bool cacheNeeded{false};
      if (auto iter = changes.find(currentKey); iter != changes.end()) {
        auto operations = iter->second;
        cacheNeeded = (operations & ((1U << PRUNE) | (1U << EXTEND))) != 0;
      }

      applyResult result{ABORT};
      std::vector<DNSResourceRecord> rrset;
      switch (operationType) {
      case DELETE:
        result = applyDelete(domainInfo, qname, qtype, cacheNeeded, rrset);
        break;
      case REPLACE:
        result = applyReplace(domainInfo, zonename, container, qname, qtype, allowUnderscores, soa, resp, cacheNeeded, rrset);
        break;
      case PRUNE:
      case EXTEND:
        // First, obtain the current RRset, either from the backend or from
        // our local cache if we already did some operations.
        if (const auto iter = cache.find(currentKey); iter != cache.end()) {
          rrset = std::move(iter->second);
        }
        else {
          DNSResourceRecord record;
          domainInfo.backend->lookup(qtype, qname, domainInfo.id);
          while (domainInfo.backend->get(record)) {
            rrset.emplace_back(record);
          }
        }
        result = applyPruneOrExtend(domainInfo, zonename, container, qname, qtype, allowUnderscores, soa, resp, operationType, rrset);
        break;
      }
      if (result == ABORT) {
        // Proper error response has been set up, no need to do anything further.
        domainInfo.backend->abortTransaction();
        return;
      }
      if (result == SUCCESS) {
        madeAnyChanges = true;
      }
      // Update RRset cache if needed.
      if (cacheNeeded) {
        cache.insert_or_assign(currentKey, std::move(rrset));
      }
    }
    cache.clear();

    if (madeAnyChanges) {
      SOAData soaData;
      bool zone_disabled = (!backend.getSOAUncached(zonename, soaData));

      // edit SOA (if needed)
      if (!zone_disabled && !soa.edit_api_kind.empty() && !soa.edit_done) {
        // return old serial in headers, before changing it
        resp->headers["X-PDNS-Old-Serial"] = std::to_string(soaData.serial);

        updateZoneSerial(domainInfo, soaData, soa.edit_api_kind, soa.edit_kind);

        // return new serial in headers
        resp->headers["X-PDNS-New-Serial"] = std::to_string(soaData.serial);
      }

      // Rectify
      DNSSECKeeper dnssecKeeper(&backend);
      if (!zone_disabled && !dnssecKeeper.isPresigned(zonename) && isZoneApiRectifyEnabled(domainInfo)) {
        string info;
        string error_msg;
        if (!dnssecKeeper.rectifyZone(zonename, error_msg, info, false)) {
          throw ApiException("Failed to rectify '" + zonename.toString() + "' " + error_msg);
        }
      }
    }
  }
  catch (...) {
    domainInfo.backend->abortTransaction();
    throw;
  }

  if (madeAnyChanges) {
    domainInfo.backend->commitTransaction();

    DNSSECKeeper::clearCaches(zonename);
    purgeAuthCaches(zonename.operator const DNSName&().toString() + "$");
  }
  else {
    domainInfo.backend->abortTransaction();
  }

  resp->body = "";
  resp->status = 204; // No Content, but indicate success
}

static void apiServerSearchData(HttpRequest* req, HttpResponse* resp)
{
  string qVar = req->getvars["q"];
  string sMaxVar = req->getvars["max"];
  string sObjectTypeVar = req->getvars["object_type"];

  size_t maxEnts = 100;
  size_t ents = 0;

  // the following types of data can be searched for using the api
  enum class ObjectType
  {
    ALL,
    ZONE,
    RECORD,
    COMMENT
  } objectType{};

  if (qVar.empty()) {
    throw ApiException("Query q can't be blank");
  }
  if (!sMaxVar.empty()) {
    maxEnts = std::stoi(sMaxVar);
  }
  if (maxEnts < 1) {
    throw ApiException("Maximum entries must be larger than 0");
  }

  if (sObjectTypeVar.empty() || sObjectTypeVar == "all") {
    objectType = ObjectType::ALL;
  }
  else if (sObjectTypeVar == "zone") {
    objectType = ObjectType::ZONE;
  }
  else if (sObjectTypeVar == "record") {
    objectType = ObjectType::RECORD;
  }
  else if (sObjectTypeVar == "comment") {
    objectType = ObjectType::COMMENT;
  }
  else {
    throw ApiException("object_type must be one of the following options: all, zone, record, comment");
  }

  SimpleMatch simpleMatch(qVar, true);
  UeberBackend backend;
  vector<DomainInfo> domains;
  vector<DNSResourceRecord> result_rr;
  vector<Comment> result_c;
  map<int, DomainInfo> zoneIdZone;
  map<int, DomainInfo>::iterator val;
  Json::array doc;

  backend.getAllDomains(&domains, false, true);

  for (const DomainInfo& domainInfo : domains) {
    if ((objectType == ObjectType::ALL || objectType == ObjectType::ZONE) && ents < maxEnts && simpleMatch.match(domainInfo.zone)) {
      doc.push_back(Json::object{
        {"object_type", "zone"},
        {"zone_id", apiZoneNameToId(domainInfo.zone)},
        {"name", domainInfo.zone.toString()}});
      ents++;
    }
    zoneIdZone[static_cast<int>(domainInfo.id)] = domainInfo; // populate cache
  }

  if ((objectType == ObjectType::ALL || objectType == ObjectType::RECORD) && backend.searchRecords(qVar, maxEnts, result_rr)) {
    for (const DNSResourceRecord& resourceRecord : result_rr) {
      if (resourceRecord.qtype.getCode() == 0) {
        continue; // skip empty non-terminals
      }

      std::string content;
      try {
        content = makeApiRecordContent(resourceRecord.qtype, resourceRecord.content);
      }
      catch (std::exception& e) {
        // makeApiRecordContent may throw an exception if the backend data
        // is not well-formed (e.g. corrupted bind zone file).
        // The exception gets caught here and rethrown as ApiException in
        // order to return a 422 error code with a (hopefully) useful error
        // message instead of a 500 error.
        throw ApiException("Ill-formed record contents found for " + resourceRecord.qname.toString() + ": " + e.what());
      }
      auto object = Json::object{
        {"object_type", "record"},
        {"name", resourceRecord.qname.toString()},
        {"type", resourceRecord.qtype.toString()},
        {"ttl", (double)resourceRecord.ttl},
        {"disabled", resourceRecord.disabled},
        {"content", content}};
      if (resourceRecord.last_modified != 0) {
        object["modified_at"] = (double)resourceRecord.last_modified;
      }

      val = zoneIdZone.find(resourceRecord.domain_id);
      if (val != zoneIdZone.end()) {
        object["zone_id"] = apiZoneNameToId(val->second.zone);
        object["zone"] = val->second.zone.toString();
      }
      doc.emplace_back(object);
    }
  }

  if ((objectType == ObjectType::ALL || objectType == ObjectType::COMMENT) && backend.searchComments(qVar, maxEnts, result_c)) {
    for (const Comment& comment : result_c) {
      auto object = Json::object{
        {"object_type", "comment"},
        {"name", comment.qname.toString()},
        {"type", comment.qtype.toString()},
        {"content", comment.content}};

      val = zoneIdZone.find(comment.domain_id);
      if (val != zoneIdZone.end()) {
        object["zone_id"] = apiZoneNameToId(val->second.zone);
        object["zone"] = val->second.zone.toString();
      }
      doc.emplace_back(object);
    }
  }

  resp->setJsonBody(doc);
}

static void apiServerCacheFlush(HttpRequest* req, HttpResponse* resp)
{
  ZoneName canon = apiNameToZoneName(req->getvars["domain"]);

  if (g_zoneCache.isEnabled()) {
    DomainInfo domainInfo;
    UeberBackend backend;
    if (backend.getDomainInfo(canon, domainInfo, false)) {
      // zone exists (uncached), add/update it in the zone cache.
      // Handle this first, to avoid concurrent queries re-populating the other caches.
      g_zoneCache.add(domainInfo.zone, static_cast<int>(domainInfo.id));
    }
    else {
      g_zoneCache.remove(domainInfo.zone);
    }
  }

  DNSSECKeeper::clearCaches(canon);
  // purge entire zone from cache, not just zone-level records.
  uint64_t count = purgeAuthCaches(canon.operator const DNSName&().toString() + "$");
  resp->setJsonBody(Json::object{
    {"count", (int)count},
    {"result", "Flushed cache."}});
}

static std::ostream& operator<<(std::ostream& outStream, StatType statType)
{
  switch (statType) {
  case StatType::counter:
    return outStream << "counter";
  case StatType::gauge:
    return outStream << "gauge";
  };
  return outStream << static_cast<uint16_t>(statType);
}

static void prometheusMetrics(HttpRequest* /* req */, HttpResponse* resp)
{
  std::ostringstream output;
  for (const auto& metricName : S.getEntries()) {
    // Prometheus suggest using '_' instead of '-'
    std::string prometheusMetricName = "pdns_auth_" + boost::replace_all_copy(metricName, "-", "_");

    output << "# HELP " << prometheusMetricName << " " << S.getDescrip(metricName) << "\n";
    output << "# TYPE " << prometheusMetricName << " " << S.getStatType(metricName) << "\n";
    output << prometheusMetricName << " " << S.read(metricName) << "\n";
  }

  output << "# HELP pdns_auth_info "
         << "Info from PowerDNS, value is always 1"
         << "\n";
  output << "# TYPE pdns_auth_info "
         << "gauge"
         << "\n";
  output << "pdns_auth_info{version=\"" << VERSION << "\"} "
         << "1"
         << "\n";

  resp->body = output.str();
  resp->headers["Content-Type"] = "text/plain; version=0.0.4";
  resp->status = 200;
}

// Views

// Serialize a list of ZoneName as a JSON array of strings
static void jsonFillZoneNameArray(Json::array& array, std::vector<ZoneName>& zones)
{
  for (const auto& zone : zones) {
    array.emplace_back(zone.toString());
  }
}

// GET /views           returns the list of all views (tags)
static void apiServerViewsAllGET(HttpRequest* /* req */, HttpResponse* resp)
{
  std::vector<std::string> views;
  UeberBackend backend;

  backend.viewList(views);

  Json::object jsonresult{
    {"views", std::move(views)}};
  resp->setJsonBody(jsonresult);
}

// GET /views/<view>     returns the list of all ZoneName in the given "view" view
static void apiServerViewsGET(HttpRequest* req, HttpResponse* resp)
{
  std::string view{req->parameters["view"]};
  std::vector<ZoneName> zones;
  UeberBackend backend;

  backend.viewListZones(view, zones);

  if (zones.empty()) {
    throw HttpNotFoundException(); // view does not exist
  }

  Json::array jsonarray;
  jsonFillZoneNameArray(jsonarray, zones);
  Json::object jsonresult{
    {"zones", jsonarray}}; // FIXME: this should probably be a list of zone objects that at least have name and variant (perhaps separated?) and a path for .../zones/[encoded domain name with variant]
  resp->setJsonBody(jsonresult);
}

// POST /views/<view> + name in json adds ZoneName "name" to view "view"
static void apiServerViewsPOST(HttpRequest* req, HttpResponse* resp)
{
  const auto& document = req->json();
  // We can't use a ZoneData object here, as the zone being added to the
  // view may not exist yet.
  ZoneName zonename = apiNameToZoneName(stringFromJson(document, "name"));

  std::string view{req->parameters["view"]};
  std::string error;
  if (!Check::validateViewName(view, error)) {
    throw ApiException(error);
  }

  UeberBackend backend;
  if (!backend.viewAddZone(view, zonename)) {
    throw ApiException("Failed to add " + zonename.toString() + " to view " + view);
  }
  // Notify zone cache of the new association
  if (g_zoneCache.isEnabled()) {
    g_zoneCache.addToView(view, zonename);
  }
  // Purge packet cache for that zone
  if (PC.enabled()) {
    std::string purgename = zonename.operator const DNSName&().toString();
    purgename.append("$");
    (void)PC.purge(view, purgename);
  }

  resp->body = "";
  resp->status = 204;
}

// DELETE /views/<view>/<id>     removes ZoneName "id" from view "view"
static void apiServerViewsDELETE(HttpRequest* req, HttpResponse* resp)
{
  // We can't use a ZoneData object here, as the zone being removed from the
  // view may no longer exist.
  ZoneName zoneName(apiZoneIdToName(req->parameters["id"]));

  std::string view{req->parameters["view"]};
  std::string error;
  if (!Check::validateViewName(view, error)) {
    throw ApiException(error);
  }

  UeberBackend backend;
  if (!backend.viewDelZone(view, zoneName)) {
    throw ApiException("Failed to remove " + zoneName.toString() + " from view " + view);
  }
  // Notify zone cache of the removed association
  bool emptyView{false};
  if (g_zoneCache.isEnabled()) {
    emptyView = g_zoneCache.removeFromView(view, zoneName);
  }
  // Purge packet cache for that zone
  if (PC.enabled()) {
    if (emptyView) {
      (void)PC.purgeView(view);
    }
    else {
      std::string purgename = zoneName.operator const DNSName&().toString();
      purgename.append("$");
      (void)PC.purge(view, purgename);
    }
  }

  resp->body = "";
  resp->status = 204;
}

// Networks

// GET /networks                return the list of all registered networks and views (only one view per network)
// GET /networks/<ip>/<prefixlen> return the name of the view for the given network
static void apiServerNetworksGET(HttpRequest* req, HttpResponse* resp)
{
  Netmask network;
  if (req->parameters.count("ip") != 0 && req->parameters.count("prefixlen") != 0) {
    std::string subnet{req->parameters["ip"]};
    std::string prefixlen{req->parameters["prefixlen"]};
    try {
      network = subnet + "/" + prefixlen;
    }
    catch (NetmaskException& e) {
      throw ApiException(e.reason);
    }
  }

  UeberBackend backend;
  std::vector<pair<Netmask, string>> networks;
  backend.networkList(networks);
  Json::array jsonarray;
  Json::object item;
  for (const auto& pair : networks) {
    if (!network.empty() && !(pair.first == network)) { // FIXME: should this case handled by a separate call networkGet, to be implemented in lmdbbackend?
      continue;
    }
    item["network"] = pair.first.toString();
    item["view"] = pair.second;
    jsonarray.emplace_back(item);
    item.clear();
  }

  if (network.empty()) {
    Json::object jsonresult{
      {"networks", std::move(jsonarray)}};
    resp->setJsonBody(jsonresult);
  }
  else {
    if (jsonarray.empty()) {
      throw HttpNotFoundException(); // no view configured for that network
    }

    resp->setJsonBody(jsonarray[0]);
  }
}

// PUT /networks/<ip>/<prefixlen> sets the name of the view for the given network
static void apiServerNetworksPUT(HttpRequest* req, HttpResponse* resp)
{
  std::string subnet{req->parameters["ip"]};
  std::string prefixlen{req->parameters["prefixlen"]};
  Netmask network;
  try {
    network = subnet + "/" + prefixlen;
  }
  catch (NetmaskException& e) {
    throw ApiException(e.reason);
  }

  const auto& document = req->json();
  std::string view = stringFromJson(document, "view");

  UeberBackend backend;
  if (!backend.networkSet(network, view)) {
    throw ApiException("Failed to setup view " + view + " for network " + network.toString());
  }
  // Notify zone cache of the new association
  if (g_zoneCache.isEnabled()) {
    g_zoneCache.updateNetwork(network, view);
  }

  resp->body = "";
  resp->status = 204;
}

static void cssfunction(HttpRequest* /* req */, HttpResponse* resp)
{
  resp->headers["Cache-Control"] = "max-age=86400";
  resp->headers["Content-Type"] = "text/css";

  ostringstream ret;
  ret << "* { box-sizing: border-box; margin: 0; padding: 0; }" << endl;
  ret << "body { color: black; background: white; margin-top: 1em; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; font-size: 10pt; position: relative; }" << endl;
  ret << "a { color: #0959c2; }" << endl;
  ret << "a:hover { color: #3B8EC8; }" << endl;
  ret << ".row { width: 940px; max-width: 100%; min-width: 768px; margin: 0 auto; }" << endl;
  ret << ".row:before, .row:after { display: table; content:\" \"; }" << endl;
  ret << ".row:after { clear: both; }" << endl;
  ret << ".columns { position: relative; min-height: 1px; float: left; }" << endl;
  ret << ".all { width: 100%; }" << endl;
  ret << ".headl { width: 60%; }" << endl;
  ret << ".header { width: 39.5%; float: right; background-repeat: no-repeat; margin-top: 7px; ";
  ret << "background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJoAAAAUCAYAAAB1RSS/AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAACtgAAArYBAHIqtQAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAABBTSURBVGiBtVp7cFRVmv9u3763b7/f9It00iFACBohgCEyQYgKI49CLV3cWaoEZBcfo2shu7KOtZbjrqOuVQtVWFuOrPqPRU3NgOIDlkgyJEYJwUAqjzEJedFJupN0p9/v+9o/mtve7r790HF+VbeSPue7555zz+98z4ucOXNmgWVZBH4AK5PJGIPBQBqNxpTNZkthGMZCCUxMTBCDg4PyiYkJWTQaRc1mc7Kuri7a1NQU4ssxDAOffPKJAQCynvnII494ESTddO3aNaXT6SS4TplMRj/44IM+7ndXV5dqfn5ewh9306ZNQZqmobu7W11qri0tLX6tVkv19vYqpqampPw+BEFYtVpNGQwG0mKxpJYsWUIKjTE6OiodGBhQ8NcgkUgYjUZDORyOhM1mSxV6fjAYFF+6dEnLb9NoNOR9990X4H53dHSovV4vzpfZvn27T6FQ0Py2sbExorOzU+N2uwmWZUGv15N33nlnuLGxMZy7byyVQEJ//nd9Yuz/lJR/HBdrHSlJ9baIuuV1L4LJ8/Y49pc/KcJX39WRC4MEgskY3Lourmn5rQdbckfe2ijfOBZo+40xNXtNysR9KLZkdVK+9oBf0fBkCABA3NraamTZwjxSKpXUAw884G1paQkUIty5c+f0Fy5cWMIfx+l0Snt6ejTt7e26AwcOuKxWawoAQCQSQW9vr3pxcTHrJTY3Nwe5Tb18+bJ2bGxMzvWhKMpu27bNj6IoCwDQ1tamd7lcRM79genpaaK1tdVQcDG3sXbt2rBWq6X6+/sV3d3d2mKyy5cvj+7cudO7atWqGL99bGxMWuxZOp0utX37du+9994b5A4Qh2AwiObei6Ioe/fdd4eVSiUNAHD16lX1+Pi4nC+zadOmIJ9oZ8+eNeTu3/T0tLSvr0/V3d0dPXr0qJNrZ+KL6MKpjZWUbyxzQMmFIYJcGCISw5+qjE9+M4UqLJmx/RdeWBK+elKfGTjuR+OhWSxx86JS/9D/zsrufDzMdSXGv5J5/vBYBZuKiLi25HS3LDndLUuMX1IYHjvtynQUQjgcFp89e9b8zjvv2BmGyepjWRbeffdd2/nz55cUIqvT6ZSeOHHC7vf7xVyb3W6P58rNzc1liOfxeLJISNM04na7Me63z+fD+P1SqZQupHn+Wty8eVN+4sSJyv7+fnlp6R/g8/nw06dPW0+ePLmUJEmklDxN08iVK1dU5Y7f0dGhvnjxYkElQVFU1jP9Xz5j4pMsSzYwifvPPWnhfsdHPpdnkYwHlk4ivi9/baFDM2IAACYZEi1++qSVTzI+YkN/VEe++726JNE4TE1Nyc6cOWPkt3322Wf6/v7+ki8nEAhgH3zwQWYhDoejINGSyaQoFAphuf2zs7MSAIBIJIImEgmU32ez2RLlruOngGVZ+Oijj6w+n09cWjobg4ODyg8//NBSWhLgu+++K4toJEkin376qancObBkFIl/f7bo2ImxC0om5kUBACK9pzTFZJlEAI0O/kEJABAf+UJOh115+8VH5MZHGkGimc3mRK66BwBoa2szBAIBMUB6w1tbW415QgUwOjqqGB4elgIA1NTU5BGN02IulwsXOqUul0sCADA/P5+3qIqKip+NaARBMBiGMbnt0Wg0z68qF729vepr164pS8k5nU7ZwsJC0U0DAOjp6VHGYjE0t10kEgmqt5TrOwIYqqRWTbmuSQAASM9fiFKy5Fx/Wnaur7Ss53tC8IQ+/fTTM/F4HH3rrbcc/E1nWRYmJyeJtWvXRr7++mt1rnoGANi6devipk2bgsePH7dHIpGs8Ts7O7W1tbXxqqqqJIZhLN+keDweDADA7XbjuWPebpcAACwsLOT1V1VVFSSayWRKvvLKK5P8tmLBTVNTk//hhx/2vv/++5aBgYEsLeB0OqWF7gMAsFqtiYqKivj169c1ueaytbVVv2HDhnChewHS7/fKlSuqPXv2LBaTyw1gAABqa2sjhw4dck1PT0vOnz9v4O+NWFNdlluBqispAABUYSEp/6TgPmRkVba0rGppybFRpZksaDodDkeioqIiT/M4nU4JAMDIyEiez1JTUxN9/PHHFyoqKpJbtmzx5faPj4/LANKOr9VqzRqbi7D4vhof8/PzOMAPhMyZa948OSAIAjiOs/xLSFvzIZFImO3bt+fNn9OqhaDRaMiDBw/Obd26NY8oTqdTWmhtfPT29paMmkOhUJ6CkEgkjFKppOvq6mIvvviis76+PkNqVF1BiQ21yWJjoiobiRlWpQAACMeWaKk5EMu2RQEAiOr7YyBCi2YliMrN0aI+Wjwez+vn/KOZmZk8lbl69eoI97+QeQwEAhgXFFRVVWX1+/1+nGVZyE1bcPB6vRKWZSE35JdKpbTJZCp4qiiKQmZmZnDuEiKqEITWTtN0SfMDALBjx45FiUSSZ35HRkaKakQAgPn5ecnU1FRRQuv1+rz0Qn9/v+ry5ctqgPTh2rFjR9ZB0e78Hzcgedb2NhDQ7vq9C24fQNXm3/gww8qCxJTX/4OfcGyJAwBgS+pSqo3/XFADo0oLqdn2lkeQaAzDIB0dHWqPx5O3YK1WSzIMA7lmEQDAaDSSQv/zEQwGUQCA6urqLKJRFIV4PB6MH3GqVCqS3z83N4cvLi5mEaVUIOD1evHXX399GXedOnXKWkweIJ3r++abb/IcYqPRWDA3xodUKmWEyMCZ/1IolQvMfXcAabN7+vRp68cff2wS8nElVVvihl99cQtV27PmhapspOHvzzmJ5Tsy6RtELGGX7G+7JV2xIysHiqAYq/rFv3h0e96f57drHnjTo2n57TwiJrIOl6SyOWo6cPmWiNAwgj7am2++6Ugmk4IkrK2tjUWjUVRoMXK5PJOHkclkdJ4AAESjURQAYPny5YKRJ59odXV1EX6ea2ZmRpKbf/s5AwEAgO+//17+8ssv1/j9/jzNt3HjxmC542g0GjI318etXQgoirKcxrx+/brKYDAUJPW6desiFy5ciM/MzORpyM7OTl04HEYPHz7synURiJpfxizPj4+T8/0S0jOEiw2rUrh5TRJE+TRAFWba+KvPZung9Hxy9iohwpUMvnRjQkSo8zQ1ICJQbX7Zp2h8LpCa7ZEwUY8Yt21IiHXLMopCkEyFSFZZWRmz2+0FVSqXUL39v6AM5yTr9XpKrVZnab2RkRFZKpXKPHvlypUxvuM+PT0tCQaDWW+lWCDwUzA3N0cIkay2tjbS0tLiL3ccoYNWzPRWVVXFcBxnAACCwSAmRCIOCILA/v373QqFghLqv3Hjhrq9vb1gioIFBNLFoLI8gbKBILdHRNi8ocvOC6nVavLw4cOzAAAKhYJGEARytRo/5A6Hw4JMk8lkmRNht9vjAwMDmU0dGhril3TAbDanDAZD0u12EwAAw8PDCoZhspZQLBD4KRBa17Zt27wPPfSQVyQqO+0IQumHQloeIB0Jr169Onzjxg01QOHDzqGioiJ55MiRW8ePH68UCg6+/PJLY0tLS4Cv1RJjF2W+z5+2UEFnxiqgKhup2/muW7pyV1YAQEfmUN9n/2SOj57PRN4IirHKphe86q2vLSIozktHMBDq+p0u3PkfRpZKZOYtqWyOavd86BZrlxWOOjMTQVH2jjvuCL/wwgtOvV5PAaQ3QyqV5r20SCSSebmhUEiQaCqVKnNfLkk4QnEwmUyk2WzOaNDp6emsU14qEABIO87Hjh2b5K79+/e7i8kLVS0UCgXF19blINfEAwCoVCpBDcShsbExVKw/FzabLXXs2LFJIT81Go2K+YFPYqpDuvDx7ko+yQAA6NAs5jn9sD1+84KMa2OpJLLw0X2VfJIBALA0iYS6/svoO/ePWcni4KWXjKH2V0x8kgEAJG99Lfd8uLmSSfiFj+j999/v3bt3r/vgwYMzb7zxxthzzz03w9UqOVit1rzFjY6OZiY7NDSUl/4gCIIxmUyZcZYtW1ZQG0mlUloul9Nmszkjn1sCK6cigGEY63A4EtxlsViKOvQOhyOm0WiyyNve3q4vN+IESKeAhKJnISeej/r6+ijfzy2Evr4+Oad19Xo9dejQoVkhbev1ejNE83/xjAXYfPcqDRZ8nz9lhdtjhjr/U0d6RwoGLtH+j7WJyctSAADSM4SHu/9bsFwFAECHXVjwq381ChKtubk50NLSEmhsbAxrNBrBU7hixYq8XMvg4KByamqKmJubw7799ts8H6GqqirGV+XV1dWJQppCq9WSAABWq7WgT/hzBwIAaW3d0NCQpVkCgQDW1dVVVnnI5XLhp06dsuW24zjO1NTUFJ0viqJsfX19Sa3W09Ojfu+996xcCkapVNIoiuaxyGAwkAAAdHBaXIw4AGnNRnqHcQCAxOTlknXdxHirHAAgOXFJBkzxQ5ic6pD/6Nodh9uRT1YxPRaLoW+//XaVWCxmhXyMe+65J8D/jeM4a7FYEkKOL5ceWLp0aUGiVVZWliSax+PBX3rppRp+27PPPjtdLKhpamoKtre3Z53Sr776yrB58+a8LzH4GB4eVr722muCpaaGhoYgQRCFVEoGGzduDF65cqVkqevGjRvqgYEBld1uj8/NzUlIMtsNwnGc4VJMlH+yrNwhFbglxoyrUnTEXVKeDs2K039nSstG5rDyvdscLF26NNnQ0JAX7tM0jQiRzGQyJdevXx/Jba+srBQ0J3q9ngRIBwRisVhQ65UTCNA0jQQCAYx/CZXO+LDb7UmLxZJFYo/Hg1+9erVovTLXtHMgCILevXt30bISh5UrV8ZzTXchUBSFTExMyIQCj7q6ugh3KHDbugSIhN8hHxLb+iQAAGasK+2SmOvTsuY1pWWNqxI/mWgAAI8++uiCTqcrmcTEMIzZt2+fW8hMFvJbuNMoEokEM+FSqZQ2m81/k0+DAADWr1+fZ8IuXrxY8lu3XKAoyu7bt8/NmbFSEDLdPxYSiYTZu3dvJqmKYHJWturhomNKa34ZFskMNACAYt2hQDFZEaGh5XfsDQMAECt2R1Glreja5GsOBP4qoul0Ouro0aO3TCZTQTOkUqnII0eO3FqxYoUgoYRKVQAA/ISl0Ph/60+Dmpqa8syky+Ui+vr6yv4uTavVks8///ytUsV0oWf/GHk+pFIp/cQTT8zqdLos31q36+S8WFcjuE9iTVVK99CpTDQuXbk7qmz8taAGRlAJq9t50o2qllIAACKJitHu+cCF4ApBdS5d/XdB+fqnguLq6upobm4Kx/GyQ3m9Xk+9+uqrk21tbZquri6t1+vFWZYFi8WSdDgcsV27di1qtdqCYb3ZbCZra2sjueaW/yl0XV1dNBwOZ/mT/KIxB6VSSTkcjlhuey44X8lkMqVy5TmC6/V6qrGx0Z8bPY6OjsrWrFkT1el0ec9CUZRVqVSUWq2mqqur4xs2bAgL+XQSiYTJvZcf9Njt9uRdd90Vys2PcQnd5ubmAMMwcPPmTXk0GhUDpCsRVVVVsccee2yBS0PxIZLqacszfZPBP7+qj4+1Kilf+lNuYtkDEU3La3mfcmsfPL4gqfxFrJxPuYll22Kmp/omgpf+zZia7ZEyCT+KGVcn5WsP+uUNh0IAAP8PaQRnE4MgdzkAAAAASUVORK5CYII=);";
  ret << " width: 154px; height: 20px; }" << endl;
  ret << "a#appname { margin: 0; font-size: 27px; color: #666; text-decoration: none; font-weight: bold; display: block; }" << endl;
  ret << "footer { border-top:  1px solid #ddd; padding-top: 4px; font-size: 12px; }" << endl;
  ret << "footer.row { margin-top: 1em; margin-bottom: 1em; }" << endl;
  ret << ".panel { background: #f2f2f2; border: 1px solid #e6e6e6; margin: 0 0 22px 0; padding: 20px; }" << endl;
  ret << "table.data { width: 100%; border-spacing: 0; border-top: 1px solid #333; }" << endl;
  ret << "table.data td { border-bottom: 1px solid #333; padding: 2px; }" << endl;
  ret << "table.data tr:nth-child(2n) { background: #e2e2e2; }" << endl;
  ret << "table.data tr:hover { background: white; }" << endl;
  ret << ".ringmeta { margin-bottom: 5px; }" << endl;
  ret << ".resetring {float: right; }" << endl;
  ret << ".resetring i { background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAA/klEQVQY01XPP04UUBgE8N/33vd2XZUWEuzYuMZEG4KFCQn2NhA4AIewAOMBPIG2xhNYeAcKGqkNCdmYlVBZGBIT4FHsbuE0U8xk/kAbqm9TOfI/nicfhmwgDNhvylUT58kxCp4l31L8SfH9IetJ2ev6PwyIwyZWsdb11/gbTK55Co+r8rmJaRPTFJcpZil+pTit7C5awMpA+Zpi1sRFE9MqflYOloYCjY2uP8EdYiGU4CVGUBubxKfOOLjrtOBmzvEilbVb/aQWvhRl0unBZVXe4XdnK+bprwqnhoyTsyZ+JG8Wk0apfExxlcp7PFruXH8gdxamWB4cyW2sIO4BG3czIp78jUIAAAAASUVORK5CYII=); width: 10px; height: 10px; margin-right: 2px; display: inline-block; background-repeat: no-repeat; }" << endl;
  ret << ".resetring:hover i { background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAA2ElEQVQY013PMUoDcRDF4c+kEzxCsNNCrBQvIGhnlcYm11EkBxAraw8gglgIoiJpAoKIYlBcgrgopsma3c3fwt1k9cHA480M8xvQp/nMjorOWY5ov7IAYlpjQk7aYxcuWBpwFQgJnUcaYk7GhEDIGL5w+MVpKLIRyR2b4JOjvGhUKzHTv2W7iuSN479Dvu9plf1awbQ6y3x1sU5tjpVJcMbakF6Ycoas8Dl5xEHJ160wRdfqzXfa6XQ4PLDlicWUjxHxZfndL/N+RhiwNzl/Q6PDhn/qsl76H7prcApk2B1aAAAAAElFTkSuQmCC);}" << endl;
  ret << ".resizering {float: right;}" << endl;
  resp->body = ret.str();
  resp->status = 200;
}

void AuthWebServer::webThread()
{
  try {
    setThreadName("pdns/webserver");
    if (::arg().mustDo("api")) {
      d_ws->registerApiHandler("/api/v1/servers/localhost/cache/flush", apiServerCacheFlush, "PUT");
      d_ws->registerApiHandler("/api/v1/servers/localhost/config", apiServerConfig, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/search-data", apiServerSearchData, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/statistics", apiServerStatistics, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/autoprimaries/<ip>/<nameserver>", &apiServerAutoprimaryDetailDELETE, "DELETE");
      d_ws->registerApiHandler("/api/v1/servers/localhost/autoprimaries", &apiServerAutoprimariesGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/autoprimaries", &apiServerAutoprimariesPOST, "POST");
      d_ws->registerApiHandler("/api/v1/servers/localhost/networks", apiServerNetworksGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/networks/<ip>/<prefixlen>", apiServerNetworksGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/networks/<ip>/<prefixlen>", apiServerNetworksPUT, "PUT");
      d_ws->registerApiHandler("/api/v1/servers/localhost/tsigkeys/<id>", apiServerTSIGKeyDetailGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/tsigkeys/<id>", apiServerTSIGKeyDetailPUT, "PUT");
      d_ws->registerApiHandler("/api/v1/servers/localhost/tsigkeys/<id>", apiServerTSIGKeyDetailDELETE, "DELETE");
      d_ws->registerApiHandler("/api/v1/servers/localhost/tsigkeys", apiServerTSIGKeysGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/tsigkeys", apiServerTSIGKeysPOST, "POST");
      d_ws->registerApiHandler("/api/v1/servers/localhost/views", apiServerViewsAllGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/views/<view>", apiServerViewsGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/views/<view>", apiServerViewsPOST, "POST");
      d_ws->registerApiHandler("/api/v1/servers/localhost/views/<view>/<id>", apiServerViewsDELETE, "DELETE");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/axfr-retrieve", apiServerZoneAxfrRetrieve, "PUT");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/cryptokeys/<key_id>", apiZoneCryptokeysGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/cryptokeys/<key_id>", apiZoneCryptokeysPOST, "POST");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/cryptokeys/<key_id>", apiZoneCryptokeysPUT, "PUT");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/cryptokeys/<key_id>", apiZoneCryptokeysDELETE, "DELETE");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/cryptokeys", apiZoneCryptokeysGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/cryptokeys", apiZoneCryptokeysPOST, "POST");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/export", apiServerZoneExport, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/metadata/<kind>", apiZoneMetadataKindGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/metadata/<kind>", apiZoneMetadataKindPUT, "PUT");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/metadata/<kind>", apiZoneMetadataKindDELETE, "DELETE");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/metadata", apiZoneMetadataGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/metadata", apiZoneMetadataPOST, "POST");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/notify", apiServerZoneNotify, "PUT");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/rectify", apiServerZoneRectify, "PUT");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>", apiServerZoneDetailGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>", apiServerZoneDetailPATCH, "PATCH");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>", apiServerZoneDetailPUT, "PUT");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>", apiServerZoneDetailDELETE, "DELETE");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones", apiServerZonesGET, "GET");
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones", apiServerZonesPOST, "POST");
      d_ws->registerApiHandler("/api/v1/servers/localhost", apiServerDetail, "GET");
      d_ws->registerApiHandler("/api/v1/servers", apiServer, "GET");
      d_ws->registerApiHandler("/api/v1", apiDiscoveryV1, "GET");
      d_ws->registerApiHandler("/api/docs", apiDocs, "GET");
      d_ws->registerApiHandler("/api", apiDiscovery, "GET");
    }
    if (::arg().mustDo("webserver")) {
      d_ws->registerWebHandler(
        "/style.css", [](HttpRequest* req, HttpResponse* resp) { cssfunction(req, resp); }, "GET");
      d_ws->registerWebHandler(
        "/", [this](HttpRequest* req, HttpResponse* resp) { indexfunction(req, resp); }, "GET");
      d_ws->registerWebHandler("/metrics", prometheusMetrics, "GET");
    }
    d_ws->go();
  }
  catch (...) {
    g_log << Logger::Error << "AuthWebServer thread caught an exception, dying" << endl;
    _exit(1);
  }
}
