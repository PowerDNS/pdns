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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "utility.hh"
#include "dynlistener.hh"
#include "ws-auth.hh"
#include "json.hh"
#include "webserver.hh"
#include "logger.hh"
#include "statbag.hh"
#include "misc.hh"
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
#include "common_startup.hh"
#include "auth-caches.hh"

using json11::Json;

extern StatBag S;

static void patchZone(HttpRequest* req, HttpResponse* resp);
static void storeChangedPTRs(UeberBackend& B, vector<DNSResourceRecord>& new_ptrs);
static void makePtr(const DNSResourceRecord& rr, DNSResourceRecord* ptr);

AuthWebServer::AuthWebServer()
{
  d_start=time(0);
  d_min10=d_min5=d_min1=0;
  d_ws = 0;
  d_tid = 0;
  if(arg().mustDo("webserver") || arg().mustDo("api")) {
    d_ws = new WebServer(arg()["webserver-address"], arg().asNum("webserver-port"));
    d_ws->bind();
  }
}

void AuthWebServer::go()
{
  S.doRings();
  pthread_create(&d_tid, 0, webThreadHelper, this);
  pthread_create(&d_tid, 0, statThreadHelper, this);
}

void AuthWebServer::statThread()
{
  try {
    for(;;) {
      d_queries.submit(S.read("udp-queries"));
      d_cachehits.submit(S.read("packetcache-hit"));
      d_cachemisses.submit(S.read("packetcache-miss"));
      d_qcachehits.submit(S.read("query-cache-hit"));
      d_qcachemisses.submit(S.read("query-cache-miss"));
      Utility::sleep(1);
    }
  }
  catch(...) {
    L<<Logger::Error<<"Webserver statThread caught an exception, dying"<<endl;
    exit(1);
  }
}

void *AuthWebServer::statThreadHelper(void *p)
{
  AuthWebServer *self=static_cast<AuthWebServer *>(p);
  self->statThread();
  return 0; // never reached
}

void *AuthWebServer::webThreadHelper(void *p)
{
  AuthWebServer *self=static_cast<AuthWebServer *>(p);
  self->webThread();
  return 0; // never reached
}

static string htmlescape(const string &s) {
  string result;
  for(string::const_iterator it=s.begin(); it!=s.end(); ++it) {
    switch (*it) {
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
      result += *it;
    }
  }
  return result;
}

void printtable(ostringstream &ret, const string &ringname, const string &title, int limit=10)
{
  int tot=0;
  int entries=0;
  vector<pair <string,unsigned int> >ring=S.getRing(ringname);

  for(vector<pair<string, unsigned int> >::const_iterator i=ring.begin(); i!=ring.end();++i) {
    tot+=i->second;
    entries++;
  }

  ret<<"<div class=\"panel\">";
  ret<<"<span class=resetring><i></i><a href=\"?resetring="<<htmlescape(ringname)<<"\">Reset</a></span>"<<endl;
  ret<<"<h2>"<<title<<"</h2>"<<endl;
  ret<<"<div class=ringmeta>";
  ret<<"<a class=topXofY href=\"?ring="<<htmlescape(ringname)<<"\">Showing: Top "<<limit<<" of "<<entries<<"</a>"<<endl;
  ret<<"<span class=resizering>Resize: ";
  unsigned int sizes[]={10,100,500,1000,10000,500000,0};
  for(int i=0;sizes[i];++i) {
    if(S.getRingSize(ringname)!=sizes[i])
      ret<<"<a href=\"?resizering="<<htmlescape(ringname)<<"&amp;size="<<sizes[i]<<"\">"<<sizes[i]<<"</a> ";
    else
      ret<<"("<<sizes[i]<<") ";
  }
  ret<<"</span></div>";

  ret<<"<table class=\"data\">";
  int printed=0;
  int total=max(1,tot);
  for(vector<pair<string,unsigned int> >::const_iterator i=ring.begin();limit && i!=ring.end();++i,--limit) {
    ret<<"<tr><td>"<<htmlescape(i->first)<<"</td><td>"<<i->second<<"</td><td align=right>"<< AuthWebServer::makePercentage(i->second*100.0/total)<<"</td>"<<endl;
    printed+=i->second;
  }
  ret<<"<tr><td colspan=3></td></tr>"<<endl;
  if(printed!=tot)
    ret<<"<tr><td><b>Rest:</b></td><td><b>"<<tot-printed<<"</b></td><td align=right><b>"<< AuthWebServer::makePercentage((tot-printed)*100.0/total)<<"</b></td>"<<endl;

  ret<<"<tr><td><b>Total:</b></td><td><b>"<<tot<<"</b></td><td align=right><b>100%</b></td>";
  ret<<"</table></div>"<<endl;
}

void AuthWebServer::printvars(ostringstream &ret)
{
  ret<<"<div class=panel><h2>Variables</h2><table class=\"data\">"<<endl;

  vector<string>entries=S.getEntries();
  for(vector<string>::const_iterator i=entries.begin();i!=entries.end();++i) {
    ret<<"<tr><td>"<<*i<<"</td><td>"<<S.read(*i)<<"</td><td>"<<S.getDescrip(*i)<<"</td>"<<endl;
  }

  ret<<"</table></div>"<<endl;
}

void AuthWebServer::printargs(ostringstream &ret)
{
  ret<<"<table border=1><tr><td colspan=3 bgcolor=\"#0000ff\"><font color=\"#ffffff\">Arguments</font></td>"<<endl;

  vector<string>entries=arg().list();
  for(vector<string>::const_iterator i=entries.begin();i!=entries.end();++i) {
    ret<<"<tr><td>"<<*i<<"</td><td>"<<arg()[*i]<<"</td><td>"<<arg().getHelp(*i)<<"</td>"<<endl;
  }
}

string AuthWebServer::makePercentage(const double& val)
{
  return (boost::format("%.01f%%") % val).str();
}

void AuthWebServer::indexfunction(HttpRequest* req, HttpResponse* resp)
{
  if(!req->getvars["resetring"].empty()) {
    if (S.ringExists(req->getvars["resetring"]))
      S.resetRing(req->getvars["resetring"]);
    resp->status = 301;
    resp->headers["Location"] = req->url.path;
    return;
  }
  if(!req->getvars["resizering"].empty()){
    int size=std::stoi(req->getvars["size"]);
    if (S.ringExists(req->getvars["resizering"]) && size > 0 && size <= 500000)
      S.resizeRing(req->getvars["resizering"], std::stoi(req->getvars["size"]));
    resp->status = 301;
    resp->headers["Location"] = req->url.path;
    return;
  }

  ostringstream ret;

  ret<<"<!DOCTYPE html>"<<endl;
  ret<<"<html><head>"<<endl;
  ret<<"<title>PowerDNS Authoritative Server Monitor</title>"<<endl;
  ret<<"<link rel=\"stylesheet\" href=\"style.css\"/>"<<endl;
  ret<<"</head><body>"<<endl;

  ret<<"<div class=\"row\">"<<endl;
  ret<<"<div class=\"headl columns\">";
  ret<<"<a href=\"/\" id=\"appname\">PowerDNS "<<htmlescape(VERSION);
  if(!arg()["config-name"].empty()) {
    ret<<" ["<<htmlescape(arg()["config-name"])<<"]";
  }
  ret<<"</a></div>"<<endl;
  ret<<"<div class=\"headr columns\"></div></div>";
  ret<<"<div class=\"row\"><div class=\"all columns\">";

  time_t passed=time(0)-s_starttime;

  ret<<"<p>Uptime: "<<
    humanDuration(passed)<<
    "<br>"<<endl;

  ret<<"Queries/second, 1, 5, 10 minute averages:  "<<std::setprecision(3)<<
    (int)d_queries.get1()<<", "<<
    (int)d_queries.get5()<<", "<<
    (int)d_queries.get10()<<". Max queries/second: "<<(int)d_queries.getMax()<<
    "<br>"<<endl;

  if(d_cachemisses.get10()+d_cachehits.get10()>0)
    ret<<"Cache hitrate, 1, 5, 10 minute averages: "<<
      makePercentage((d_cachehits.get1()*100.0)/((d_cachehits.get1())+(d_cachemisses.get1())))<<", "<<
      makePercentage((d_cachehits.get5()*100.0)/((d_cachehits.get5())+(d_cachemisses.get5())))<<", "<<
      makePercentage((d_cachehits.get10()*100.0)/((d_cachehits.get10())+(d_cachemisses.get10())))<<
      "<br>"<<endl;

  if(d_qcachemisses.get10()+d_qcachehits.get10()>0)
    ret<<"Backend query cache hitrate, 1, 5, 10 minute averages: "<<std::setprecision(2)<<
      makePercentage((d_qcachehits.get1()*100.0)/((d_qcachehits.get1())+(d_qcachemisses.get1())))<<", "<<
      makePercentage((d_qcachehits.get5()*100.0)/((d_qcachehits.get5())+(d_qcachemisses.get5())))<<", "<<
      makePercentage((d_qcachehits.get10()*100.0)/((d_qcachehits.get10())+(d_qcachemisses.get10())))<<
      "<br>"<<endl;

  ret<<"Backend query load, 1, 5, 10 minute averages: "<<std::setprecision(3)<<
    (int)d_qcachemisses.get1()<<", "<<
    (int)d_qcachemisses.get5()<<", "<<
    (int)d_qcachemisses.get10()<<". Max queries/second: "<<(int)d_qcachemisses.getMax()<<
    "<br>"<<endl;

  ret<<"Total queries: "<<S.read("udp-queries")<<". Question/answer latency: "<<S.read("latency")/1000.0<<"ms</p><br>"<<endl;
  if(req->getvars["ring"].empty()) {
    vector<string>entries=S.listRings();
    for(vector<string>::const_iterator i=entries.begin();i!=entries.end();++i)
      printtable(ret,*i,S.getRingTitle(*i));

    printvars(ret);
    if(arg().mustDo("webserver-print-arguments"))
      printargs(ret);
  }
  else if(S.ringExists(req->getvars["ring"]))
    printtable(ret,req->getvars["ring"],S.getRingTitle(req->getvars["ring"]),100);

  ret<<"</div></div>"<<endl;
  ret<<"<footer class=\"row\">"<<fullVersionString()<<"<br>&copy; 2013 - 2017 <a href=\"http://www.powerdns.com/\">PowerDNS.COM BV</a>.</footer>"<<endl;
  ret<<"</body></html>"<<endl;

  resp->body = ret.str();
  resp->status = 200;
}

/** Helper to build a record content as needed. */
static inline string makeRecordContent(const QType& qtype, const string& content, bool noDot) {
  // noDot: for backend storage, pass true. for API users, pass false.
  std::unique_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(qtype.getCode(), 1, content));
  return drc->getZoneRepresentation(noDot);
}

/** "Normalize" record content for API consumers. */
static inline string makeApiRecordContent(const QType& qtype, const string& content) {
  return makeRecordContent(qtype, content, false);
}

/** "Normalize" record content for backend storage. */
static inline string makeBackendRecordContent(const QType& qtype, const string& content) {
  return makeRecordContent(qtype, content, true);
}

static Json::object getZoneInfo(const DomainInfo& di, DNSSECKeeper *dk) {
  string zoneId = apiZoneNameToId(di.zone);
  return Json::object {
    // id is the canonical lookup key, which doesn't actually match the name (in some cases)
    { "id", zoneId },
    { "url", "/api/v1/servers/localhost/zones/" + zoneId },
    { "name", di.zone.toString() },
    { "kind", di.getKindString() },
    { "dnssec", dk->isSecuredZone(di.zone) },
    { "account", di.account },
    { "masters", di.masters },
    { "serial", (double)di.serial },
    { "notified_serial", (double)di.notified_serial },
    { "last_check", (double)di.last_check }
  };
}

static void fillZone(const DNSName& zonename, HttpResponse* resp) {
  UeberBackend B;
  DomainInfo di;
  if(!B.getDomainInfo(zonename, di))
    throw ApiException("Could not find domain '"+zonename.toString()+"'");

  DNSSECKeeper dk(&B);
  Json::object doc = getZoneInfo(di, &dk);
  // extra stuff getZoneInfo doesn't do for us (more expensive)
  string soa_edit_api;
  di.backend->getDomainMetadataOne(zonename, "SOA-EDIT-API", soa_edit_api);
  doc["soa_edit_api"] = soa_edit_api;
  string soa_edit;
  di.backend->getDomainMetadataOne(zonename, "SOA-EDIT", soa_edit);
  doc["soa_edit"] = soa_edit;

  vector<DNSResourceRecord> records;
  vector<Comment> comments;

  // load all records + sort
  {
    DNSResourceRecord rr;
    di.backend->list(zonename, di.id, true); // incl. disabled
    while(di.backend->get(rr)) {
      if (!rr.qtype.getCode())
        continue; // skip empty non-terminals
      records.push_back(rr);
    }
    sort(records.begin(), records.end(), [](const DNSResourceRecord& a, const DNSResourceRecord& b) {
            if (a.qname == b.qname) {
                return b.qtype < a.qtype;
            }
            return b.qname < a.qname;
        });
  }

  // load all comments + sort
  {
    Comment comment;
    di.backend->listComments(di.id);
    while(di.backend->getComment(comment)) {
      comments.push_back(comment);
    }
    sort(comments.begin(), comments.end(), [](const Comment& a, const Comment& b) {
            if (a.qname == b.qname) {
                return b.qtype < a.qtype;
            }
            return b.qname < a.qname;
        });
  }

  Json::array rrsets;
  Json::object rrset;
  Json::array rrset_records;
  Json::array rrset_comments;
  DNSName current_qname;
  QType current_qtype;
  uint32_t ttl;
  auto rit = records.begin();
  auto cit = comments.begin();

  while (rit != records.end() || cit != comments.end()) {
    if (cit == comments.end() || (rit != records.end() && (cit->qname.toString() <= rit->qname.toString() || cit->qtype < rit->qtype || cit->qtype == rit->qtype))) {
      current_qname = rit->qname;
      current_qtype = rit->qtype;
      ttl = rit->ttl;
    } else {
      current_qname = cit->qname;
      current_qtype = cit->qtype;
      ttl = 0;
    }

    while(rit != records.end() && rit->qname == current_qname && rit->qtype == current_qtype) {
      ttl = min(ttl, rit->ttl);
      rrset_records.push_back(Json::object {
        { "disabled", rit->disabled },
        { "content", makeApiRecordContent(rit->qtype, rit->content) }
      });
      rit++;
    }
    while (cit != comments.end() && cit->qname == current_qname && cit->qtype == current_qtype) {
      rrset_comments.push_back(Json::object {
        { "modified_at", (double)cit->modified_at },
        { "account", cit->account },
        { "content", cit->content }
      });
      cit++;
    }

    rrset["name"] = current_qname.toString();
    rrset["type"] = current_qtype.getName();
    rrset["records"] = rrset_records;
    rrset["comments"] = rrset_comments;
    rrset["ttl"] = (double)ttl;
    rrsets.push_back(rrset);
    rrset.clear();
    rrset_records.clear();
    rrset_comments.clear();
  }

  doc["rrsets"] = rrsets;

  resp->setBody(doc);
}

void productServerStatisticsFetch(map<string,string>& out)
{
  vector<string> items = S.getEntries();
  for(const string& item :  items) {
    out[item] = std::to_string(S.read(item));
  }

  // add uptime
  out["uptime"] = std::to_string(time(0) - s_starttime);
}

static void gatherRecords(const Json container, const DNSName& qname, const QType qtype, const int ttl, vector<DNSResourceRecord>& new_records, vector<DNSResourceRecord>& new_ptrs) {
  UeberBackend B;
  DNSResourceRecord rr;
  rr.qname = qname;
  rr.qtype = qtype;
  rr.auth = 1;
  rr.ttl = ttl;
  for(auto record : container["records"].array_items()) {
    string content = stringFromJson(record, "content");
    rr.disabled = boolFromJson(record, "disabled");

    // validate that the client sent something we can actually parse, and require that data to be dotted.
    try {
      if (rr.qtype.getCode() != QType::AAAA) {
        string tmp = makeApiRecordContent(rr.qtype, content);
        if (!pdns_iequals(tmp, content)) {
          throw std::runtime_error("Not in expected format (parsed as '"+tmp+"')");
        }
      } else {
        struct in6_addr tmpbuf;
        if (inet_pton(AF_INET6, content.c_str(), &tmpbuf) != 1 || content.find('.') != string::npos) {
          throw std::runtime_error("Invalid IPv6 address");
        }
      }
      rr.content = makeBackendRecordContent(rr.qtype, content);
    }
    catch(std::exception& e)
    {
      throw ApiException("Record "+rr.qname.toString()+"/"+rr.qtype.getName()+" '"+content+"': "+e.what());
    }

    if ((rr.qtype.getCode() == QType::A || rr.qtype.getCode() == QType::AAAA) &&
        boolFromJson(record, "set-ptr", false) == true) {
      DNSResourceRecord ptr;
      makePtr(rr, &ptr);

      // verify that there's a zone for the PTR
      DNSPacket fakePacket(false);
      SOAData sd;
      fakePacket.qtype = QType::PTR;
      if (!B.getAuth(&fakePacket, &sd, ptr.qname))
        throw ApiException("Could not find domain for PTR '"+ptr.qname.toString()+"' requested for '"+ptr.content+"'");

      ptr.domain_id = sd.domain_id;
      new_ptrs.push_back(ptr);
    }

    new_records.push_back(rr);
  }
}

static void gatherComments(const Json container, const DNSName& qname, const QType qtype, vector<Comment>& new_comments) {
  Comment c;
  c.qname = qname;
  c.qtype = qtype;

  time_t now = time(0);
  for (auto comment : container["comments"].array_items()) {
    c.modified_at = intFromJson(comment, "modified_at", now);
    c.content = stringFromJson(comment, "content");
    c.account = stringFromJson(comment, "account");
    new_comments.push_back(c);
  }
}

static void updateDomainSettingsFromDocument(const DomainInfo& di, const DNSName& zonename, const Json document) {
  string zonemaster;
  for(auto value : document["masters"].array_items()) {
    string master = value.string_value();
    if (master.empty())
      throw ApiException("Master can not be an empty string");
    zonemaster += master + " ";
  }

  di.backend->setKind(zonename, DomainInfo::stringToKind(stringFromJson(document, "kind")));
  di.backend->setMaster(zonename, zonemaster);

  if (document["soa_edit_api"].is_string()) {
    di.backend->setDomainMetadataOne(zonename, "SOA-EDIT-API", document["soa_edit_api"].string_value());
  }
  if (document["soa_edit"].is_string()) {
    di.backend->setDomainMetadataOne(zonename, "SOA-EDIT", document["soa_edit"].string_value());
  }
  if (document["account"].is_string()) {
    di.backend->setAccount(zonename, document["account"].string_value());
  }
}

static bool isValidMetadataKind(const string& kind, bool readonly) {
  static vector<string> builtinOptions {
    "ALLOW-AXFR-FROM",
    "AXFR-SOURCE",
    "ALLOW-DNSUPDATE-FROM",
    "TSIG-ALLOW-DNSUPDATE",
    "FORWARD-DNSUPDATE",
    "SOA-EDIT-DNSUPDATE",
    "NOTIFY-DNSUPDATE",
    "ALSO-NOTIFY",
    "AXFR-MASTER-TSIG",
    "GSS-ALLOW-AXFR-PRINCIPAL",
    "GSS-ACCEPTOR-PRINCIPAL",
    "IXFR",
    "LUA-AXFR-SCRIPT",
    "NSEC3NARROW",
    "NSEC3PARAM",
    "PRESIGNED",
    "PUBLISH-CDNSKEY",
    "PUBLISH-CDS",
    "SOA-EDIT",
    "TSIG-ALLOW-AXFR",
    "TSIG-ALLOW-DNSUPDATE"
  };

  // the following options do not allow modifications via API
  static vector<string> protectedOptions {
    "NSEC3NARROW",
    "NSEC3PARAM",
    "PRESIGNED",
    "LUA-AXFR-SCRIPT"
  };

  if (kind.find("X-") == 0)
    return true;

  bool found = false;

  for (const string& s : builtinOptions) {
    if (kind == s) {
      for (const string& s2 : protectedOptions) {
        if (!readonly && s == s2)
          return false;
      }
      found = true;
      break;
    }
  }

  return found;
}

static void apiZoneMetadata(HttpRequest* req, HttpResponse *resp) {
  DNSName zonename = apiZoneIdToName(req->parameters["id"]);
  UeberBackend B;

  if (req->method == "GET") {
    map<string, vector<string> > md;
    Json::array document;

    if (!B.getAllDomainMetadata(zonename, md))
      throw HttpNotFoundException();

    for (const auto& i : md) {
      Json::array entries;
      for (string j : i.second)
        entries.push_back(j);

      Json::object key {
        { "type", "Metadata" },
        { "kind", i.first },
        { "metadata", entries }
      };

      document.push_back(key);
    }

    resp->setBody(document);
  } else if (req->method == "POST" && !::arg().mustDo("api-readonly")) {
    auto document = req->json();
    string kind;
    vector<string> entries;

    try {
      kind = stringFromJson(document, "kind");
    } catch (JsonException) {
      throw ApiException("kind is not specified or not a string");
    }

    if (!isValidMetadataKind(kind, false))
      throw ApiException("Unsupported metadata kind '" + kind + "'");

    vector<string> vecMetadata;

    if (!B.getDomainMetadata(zonename, kind, vecMetadata))
      throw ApiException("Could not retrieve metadata entries for domain '" +
        zonename.toString() + "'");

    auto& metadata = document["metadata"];
    if (!metadata.is_array())
      throw ApiException("metadata is not specified or not an array");

    for (const auto& i : metadata.array_items()) {
      if (!i.is_string())
        throw ApiException("metadata must be strings");
      else if (std::find(vecMetadata.cbegin(),
                         vecMetadata.cend(),
                         i.string_value()) == vecMetadata.cend()) {
        vecMetadata.push_back(i.string_value());
      }
    }

    if (!B.setDomainMetadata(zonename, kind, vecMetadata))
      throw ApiException("Could not update metadata entries for domain '" +
        zonename.toString() + "'");

    Json::array respMetadata;
    for (const string& s : vecMetadata)
      respMetadata.push_back(s);

    Json::object key {
      { "type", "Metadata" },
      { "kind", document["kind"] },
      { "metadata", respMetadata }
    };

    resp->status = 201;
    resp->setBody(key);
  } else
    throw HttpMethodNotAllowedException();
}

static void apiZoneMetadataKind(HttpRequest* req, HttpResponse* resp) {
  DNSName zonename = apiZoneIdToName(req->parameters["id"]);
  string kind = req->parameters["kind"];
  UeberBackend B;

  if (req->method == "GET") {
    vector<string> metadata;
    Json::object document;
    Json::array entries;

    if (!B.getDomainMetadata(zonename, kind, metadata))
      throw HttpNotFoundException();
    else if (!isValidMetadataKind(kind, true))
      throw ApiException("Unsupported metadata kind '" + kind + "'");

    document["type"] = "Metadata";
    document["kind"] = kind;

    for (const string& i : metadata)
      entries.push_back(i);

    document["metadata"] = entries;
    resp->setBody(document);
  } else if (req->method == "PUT" && !::arg().mustDo("api-readonly")) {
    auto document = req->json();

    if (!isValidMetadataKind(kind, false))
      throw ApiException("Unsupported metadata kind '" + kind + "'");

    vector<string> vecMetadata;
    auto& metadata = document["metadata"];
    if (!metadata.is_array())
      throw ApiException("metadata is not specified or not an array");

    for (const auto& i : metadata.array_items()) {
      if (!i.is_string())
        throw ApiException("metadata must be strings");
      vecMetadata.push_back(i.string_value());
    }

    if (!B.setDomainMetadata(zonename, kind, vecMetadata))
      throw ApiException("Could not update metadata entries for domain '" + zonename.toString() + "'");

    Json::object key {
      { "type", "Metadata" },
      { "kind", kind },
      { "metadata", metadata }
    };

    resp->setBody(key);
  } else if (req->method == "DELETE" && !::arg().mustDo("api-readonly")) {
    if (!isValidMetadataKind(kind, false))
      throw ApiException("Unsupported metadata kind '" + kind + "'");

    vector<string> md;  // an empty vector will do it
    if (!B.setDomainMetadata(zonename, kind, md))
      throw ApiException("Could not delete metadata for domain '" + zonename.toString() + "' (" + kind + ")");
  } else
    throw HttpMethodNotAllowedException();
}

static void apiZoneCryptokeysGET(DNSName zonename, int inquireKeyId, HttpResponse *resp, DNSSECKeeper *dk) {
  DNSSECKeeper::keyset_t keyset=dk->getKeys(zonename, false);

  bool inquireSingleKey = inquireKeyId >= 0;

  Json::array doc;
  for(const auto& value : keyset) {
    if (inquireSingleKey && (unsigned)inquireKeyId != value.second.id) {
      continue;
    }

    string keyType;
    switch (value.second.keyType) {
      case DNSSECKeeper::KSK: keyType="ksk"; break;
      case DNSSECKeeper::ZSK: keyType="zsk"; break;
      case DNSSECKeeper::CSK: keyType="csk"; break;
    }

    Json::object key {
        { "type", "Cryptokey" },
        { "id", (int)value.second.id },
        { "active", value.second.active },
        { "keytype", keyType },
        { "flags", (uint16_t)value.first.d_flags },
        { "dnskey", value.first.getDNSKEY().getZoneRepresentation() }
    };

    if (value.second.keyType == DNSSECKeeper::KSK || value.second.keyType == DNSSECKeeper::CSK) {
      Json::array dses;
      for(const int keyid : { 1, 2, 3, 4 })
        try {
          dses.push_back(makeDSFromDNSKey(zonename, value.first.getDNSKEY(), keyid).getZoneRepresentation());
        } catch (...) {}
      key["ds"] = dses;
    }

    if (inquireSingleKey) {
      key["privatekey"] = value.first.getKey()->convertToISC();
      resp->setBody(key);
      return;
    }
    doc.push_back(key);
  }

  if (inquireSingleKey) {
    // we came here because we couldn't find the requested key.
    throw HttpNotFoundException();
  }
  resp->setBody(doc);

}

/*
 * This method handles DELETE requests for URL /api/v1/servers/:server_id/zones/:zone_name/cryptokeys/:cryptokey_id .
 * It deletes a key from :zone_name specified by :cryptokey_id.
 * Server Answers:
 * Case 1: the backend returns true on removal. This means the key is gone.
 *      The server returns 200 OK, no body.
 * Case 2: the backend returns false on removal. An error occurred.
 *      The sever returns 422 Unprocessable Entity with message "Could not DELETE :cryptokey_id".
 * */
static void apiZoneCryptokeysDELETE(DNSName zonename, int inquireKeyId, HttpRequest *req, HttpResponse *resp, DNSSECKeeper *dk) {
  if (dk->removeKey(zonename, inquireKeyId)) {
    resp->body = "";
    resp->status = 200;
  } else {
    resp->setErrorResult("Could not DELETE " + req->parameters["key_id"], 422);
  }
}

/*
 * This method adds a key to a zone by generate it or content parameter.
 * Parameter:
 *  {
 *  "content" : "key The format used is compatible with BIND and NSD/LDNS" <string>
 *  "keytype" : "ksk|zsk" <string>
 *  "active"  : "true|false" <value>
 *  "algo" : "key generation algorithm "name|number" as default"<string> https://doc.powerdns.com/md/authoritative/dnssec/#supported-algorithms
 *  "bits" : number of bits <int>
 *  }
 *
 * Response:
 *  Case 1: keytype isn't ksk|zsk
 *    The server returns 422 Unprocessable Entity {"error" : "Invalid keytype 'keytype'"}
 *  Case 2: 'bits' must be a positive integer value.
 *    The server returns 422 Unprocessable Entity {"error" : "'bits' must be a positive integer value."}
 *  Case 3: The "algo" isn't supported
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

static void apiZoneCryptokeysPOST(DNSName zonename, HttpRequest *req, HttpResponse *resp, DNSSECKeeper *dk) {
  auto document = req->json();
  auto content = document["content"];
  bool active = boolFromJson(document, "active", false);
  bool keyOrZone;

  if (stringFromJson(document, "keytype") == "ksk") {
    keyOrZone = true;
  } else if (stringFromJson(document, "keytype") == "zsk") {
    keyOrZone = false;
  } else {
    throw ApiException("Invalid keytype " + stringFromJson(document, "keytype"));
  }

  int64_t insertedId;

  if (content.is_null()) {
    int bits = 0;
    auto docbits = document["bits"];
    if (!docbits.is_null()) {
      if (!docbits.is_number() || (fmod(docbits.number_value(), 1.0) != 0) || docbits.int_value() < 0) {
        throw ApiException("'bits' must be a positive integer value");
      } else {
        bits = docbits.int_value();
      }
    }
    int algorithm = 13; // ecdsa256
    auto providedAlgo = document["algo"];
    if (providedAlgo.is_string()) {
      algorithm = DNSSECKeeper::shorthand2algorithm(providedAlgo.string_value());
      if (algorithm == -1)
        throw ApiException("Unknown algorithm: " + providedAlgo.string_value());
    } else if (providedAlgo.is_number()) {
      algorithm = providedAlgo.int_value();
    } else if (!providedAlgo.is_null()) {
      throw ApiException("Unknown algorithm: " + providedAlgo.string_value());
    }

    try {
      dk->addKey(zonename, keyOrZone, algorithm, insertedId, bits, active);
    } catch (std::runtime_error& error) {
      throw ApiException(error.what());
    }
    if (insertedId < 0)
      throw ApiException("Adding key failed, perhaps DNSSEC not enabled in configuration?");
  } else if (document["bits"].is_null() && document["algo"].is_null()) {
    auto keyData = stringFromJson(document, "content");
    DNSKEYRecordContent dkrc;
    DNSSECPrivateKey dpk;
    try {
      shared_ptr<DNSCryptoKeyEngine> dke(DNSCryptoKeyEngine::makeFromISCString(dkrc, keyData));
      dpk.d_algorithm = dkrc.d_algorithm;
      if(dpk.d_algorithm == 7)
        dpk.d_algorithm = 5;

      if (keyOrZone)
        dpk.d_flags = 257;
      else
        dpk.d_flags = 256;

      dpk.setKey(dke);
    }
    catch (std::runtime_error& error) {
      throw ApiException("Key could not be parsed. Make sure your key format is correct.");
    } try {
      dk->addKey(zonename, dpk,insertedId, active);
    } catch (std::runtime_error& error) {
      throw ApiException(error.what());
    }
    if (insertedId < 0)
      throw ApiException("Adding key failed, perhaps DNSSEC not enabled in configuration?");
  } else {
    throw ApiException("Either you submit just the 'content' field or you leave 'content' empty and submit the other fields.");
  }
  apiZoneCryptokeysGET(zonename, insertedId, resp, dk);
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
static void apiZoneCryptokeysPUT(DNSName zonename, int inquireKeyId, HttpRequest *req, HttpResponse *resp, DNSSECKeeper *dk) {
  //throws an exception if the Body is empty
  auto document = req->json();
  //throws an exception if the key does not exist or is not a bool
  bool active = boolFromJson(document, "active");
  if (active) {
    if (!dk->activateKey(zonename, inquireKeyId)) {
      resp->setErrorResult("Could not activate Key: " + req->parameters["key_id"] + " in Zone: " + zonename.toString(), 422);
      return;
    }
  } else {
    if (!dk->deactivateKey(zonename, inquireKeyId)) {
      resp->setErrorResult("Could not deactivate Key: " + req->parameters["key_id"] + " in Zone: " + zonename.toString(), 422);
      return;
    }
  }
  resp->body = "";
  resp->status = 204;
  return;
}

/*
 * This method chooses the right functionality for the request. It also checks for a cryptokey_id which has to be passed
 * by URL /api/v1/servers/:server_id/zones/:zone_name/cryptokeys/:cryptokey_id .
 * If the the HTTP-request-method isn't supported, the function returns a response with the 405 code (method not allowed).
 * */
static void apiZoneCryptokeys(HttpRequest *req, HttpResponse *resp) {
  DNSName zonename = apiZoneIdToName(req->parameters["id"]);

  UeberBackend B;
  DNSSECKeeper dk(&B);
  DomainInfo di;
  if (!B.getDomainInfo(zonename, di))
    throw HttpBadRequestException();

  int inquireKeyId = -1;
  if (req->parameters.count("key_id")) {
    inquireKeyId = std::stoi(req->parameters["key_id"]);
  }

  if (req->method == "GET") {
    apiZoneCryptokeysGET(zonename, inquireKeyId, resp, &dk);
  } else if (req->method == "DELETE") {
    if (inquireKeyId == -1)
      throw HttpBadRequestException();
    apiZoneCryptokeysDELETE(zonename, inquireKeyId, req, resp, &dk);
  } else if (req->method == "POST") {
    apiZoneCryptokeysPOST(zonename, req, resp, &dk);
  } else if (req->method == "PUT") {
    if (inquireKeyId == -1)
      throw HttpBadRequestException();
    apiZoneCryptokeysPUT(zonename, inquireKeyId, req, resp, &dk);
  } else {
    throw HttpMethodNotAllowedException(); //Returns method not allowed
  }
}

static void gatherRecordsFromZone(const std::string& zonestring, vector<DNSResourceRecord>& new_records, DNSName zonename) {
  DNSResourceRecord rr;
  vector<string> zonedata;
  stringtok(zonedata, zonestring, "\r\n");

  ZoneParserTNG zpt(zonedata, zonename);

  bool seenSOA=false;

  string comment = "Imported via the API";

  try {
    while(zpt.get(rr, &comment)) {
      if(seenSOA && rr.qtype.getCode() == QType::SOA)
        continue;
      if(rr.qtype.getCode() == QType::SOA)
        seenSOA=true;

      new_records.push_back(rr);
    }
  }
  catch(std::exception& ae) {
    throw ApiException("An error occurred while parsing the zonedata: "+string(ae.what()));
  }
}

static void apiServerZones(HttpRequest* req, HttpResponse* resp) {
  UeberBackend B;
  DNSSECKeeper dk(&B);
  if (req->method == "POST" && !::arg().mustDo("api-readonly")) {
    DomainInfo di;
    auto document = req->json();
    DNSName zonename = apiNameToDNSName(stringFromJson(document, "name"));
    apiCheckNameAllowedCharacters(zonename.toString());

    bool exists = B.getDomainInfo(zonename, di);
    if(exists)
      throw ApiException("Domain '"+zonename.toString()+"' already exists");

    // validate 'kind' is set
    DomainInfo::DomainKind zonekind = DomainInfo::stringToKind(stringFromJson(document, "kind"));

    string zonestring = document["zone"].string_value();
    auto rrsets = document["rrsets"];
    if (rrsets.is_array() && zonestring != "")
      throw ApiException("You cannot give rrsets AND zone data as text");

    auto nameservers = document["nameservers"];
    if (!nameservers.is_array() && zonekind != DomainInfo::Slave)
      throw ApiException("Nameservers list must be given (but can be empty if NS records are supplied)");

    string soa_edit_api_kind;
    if (document["soa_edit_api"].is_string()) {
      soa_edit_api_kind = document["soa_edit_api"].string_value();
    }
    else {
      soa_edit_api_kind = "DEFAULT";
    }
    string soa_edit_kind = document["soa_edit"].string_value();

    // if records/comments are given, load and check them
    bool have_soa = false;
    bool have_zone_ns = false;
    vector<DNSResourceRecord> new_records;
    vector<Comment> new_comments;
    vector<DNSResourceRecord> new_ptrs;

    if (rrsets.is_array()) {
      for (const auto& rrset : rrsets.array_items()) {
        DNSName qname = apiNameToDNSName(stringFromJson(rrset, "name"));
        apiCheckQNameAllowedCharacters(qname.toString());
        QType qtype;
        qtype = stringFromJson(rrset, "type");
        if (qtype.getCode() == 0) {
          throw ApiException("RRset "+qname.toString()+" IN "+stringFromJson(rrset, "type")+": unknown type given");
        }
        if (rrset["records"].is_array()) {
          int ttl = intFromJson(rrset, "ttl");
          gatherRecords(rrset, qname, qtype, ttl, new_records, new_ptrs);
        }
        if (rrset["comments"].is_array()) {
          gatherComments(rrset, qname, qtype, new_comments);
        }
      }
    } else if (zonestring != "") {
      gatherRecordsFromZone(zonestring, new_records, zonename);
    }

    for(auto& rr : new_records) {
      if (!rr.qname.isPartOf(zonename) && rr.qname != zonename)
        throw ApiException("RRset "+rr.qname.toString()+" IN "+rr.qtype.getName()+": Name is out of zone");
      apiCheckQNameAllowedCharacters(rr.qname.toString());

      if (rr.qtype.getCode() == QType::SOA && rr.qname==zonename) {
        have_soa = true;
        increaseSOARecord(rr, soa_edit_api_kind, soa_edit_kind);
        // fixup dots after serializeSOAData/increaseSOARecord
        rr.content = makeBackendRecordContent(rr.qtype, rr.content);
      }
      if (rr.qtype.getCode() == QType::NS && rr.qname==zonename) {
        have_zone_ns = true;
      }
    }

    // synthesize RRs as needed
    DNSResourceRecord autorr;
    autorr.qname = zonename;
    autorr.auth = 1;
    autorr.ttl = ::arg().asNum("default-ttl");

    if (!have_soa && zonekind != DomainInfo::Slave) {
      // synthesize a SOA record so the zone "really" exists
      string soa = (boost::format("%s %s %lu")
        % ::arg()["default-soa-name"]
        % (::arg().isEmpty("default-soa-mail") ? (DNSName("hostmaster.") + zonename).toString() : ::arg()["default-soa-mail"])
        % document["serial"].int_value()
      ).str();
      SOAData sd;
      fillSOAData(soa, sd);  // fills out default values for us
      autorr.qtype = "SOA";
      autorr.content = serializeSOAData(sd);
      increaseSOARecord(autorr, soa_edit_api_kind, soa_edit_kind);
      // fixup dots after serializeSOAData/increaseSOARecord
      autorr.content = makeBackendRecordContent(autorr.qtype, autorr.content);
      new_records.push_back(autorr);
    }

    // create NS records if nameservers are given
    for (auto value : nameservers.array_items()) {
      string nameserver = value.string_value();
      if (nameserver.empty())
        throw ApiException("Nameservers must be non-empty strings");
      if (!isCanonical(nameserver))
        throw ApiException("Nameserver is not canonical: '" + nameserver + "'");
      try {
        // ensure the name parses
        autorr.content = DNSName(nameserver).toStringRootDot();
      } catch (...) {
        throw ApiException("Unable to parse DNS Name for NS '" + nameserver + "'");
      }
      autorr.qtype = "NS";
      new_records.push_back(autorr);
      if (have_zone_ns) {
        throw ApiException("Nameservers list MUST NOT be mixed with zone-level NS in rrsets");
      }
    }

    // no going back after this
    if(!B.createDomain(zonename))
      throw ApiException("Creating domain '"+zonename.toString()+"' failed");

    if(!B.getDomainInfo(zonename, di))
      throw ApiException("Creating domain '"+zonename.toString()+"' failed: lookup of domain ID failed");

    // updateDomainSettingsFromDocument does NOT fill out the default we've established above.
    if (!soa_edit_api_kind.empty()) {
      di.backend->setDomainMetadataOne(zonename, "SOA-EDIT-API", soa_edit_api_kind);
    }

    di.backend->startTransaction(zonename, di.id);

    for(auto rr : new_records) {
      rr.domain_id = di.id;
      di.backend->feedRecord(rr);
    }
    for(Comment& c : new_comments) {
      c.domain_id = di.id;
      di.backend->feedComment(c);
    }

    updateDomainSettingsFromDocument(di, zonename, document);

    di.backend->commitTransaction();

    storeChangedPTRs(B, new_ptrs);

    fillZone(zonename, resp);
    resp->status = 201;
    return;
  }

  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  vector<DomainInfo> domains;
  B.getAllDomains(&domains, true); // incl. disabled

  Json::array doc;
  for(const DomainInfo& di : domains) {
    doc.push_back(getZoneInfo(di, &dk));
  }
  resp->setBody(doc);
}

static void apiServerZoneDetail(HttpRequest* req, HttpResponse* resp) {
  DNSName zonename = apiZoneIdToName(req->parameters["id"]);

  if(req->method == "PUT" && !::arg().mustDo("api-readonly")) {
    // update domain settings
    UeberBackend B;
    DomainInfo di;
    if(!B.getDomainInfo(zonename, di))
      throw ApiException("Could not find domain '"+zonename.toString()+"'");

    updateDomainSettingsFromDocument(di, zonename, req->json());

    resp->body = "";
    resp->status = 204; // No Content, but indicate success
    return;
  }
  else if(req->method == "DELETE" && !::arg().mustDo("api-readonly")) {
    // delete domain
    UeberBackend B;
    DomainInfo di;
    if(!B.getDomainInfo(zonename, di))
      throw ApiException("Could not find domain '"+zonename.toString()+"'");

    if(!di.backend->deleteDomain(zonename))
      throw ApiException("Deleting domain '"+zonename.toString()+"' failed: backend delete failed/unsupported");

    // empty body on success
    resp->body = "";
    resp->status = 204; // No Content: declare that the zone is gone now
    return;
  } else if (req->method == "PATCH" && !::arg().mustDo("api-readonly")) {
    patchZone(req, resp);
    return;
  } else if (req->method == "GET") {
    fillZone(zonename, resp);
    return;
  }

  throw HttpMethodNotAllowedException();
}

static void apiServerZoneExport(HttpRequest* req, HttpResponse* resp) {
  DNSName zonename = apiZoneIdToName(req->parameters["id"]);

  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  ostringstream ss;

  UeberBackend B;
  DomainInfo di;
  if(!B.getDomainInfo(zonename, di))
    throw ApiException("Could not find domain '"+zonename.toString()+"'");

  DNSResourceRecord rr;
  SOAData sd;
  di.backend->list(zonename, di.id);
  while(di.backend->get(rr)) {
    if (!rr.qtype.getCode())
      continue; // skip empty non-terminals

    ss <<
      rr.qname.toString() << "\t" <<
      rr.ttl << "\t" <<
      rr.qtype.getName() << "\t" <<
      makeApiRecordContent(rr.qtype, rr.content) <<
      endl;
  }

  if (req->accept_json) {
    resp->setBody(Json::object { { "zone", ss.str() } });
  } else {
    resp->headers["Content-Type"] = "text/plain; charset=us-ascii";
    resp->body = ss.str();
  }
}

static void apiServerZoneAxfrRetrieve(HttpRequest* req, HttpResponse* resp) {
  DNSName zonename = apiZoneIdToName(req->parameters["id"]);

  if(req->method != "PUT")
    throw HttpMethodNotAllowedException();

  UeberBackend B;
  DomainInfo di;
  if(!B.getDomainInfo(zonename, di))
    throw ApiException("Could not find domain '"+zonename.toString()+"'");

  if(di.masters.empty())
    throw ApiException("Domain '"+zonename.toString()+"' is not a slave domain (or has no master defined)");

  random_shuffle(di.masters.begin(), di.masters.end());
  Communicator.addSuckRequest(zonename, di.masters.front());
  resp->setSuccessResult("Added retrieval request for '"+zonename.toString()+"' from master "+di.masters.front());
}

static void apiServerZoneNotify(HttpRequest* req, HttpResponse* resp) {
  DNSName zonename = apiZoneIdToName(req->parameters["id"]);

  if(req->method != "PUT")
    throw HttpMethodNotAllowedException();

  UeberBackend B;
  DomainInfo di;
  if(!B.getDomainInfo(zonename, di))
    throw ApiException("Could not find domain '"+zonename.toString()+"'");

  if(!Communicator.notifyDomain(zonename))
    throw ApiException("Failed to add to the queue - see server log");

  resp->setSuccessResult("Notification queued");
}

static void makePtr(const DNSResourceRecord& rr, DNSResourceRecord* ptr) {
  if (rr.qtype.getCode() == QType::A) {
    uint32_t ip;
    if (!IpToU32(rr.content, &ip)) {
      throw ApiException("PTR: Invalid IP address given");
    }
    ptr->qname = DNSName((boost::format("%u.%u.%u.%u.in-addr.arpa.")
                  % ((ip >> 24) & 0xff)
                  % ((ip >> 16) & 0xff)
                  % ((ip >>  8) & 0xff)
                  % ((ip      ) & 0xff)
                         ).str());
  } else if (rr.qtype.getCode() == QType::AAAA) {
    ComboAddress ca(rr.content);
    char buf[3];
    ostringstream ss;
    for (int octet = 0; octet < 16; ++octet) {
      if (snprintf(buf, sizeof(buf), "%02x", ca.sin6.sin6_addr.s6_addr[octet]) != (sizeof(buf)-1)) {
        // this should be impossible: no byte should give more than two digits in hex format
        throw PDNSException("Formatting IPv6 address failed");
      }
      ss << buf[0] << '.' << buf[1] << '.';
    }
    string tmp = ss.str();
    tmp.resize(tmp.size()-1); // remove last dot
    // reverse and append arpa domain
    ptr->qname = DNSName(string(tmp.rbegin(), tmp.rend())) + DNSName("ip6.arpa.");
  } else {
    throw ApiException("Unsupported PTR source '" + rr.qname.toString() + "' type '" + rr.qtype.getName() + "'");
  }

  ptr->qtype = "PTR";
  ptr->ttl = rr.ttl;
  ptr->disabled = rr.disabled;
  ptr->content = rr.qname.toStringRootDot();
}

static void storeChangedPTRs(UeberBackend& B, vector<DNSResourceRecord>& new_ptrs) {
  for(const DNSResourceRecord& rr :  new_ptrs) {
    DNSPacket fakePacket(false);
    SOAData sd;
    sd.db = (DNSBackend *)-1;  // getAuth() cache bypass
    fakePacket.qtype = QType::PTR;

    if (!B.getAuth(&fakePacket, &sd, rr.qname))
      throw ApiException("Could not find domain for PTR '"+rr.qname.toString()+"' requested for '"+rr.content+"' (while saving)");

    string soa_edit_api_kind;
    string soa_edit_kind;
    bool soa_changed = false;
    DNSResourceRecord soarr;
    sd.db->getDomainMetadataOne(sd.qname, "SOA-EDIT-API", soa_edit_api_kind);
    sd.db->getDomainMetadataOne(sd.qname, "SOA-EDIT", soa_edit_kind);
    if (!soa_edit_api_kind.empty()) {
      soarr.qname = sd.qname;
      soarr.content = serializeSOAData(sd);
      soarr.qtype = "SOA";
      soarr.domain_id = sd.domain_id;
      soarr.auth = 1;
      soarr.ttl = sd.ttl;
      increaseSOARecord(soarr, soa_edit_api_kind, soa_edit_kind);
      // fixup dots after serializeSOAData/increaseSOARecord
      soarr.content = makeBackendRecordContent(soarr.qtype, soarr.content);
      soa_changed = true;
    }

    sd.db->startTransaction(sd.qname);
    if (!sd.db->replaceRRSet(sd.domain_id, rr.qname, rr.qtype, vector<DNSResourceRecord>(1, rr))) {
      sd.db->abortTransaction();
      throw ApiException("PTR-Hosting backend for "+rr.qname.toString()+"/"+rr.qtype.getName()+" does not support editing records.");
    }

    if (soa_changed) {
      sd.db->replaceRRSet(sd.domain_id, soarr.qname, soarr.qtype, vector<DNSResourceRecord>(1, soarr));
    }

    sd.db->commitTransaction();
    purgeAuthCachesExact(rr.qname);
  }
}

static void patchZone(HttpRequest* req, HttpResponse* resp) {
  UeberBackend B;
  DomainInfo di;
  DNSName zonename = apiZoneIdToName(req->parameters["id"]);
  if (!B.getDomainInfo(zonename, di))
    throw ApiException("Could not find domain '"+zonename.toString()+"'");

  vector<DNSResourceRecord> new_records;
  vector<Comment> new_comments;
  vector<DNSResourceRecord> new_ptrs;

  Json document = req->json();

  auto rrsets = document["rrsets"];
  if (!rrsets.is_array())
    throw ApiException("No rrsets given in update request");

  di.backend->startTransaction(zonename);

  try {
    string soa_edit_api_kind;
    string soa_edit_kind;
    di.backend->getDomainMetadataOne(zonename, "SOA-EDIT-API", soa_edit_api_kind);
    di.backend->getDomainMetadataOne(zonename, "SOA-EDIT", soa_edit_kind);
    bool soa_edit_done = false;

    for (const auto& rrset : rrsets.array_items()) {
      string changetype = toUpper(stringFromJson(rrset, "changetype"));
      DNSName qname = apiNameToDNSName(stringFromJson(rrset, "name"));
      apiCheckQNameAllowedCharacters(qname.toString());
      QType qtype;
      qtype = stringFromJson(rrset, "type");
      if (qtype.getCode() == 0) {
        throw ApiException("RRset "+qname.toString()+" IN "+stringFromJson(rrset, "type")+": unknown type given");
      }

      if (changetype == "DELETE") {
        // delete all matching qname/qtype RRs (and, implicitly comments).
        if (!di.backend->replaceRRSet(di.id, qname, qtype, vector<DNSResourceRecord>())) {
          throw ApiException("Hosting backend does not support editing records.");
        }
      }
      else if (changetype == "REPLACE") {
        // we only validate for REPLACE, as DELETE can be used to "fix" out of zone records.
        if (!qname.isPartOf(zonename) && qname != zonename)
          throw ApiException("RRset "+qname.toString()+" IN "+qtype.getName()+": Name is out of zone");

        bool replace_records = rrset["records"].is_array();
        bool replace_comments = rrset["comments"].is_array();

        if (!replace_records && !replace_comments) {
          throw ApiException("No change for RRset " + qname.toString() + " IN " + qtype.getName());
        }

        new_records.clear();
        new_comments.clear();

        if (replace_records) {
          // ttl shouldn't be part of DELETE, and it shouldn't be required if we don't get new records.
          int ttl = intFromJson(rrset, "ttl");
          // new_ptrs is merged.
          gatherRecords(rrset, qname, qtype, ttl, new_records, new_ptrs);

          for(DNSResourceRecord& rr : new_records) {
            rr.domain_id = di.id;
            if (rr.qtype.getCode() == QType::SOA && rr.qname==zonename) {
              soa_edit_done = increaseSOARecord(rr, soa_edit_api_kind, soa_edit_kind);
              rr.content = makeBackendRecordContent(rr.qtype, rr.content);
            }
          }
        }

        if (replace_comments) {
          gatherComments(rrset, qname, qtype, new_comments);

          for(Comment& c : new_comments) {
            c.domain_id = di.id;
          }
        }

        if (replace_records) {
          if (!di.backend->replaceRRSet(di.id, qname, qtype, new_records)) {
            throw ApiException("Hosting backend does not support editing records.");
          }
        }
        if (replace_comments) {
          if (!di.backend->replaceComments(di.id, qname, qtype, new_comments)) {
            throw ApiException("Hosting backend does not support editing comments.");
          }
        }
      }
      else
        throw ApiException("Changetype not understood");
    }

    // edit SOA (if needed)
    if (!soa_edit_api_kind.empty() && !soa_edit_done) {
      SOAData sd;
      if (!B.getSOA(zonename, sd))
        throw ApiException("No SOA found for domain '"+zonename.toString()+"'");

      DNSResourceRecord rr;
      rr.qname = zonename;
      rr.content = serializeSOAData(sd);
      rr.qtype = "SOA";
      rr.domain_id = di.id;
      rr.auth = 1;
      rr.ttl = sd.ttl;
      increaseSOARecord(rr, soa_edit_api_kind, soa_edit_kind);
      // fixup dots after serializeSOAData/increaseSOARecord
      rr.content = makeBackendRecordContent(rr.qtype, rr.content);

      if (!di.backend->replaceRRSet(di.id, rr.qname, rr.qtype, vector<DNSResourceRecord>(1, rr))) {
        throw ApiException("Hosting backend does not support editing records.");
      }
    }

  } catch(...) {
    di.backend->abortTransaction();
    throw;
  }
  di.backend->commitTransaction();

  purgeAuthCachesExact(zonename);

  // now the PTRs
  storeChangedPTRs(B, new_ptrs);

  resp->body = "";
  resp->status = 204; // No Content, but indicate success
  return;
}

static void apiServerSearchData(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  string q = req->getvars["q"];
  string sMax = req->getvars["max"];
  int maxEnts = 100;
  int ents = 0;

  if (q.empty())
    throw ApiException("Query q can't be blank");
  if (!sMax.empty())
    maxEnts = std::stoi(sMax);
  if (maxEnts < 1)
    throw ApiException("Maximum entries must be larger than 0");

  SimpleMatch sm(q,true);
  UeberBackend B;
  vector<DomainInfo> domains;
  vector<DNSResourceRecord> result_rr;
  vector<Comment> result_c;
  map<int,DomainInfo> zoneIdZone;
  map<int,DomainInfo>::iterator val;
  Json::array doc;

  B.getAllDomains(&domains, true);

  for(const DomainInfo di: domains)
  {
    if (ents < maxEnts && sm.match(di.zone)) {
      doc.push_back(Json::object {
        { "object_type", "zone" },
        { "zone_id", apiZoneNameToId(di.zone) },
        { "name", di.zone.toString() }
      });
      ents++;
    }
    zoneIdZone[di.id] = di; // populate cache
  }

  if (B.searchRecords(q, maxEnts, result_rr))
  {
    for(const DNSResourceRecord& rr: result_rr)
    {
      if (!rr.qtype.getCode())
        continue; // skip empty non-terminals

      auto object = Json::object {
        { "object_type", "record" },
        { "name", rr.qname.toString() },
        { "type", rr.qtype.getName() },
        { "ttl", (double)rr.ttl },
        { "disabled", rr.disabled },
        { "content", makeApiRecordContent(rr.qtype, rr.content) }
      };
      if ((val = zoneIdZone.find(rr.domain_id)) != zoneIdZone.end()) {
        object["zone_id"] = apiZoneNameToId(val->second.zone);
        object["zone"] = val->second.zone.toString();
      }
      doc.push_back(object);
    }
  }

  if (B.searchComments(q, maxEnts, result_c))
  {
    for(const Comment &c: result_c)
    {
      auto object = Json::object {
        { "object_type", "comment" },
        { "name", c.qname.toString() },
        { "content", c.content }
      };
      if ((val = zoneIdZone.find(c.domain_id)) != zoneIdZone.end()) {
        object["zone_id"] = apiZoneNameToId(val->second.zone);
        object["zone"] = val->second.zone.toString();
      }
      doc.push_back(object);
    }
  }

  resp->setBody(doc);
}

void apiServerCacheFlush(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "PUT")
    throw HttpMethodNotAllowedException();

  DNSName canon = apiNameToDNSName(req->getvars["domain"]);

  uint64_t count = purgeAuthCachesExact(canon);
  resp->setBody(Json::object {
      { "count", (int) count },
      { "result", "Flushed cache." }
  });
}

void AuthWebServer::cssfunction(HttpRequest* req, HttpResponse* resp)
{
  resp->headers["Cache-Control"] = "max-age=86400";
  resp->headers["Content-Type"] = "text/css";

  ostringstream ret;
  ret<<"* { box-sizing: border-box; margin: 0; padding: 0; }"<<endl;
  ret<<"body { color: black; background: white; margin-top: 1em; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; font-size: 10pt; position: relative; }"<<endl;
  ret<<"a { color: #0959c2; }"<<endl;
  ret<<"a:hover { color: #3B8EC8; }"<<endl;
  ret<<".row { width: 940px; max-width: 100%; min-width: 768px; margin: 0 auto; }"<<endl;
  ret<<".row:before, .row:after { display: table; content:\" \"; }"<<endl;
  ret<<".row:after { clear: both; }"<<endl;
  ret<<".columns { position: relative; min-height: 1px; float: left; }"<<endl;
  ret<<".all { width: 100%; }"<<endl;
  ret<<".headl { width: 60%; }"<<endl;
  ret<<".headr { width: 39.5%; float: right; background-repeat: no-repeat; margin-top: 7px; ";
  ret<<"background-image: url(data:image/png;base64,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);";
  ret<<" width: 154px; height: 20px; }"<<endl;
  ret<<"a#appname { margin: 0; font-size: 27px; color: #666; text-decoration: none; font-weight: bold; display: block; }"<<endl;
  ret<<"footer { border-top:  1px solid #ddd; padding-top: 4px; font-size: 12px; }"<<endl;
  ret<<"footer.row { margin-top: 1em; margin-bottom: 1em; }"<<endl;
  ret<<".panel { background: #f2f2f2; border: 1px solid #e6e6e6; margin: 0 0 22px 0; padding: 20px; }"<<endl;
  ret<<"table.data { width: 100%; border-spacing: 0; border-top: 1px solid #333; }"<<endl;
  ret<<"table.data td { border-bottom: 1px solid #333; padding: 2px; }"<<endl;
  ret<<"table.data tr:nth-child(2n) { background: #e2e2e2; }"<<endl;
  ret<<"table.data tr:hover { background: white; }"<<endl;
  ret<<".ringmeta { margin-bottom: 5px; }"<<endl;
  ret<<".resetring {float: right; }"<<endl;
  ret<<".resetring i { background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAA/klEQVQY01XPP04UUBgE8N/33vd2XZUWEuzYuMZEG4KFCQn2NhA4AIewAOMBPIG2xhNYeAcKGqkNCdmYlVBZGBIT4FHsbuE0U8xk/kAbqm9TOfI/nicfhmwgDNhvylUT58kxCp4l31L8SfH9IetJ2ev6PwyIwyZWsdb11/gbTK55Co+r8rmJaRPTFJcpZil+pTit7C5awMpA+Zpi1sRFE9MqflYOloYCjY2uP8EdYiGU4CVGUBubxKfOOLjrtOBmzvEilbVb/aQWvhRl0unBZVXe4XdnK+bprwqnhoyTsyZ+JG8Wk0apfExxlcp7PFruXH8gdxamWB4cyW2sIO4BG3czIp78jUIAAAAASUVORK5CYII=); width: 10px; height: 10px; margin-right: 2px; display: inline-block; background-repeat: no-repeat; }"<<endl;
  ret<<".resetring:hover i { background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAA2ElEQVQY013PMUoDcRDF4c+kEzxCsNNCrBQvIGhnlcYm11EkBxAraw8gglgIoiJpAoKIYlBcgrgopsma3c3fwt1k9cHA480M8xvQp/nMjorOWY5ov7IAYlpjQk7aYxcuWBpwFQgJnUcaYk7GhEDIGL5w+MVpKLIRyR2b4JOjvGhUKzHTv2W7iuSN479Dvu9plf1awbQ6y3x1sU5tjpVJcMbakF6Ycoas8Dl5xEHJ160wRdfqzXfa6XQ4PLDlicWUjxHxZfndL/N+RhiwNzl/Q6PDhn/qsl76H7prcApk2B1aAAAAAElFTkSuQmCC);}"<<endl;
  ret<<".resizering {float: right;}"<<endl;
  resp->body = ret.str();
  resp->status = 200;
}

void AuthWebServer::webThread()
{
  try {
    if(::arg().mustDo("api")) {
      d_ws->registerApiHandler("/api/v1/servers/localhost/cache/flush", &apiServerCacheFlush);
      d_ws->registerApiHandler("/api/v1/servers/localhost/config", &apiServerConfig);
      d_ws->registerApiHandler("/api/v1/servers/localhost/search-log", &apiServerSearchLog);
      d_ws->registerApiHandler("/api/v1/servers/localhost/search-data", &apiServerSearchData);
      d_ws->registerApiHandler("/api/v1/servers/localhost/statistics", &apiServerStatistics);
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/axfr-retrieve", &apiServerZoneAxfrRetrieve);
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/cryptokeys/<key_id>", &apiZoneCryptokeys);
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/cryptokeys", &apiZoneCryptokeys);
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/export", &apiServerZoneExport);
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/metadata/<kind>", &apiZoneMetadataKind);
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/metadata", &apiZoneMetadata);
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>/notify", &apiServerZoneNotify);
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones/<id>", &apiServerZoneDetail);
      d_ws->registerApiHandler("/api/v1/servers/localhost/zones", &apiServerZones);
      d_ws->registerApiHandler("/api/v1/servers/localhost", &apiServerDetail);
      d_ws->registerApiHandler("/api/v1/servers", &apiServer);
      d_ws->registerApiHandler("/api", &apiDiscovery);
    }
    if (::arg().mustDo("webserver")) {
      d_ws->registerWebHandler("/style.css", boost::bind(&AuthWebServer::cssfunction, this, _1, _2));
      d_ws->registerWebHandler("/", boost::bind(&AuthWebServer::indexfunction, this, _1, _2));
    }
    d_ws->go();
  }
  catch(...) {
    L<<Logger::Error<<"AuthWebServer thread caught an exception, dying"<<endl;
    exit(1);
  }
}
