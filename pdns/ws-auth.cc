/*
    Copyright (C) 2002 - 2014  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "utility.hh"
#include "dynlistener.hh"
#include "ws-auth.hh"
#include "json.hh"
#include "webserver.hh"
#include "logger.hh"
#include "packetcache.hh"
#include "statbag.hh"
#include "misc.hh"
#include "arguments.hh"
#include "dns.hh"
#include "comment.hh"
#include "ueberbackend.hh"
#include <boost/format.hpp>
#include <boost/foreach.hpp>
#include "namespaces.hh"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "ws-api.hh"
#include "version.hh"
#include "dnsseckeeper.hh"
#include <iomanip>
#include "zoneparser-tng.hh"

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif // HAVE_CONFIG_H

using namespace rapidjson;

extern StatBag S;

static void patchZone(HttpRequest* req, HttpResponse* resp);
static void makePtr(const DNSResourceRecord& rr, DNSResourceRecord* ptr);

AuthWebServer::AuthWebServer()
{
  d_start=time(0);
  d_min10=d_min5=d_min1=0;
  d_ws = 0;
  d_tid = 0;
  if(arg().mustDo("webserver")) {
    d_ws = new WebServer(arg()["webserver-address"], arg().asNum("webserver-port"));
    d_ws->bind();
  }
}

void AuthWebServer::go()
{
  if(arg().mustDo("webserver"))
  {
    S.doRings();
    pthread_create(&d_tid, 0, webThreadHelper, this);
    pthread_create(&d_tid, 0, statThreadHelper, this);
  }
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
  ret<<"<span class=resetring><i></i><a href=\"?resetring="<<ringname<<"\">Reset</a></span>"<<endl;
  ret<<"<h2>"<<title<<"</h2>"<<endl;
  ret<<"<div class=ringmeta>";
  ret<<"<a class=topXofY href=\"?ring="<<ringname<<"\">Showing: Top "<<limit<<" of "<<entries<<"</a>"<<endl;
  ret<<"<span class=resizering>Resize: ";
  unsigned int sizes[]={10,100,500,1000,10000,500000,0};
  for(int i=0;sizes[i];++i) {
    if(S.getRingSize(ringname)!=sizes[i])
      ret<<"<a href=\"?resizering="<<ringname<<"&amp;size="<<sizes[i]<<"\">"<<sizes[i]<<"</a> ";
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
    resp->headers["Location"] = "/";
    return;
  }
  if(!req->getvars["resizering"].empty()){
    int size=atoi(req->getvars["size"].c_str());
    if (S.ringExists(req->getvars["resizering"]) && size > 0 && size <= 500000)
      S.resizeRing(req->getvars["resizering"], atoi(req->getvars["size"].c_str()));
    resp->status = 301;
    resp->headers["Location"] = "/";
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
    d_queries.get1()<<", "<<
    d_queries.get5()<<", "<<
    d_queries.get10()<<". Max queries/second: "<<d_queries.getMax()<<
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
    d_qcachemisses.get1()<<", "<<
    d_qcachemisses.get5()<<", "<<
    d_qcachemisses.get10()<<". Max queries/second: "<<d_qcachemisses.getMax()<<
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
  else
    printtable(ret,req->getvars["ring"],S.getRingTitle(req->getvars["ring"]),100);

  ret<<"</div></div>"<<endl;
  ret<<"<footer class=\"row\">"<<fullVersionString()<<"<br>&copy; 2013 - 2015 <a href=\"http://www.powerdns.com/\">PowerDNS.COM BV</a>.</footer>"<<endl;
  ret<<"</body></html>"<<endl;

  resp->body = ret.str();
  resp->status = 200;
}

static void fillZone(const string& zonename, HttpResponse* resp) {
  UeberBackend B;
  DomainInfo di;
  DNSSECKeeper dk;
  if(!B.getDomainInfo(zonename, di))
    throw ApiException("Could not find domain '"+zonename+"'");

  Document doc;
  doc.SetObject();

  // id is the canonical lookup key, which doesn't actually match the name (in some cases)
  string zoneId = apiZoneNameToId(di.zone);
  Value jzoneId(zoneId.c_str(), doc.GetAllocator()); // copy
  doc.AddMember("id", jzoneId, doc.GetAllocator());
  string url = "/servers/localhost/zones/" + zoneId;
  Value jurl(url.c_str(), doc.GetAllocator()); // copy
  doc.AddMember("url", jurl, doc.GetAllocator());
  doc.AddMember("name", di.zone.c_str(), doc.GetAllocator());
  doc.AddMember("type", "Zone", doc.GetAllocator());
  doc.AddMember("kind", di.getKindString(), doc.GetAllocator());
  doc.AddMember("dnssec", dk.isSecuredZone(di.zone), doc.GetAllocator());
  string soa_edit_api;
  di.backend->getDomainMetadataOne(zonename, "SOA-EDIT-API", soa_edit_api);
  doc.AddMember("soa_edit_api", soa_edit_api.c_str(), doc.GetAllocator());
  string soa_edit;
  di.backend->getDomainMetadataOne(zonename, "SOA-EDIT", soa_edit);
  doc.AddMember("soa_edit", soa_edit.c_str(), doc.GetAllocator());
  Value masters;
  masters.SetArray();
  BOOST_FOREACH(const string& master, di.masters) {
    Value value(master.c_str(), doc.GetAllocator());
    masters.PushBack(value, doc.GetAllocator());
  }
  doc.AddMember("masters", masters, doc.GetAllocator());
  doc.AddMember("serial", di.serial, doc.GetAllocator());
  doc.AddMember("notified_serial", di.notified_serial, doc.GetAllocator());
  doc.AddMember("last_check", (unsigned int) di.last_check, doc.GetAllocator());

  // fill records
  DNSResourceRecord rr;
  Value records;
  records.SetArray();
  di.backend->list(zonename, di.id, true); // incl. disabled
  while(di.backend->get(rr)) {
    if (!rr.qtype.getCode())
      continue; // skip empty non-terminals

    Value object;
    object.SetObject();
    Value jname(rr.qname.c_str(), doc.GetAllocator()); // copy
    object.AddMember("name", jname, doc.GetAllocator());
    Value jtype(rr.qtype.getName().c_str(), doc.GetAllocator()); // copy
    object.AddMember("type", jtype, doc.GetAllocator());
    object.AddMember("ttl", rr.ttl, doc.GetAllocator());
    object.AddMember("disabled", rr.disabled, doc.GetAllocator());
    Value jcontent(rr.content.c_str(), doc.GetAllocator()); // copy
    object.AddMember("content", jcontent, doc.GetAllocator());
    records.PushBack(object, doc.GetAllocator());
  }
  doc.AddMember("records", records, doc.GetAllocator());

  // fill comments
  Comment comment;
  Value comments;
  comments.SetArray();
  di.backend->listComments(di.id);
  while(di.backend->getComment(comment)) {
    Value object;
    object.SetObject();
    Value jname(comment.qname.c_str(), doc.GetAllocator()); // copy
    object.AddMember("name", jname, doc.GetAllocator());
    Value jtype(comment.qtype.getName().c_str(), doc.GetAllocator()); // copy
    object.AddMember("type", jtype, doc.GetAllocator());
    object.AddMember("modified_at", (unsigned int) comment.modified_at, doc.GetAllocator());
    Value jaccount(comment.account.c_str(), doc.GetAllocator()); // copy
    object.AddMember("account", jaccount, doc.GetAllocator());
    Value jcontent(comment.content.c_str(), doc.GetAllocator()); // copy
    object.AddMember("content", jcontent, doc.GetAllocator());
    comments.PushBack(object, doc.GetAllocator());
  }
  doc.AddMember("comments", comments, doc.GetAllocator());

  resp->setBody(doc);
}

void productServerStatisticsFetch(map<string,string>& out)
{
  vector<string> items = S.getEntries();
  BOOST_FOREACH(const string& item, items) {
    out[item] = lexical_cast<string>(S.read(item));
  }

  // add uptime
  out["uptime"] = lexical_cast<string>(time(0) - s_starttime);
}

static void gatherRecords(const Value& container, vector<DNSResourceRecord>& new_records, vector<DNSResourceRecord>& new_ptrs) {
  UeberBackend B;
  DNSResourceRecord rr;
  const Value& records = container["records"];
  if (records.IsArray()) {
    for (SizeType idx = 0; idx < records.Size(); ++idx) {
      const Value& record = records[idx];
      rr.qname = stringFromJson(record, "name");
      rr.qtype = stringFromJson(record, "type");
      rr.content = stringFromJson(record, "content");
      rr.auth = 1;
      rr.ttl = intFromJson(record, "ttl");
      rr.disabled = boolFromJson(record, "disabled");

      try {
        shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(rr.qtype.getCode(), 1, rr.content));
        string tmp = drc->serialize(rr.qname);
      }
      catch(std::exception& e)
      {
        throw ApiException("Record "+rr.qname+"/"+rr.qtype.getName()+" "+rr.content+": "+e.what());
      }

      if ((rr.qtype.getCode() == QType::A || rr.qtype.getCode() == QType::AAAA) &&
          boolFromJson(record, "set-ptr", false) == true) {
        DNSResourceRecord ptr;
        makePtr(rr, &ptr);

        // verify that there's a zone for the PTR
        DNSPacket fakePacket;
        SOAData sd;
        fakePacket.qtype = QType::PTR;
        if (!B.getAuth(&fakePacket, &sd, ptr.qname, 0))
          throw ApiException("Could not find domain for PTR '"+ptr.qname+"' requested for '"+ptr.content+"'");

        ptr.domain_id = sd.domain_id;
        new_ptrs.push_back(ptr);
      }

      new_records.push_back(rr);
    }
  }
}

static void gatherComments(const Value& container, vector<Comment>& new_comments, bool use_name_type_from_container) {
  Comment c;
  if (use_name_type_from_container) {
    c.qname = stringFromJson(container, "name");
    c.qtype = stringFromJson(container, "type");
  }

  time_t now = time(0);
  const Value& comments = container["comments"];
  if (comments.IsArray()) {
    for(SizeType idx = 0; idx < comments.Size(); ++idx) {
      const Value& comment = comments[idx];
      if (!use_name_type_from_container) {
        c.qname = stringFromJson(comment, "name");
        c.qtype = stringFromJson(comment, "type");
      }
      c.modified_at = intFromJson(comment, "modified_at", now);
      c.content = stringFromJson(comment, "content");
      c.account = stringFromJson(comment, "account");
      new_comments.push_back(c);
    }
  }
}

static void updateDomainSettingsFromDocument(const DomainInfo& di, const string& zonename, Document& document) {
  string master;
  const Value &masters = document["masters"];
  if (masters.IsArray()) {
    for (SizeType i = 0; i < masters.Size(); ++i) {
      master += masters[i].GetString();
      master += " ";
    }
  }

  di.backend->setKind(zonename, DomainInfo::stringToKind(stringFromJson(document, "kind")));
  di.backend->setMaster(zonename, master);

  if (document["soa_edit_api"].IsString()) {
    di.backend->setDomainMetadataOne(zonename, "SOA-EDIT-API", document["soa_edit_api"].GetString());
  }
  if (document["soa_edit"].IsString()) {
    di.backend->setDomainMetadataOne(zonename, "SOA-EDIT", document["soa_edit"].GetString());
  }
}

static void apiZoneCryptokeys(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw ApiException("Only GET is implemented");

  string zonename = apiZoneIdToName(req->parameters["id"]);

  UeberBackend B;
  DomainInfo di;
  DNSSECKeeper dk;

  if(!B.getDomainInfo(zonename, di))
    throw ApiException("Could not find domain '"+zonename+"'");

  DNSSECKeeper::keyset_t keyset=dk.getKeys(zonename, boost::indeterminate, false);

  if (keyset.empty())
    throw ApiException("No keys for zone '"+zonename+"'");

  Document doc;
  doc.SetArray();

  BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type value, keyset) {
    if (req->parameters.count("key_id")) {
      int keyid = lexical_cast<int>(req->parameters["key_id"]);
      int curid = lexical_cast<int>(value.second.id);
      if (keyid != curid)
        continue;
    }
    Value key;
    key.SetObject();
    key.AddMember("type", "Cryptokey", doc.GetAllocator());
    key.AddMember("id", value.second.id, doc.GetAllocator());
    key.AddMember("active", value.second.active, doc.GetAllocator());
    key.AddMember("keytype", (value.second.keyOrZone ? "ksk" : "zsk"), doc.GetAllocator());
    Value dnskey(value.first.getDNSKEY().getZoneRepresentation().c_str(), doc.GetAllocator());
    key.AddMember("dnskey", dnskey, doc.GetAllocator());
    if (req->parameters.count("key_id")) {
      DNSSECPrivateKey dpk=dk.getKeyById(zonename, lexical_cast<int>(req->parameters["key_id"]));
      Value content(dpk.getKey()->convertToISC().c_str(), doc.GetAllocator());
      key.AddMember("content", content, doc.GetAllocator());
    }

    if (value.second.keyOrZone) {
      Value dses;
      dses.SetArray();
      Value ds(makeDSFromDNSKey(zonename, value.first.getDNSKEY(), 1).getZoneRepresentation().c_str(), doc.GetAllocator());
      dses.PushBack(ds, doc.GetAllocator());
      Value ds2(makeDSFromDNSKey(zonename, value.first.getDNSKEY(), 2).getZoneRepresentation().c_str(), doc.GetAllocator());
      dses.PushBack(ds2, doc.GetAllocator());

      try {
        Value ds3(makeDSFromDNSKey(zonename, value.first.getDNSKEY(), 3).getZoneRepresentation().c_str(), doc.GetAllocator());
        dses.PushBack(ds3, doc.GetAllocator());
      }
      catch(...)
      {
      }
      try {
        Value ds4(makeDSFromDNSKey(zonename, value.first.getDNSKEY(), 4).getZoneRepresentation().c_str(), doc.GetAllocator());
        dses.PushBack(ds4, doc.GetAllocator());
      }
      catch(...)
      {
      }
      key.AddMember("ds", dses, doc.GetAllocator());
    }

    doc.PushBack(key, doc.GetAllocator());
  }

  resp->setBody(doc);
}

static void gatherRecordsFromZone(const Value &container, vector<DNSResourceRecord>& new_records, string zonename) {
  DNSResourceRecord rr;
  vector<string> zonedata;
  stringtok(zonedata, stringFromJson(container, "zone"), "\r\n");

  ZoneParserTNG zpt(zonedata, zonename);

  bool seenSOA=false;

  string comment = "Imported via the API";

  try {
    while(zpt.get(rr, &comment)) {
      if(seenSOA && rr.qtype.getCode() == QType::SOA)
        continue;
      if(rr.qtype.getCode() == QType::SOA)
        seenSOA=true;

      rr.qname = stripDot(rr.qname);
      new_records.push_back(rr);
    }
  }
  catch(std::exception& ae) {
    throw ApiException("An error occured while parsing the zonedata: "+string(ae.what()));
  }
}

static void apiServerZones(HttpRequest* req, HttpResponse* resp) {
  UeberBackend B;
  DNSSECKeeper dk;
  if (req->method == "POST" && !::arg().mustDo("experimental-api-readonly")) {
    DomainInfo di;
    Document document;
    req->json(document);
    string zonename = stringFromJson(document, "name");
    string dotsuffix = "." + zonename;
    string zonestring = stringFromJson(document, "zone", "");

    // TODO: better validation of zonename
    if(zonename.empty())
      throw ApiException("Zone name empty");

    // strip any trailing dots
    while (zonename.substr(zonename.size()-1) == ".") {
      zonename.resize(zonename.size()-1);
    }

    bool exists = B.getDomainInfo(zonename, di);
    if(exists)
      throw ApiException("Domain '"+zonename+"' already exists");

    // validate 'kind' is set
    DomainInfo::DomainKind zonekind = DomainInfo::stringToKind(stringFromJson(document, "kind"));

    const Value &records = document["records"];
    if (records.IsArray() && zonestring != "")
      throw ApiException("You cannot give zonedata AND records");

    const Value &nameservers = document["nameservers"];
    if (!nameservers.IsArray() && zonekind != DomainInfo::Slave)
      throw ApiException("Nameservers list must be given (but can be empty if NS records are supplied)");

    string soa_edit_api_kind;
    if (document["soa_edit_api"].IsString())
      soa_edit_api_kind = document["soa_edit_api"].GetString();

    // if records/comments are given, load and check them
    bool have_soa = false;
    vector<DNSResourceRecord> new_records;
    vector<Comment> new_comments;
    vector<DNSResourceRecord> new_ptrs;

    if (records.IsArray()) {
      gatherRecords(document, new_records, new_ptrs);
    } else if (zonestring != "") {
      gatherRecordsFromZone(document, new_records, zonename);
    }

    gatherComments(document, new_comments, false);

    DNSResourceRecord rr;

    BOOST_FOREACH(rr, new_records) {
      if (!iends_with(rr.qname, dotsuffix) && !pdns_iequals(rr.qname, zonename))
        throw ApiException("RRset "+rr.qname+" IN "+rr.qtype.getName()+": Name is out of zone");

      if (rr.qtype.getCode() == QType::SOA && pdns_iequals(rr.qname, zonename)) {
        have_soa = true;
        editSOARecord(rr, soa_edit_api_kind);
      }
    }

    rr.qname = zonename;
    rr.auth = 1;
    rr.ttl = ::arg().asNum("default-ttl");

    if (!have_soa && zonekind != DomainInfo::Slave) {
      // synthesize a SOA record so the zone "really" exists

      SOAData sd;
      sd.qname = zonename;
      sd.nameserver = arg()["default-soa-name"];
      if (!arg().isEmpty("default-soa-mail")) {
        sd.hostmaster = arg()["default-soa-mail"];
        attodot(sd.hostmaster);
      } else {
        sd.hostmaster = "hostmaster." + zonename;
      }
      sd.serial = intFromJson(document, "serial", 0);
      sd.ttl = rr.ttl;
      sd.refresh = ::arg().asNum("soa-refresh-default");
      sd.retry = ::arg().asNum("soa-retry-default");
      sd.expire = ::arg().asNum("soa-expire-default");
      sd.default_ttl = ::arg().asNum("soa-minimum-ttl");

      rr.content = serializeSOAData(sd);
      rr.qtype = "SOA";
      editSOARecord(rr, soa_edit_api_kind);
      new_records.push_back(rr);
    }

    // create NS records if nameservers are given
    if (nameservers.IsArray()) {
      for (SizeType i = 0; i < nameservers.Size(); ++i) {
        if (!nameservers[i].IsString())
          throw ApiException("Nameservers must be strings");
        rr.content = nameservers[i].GetString();
        rr.qtype = "NS";
        new_records.push_back(rr);
      }
    }

    // no going back after this
    if(!B.createDomain(zonename))
      throw ApiException("Creating domain '"+zonename+"' failed");

    if(!B.getDomainInfo(zonename, di))
      throw ApiException("Creating domain '"+zonename+"' failed: lookup of domain ID failed");

    di.backend->startTransaction(zonename, di.id);

    BOOST_FOREACH(rr, new_records) {
      rr.domain_id = di.id;
      di.backend->feedRecord(rr);
    }
    BOOST_FOREACH(Comment& c, new_comments) {
      c.domain_id = di.id;
      di.backend->feedComment(c);
    }

    updateDomainSettingsFromDocument(di, zonename, document);

    di.backend->commitTransaction();

    fillZone(zonename, resp);
    resp->status = 201;
    return;
  }

  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  vector<DomainInfo> domains;
  B.getAllDomains(&domains, true); // incl. disabled

  Document doc;
  doc.SetArray();

  BOOST_FOREACH(const DomainInfo& di, domains) {
    Value jdi;
    jdi.SetObject();
    // id is the canonical lookup key, which doesn't actually match the name (in some cases)
    string zoneId = apiZoneNameToId(di.zone);
    Value jzoneId(zoneId.c_str(), doc.GetAllocator()); // copy
    jdi.AddMember("id", jzoneId, doc.GetAllocator());
    string url = "/servers/localhost/zones/" + zoneId;
    Value jurl(url.c_str(), doc.GetAllocator()); // copy
    jdi.AddMember("url", jurl, doc.GetAllocator());
    jdi.AddMember("name", di.zone.c_str(), doc.GetAllocator());
    jdi.AddMember("kind", di.getKindString(), doc.GetAllocator());
    jdi.AddMember("dnssec", dk.isSecuredZone(di.zone), doc.GetAllocator());
    Value masters;
    masters.SetArray();
    BOOST_FOREACH(const string& master, di.masters) {
      Value value(master.c_str(), doc.GetAllocator());
      masters.PushBack(value, doc.GetAllocator());
    }
    jdi.AddMember("masters", masters, doc.GetAllocator());
    jdi.AddMember("serial", di.serial, doc.GetAllocator());
    jdi.AddMember("notified_serial", di.notified_serial, doc.GetAllocator());
    jdi.AddMember("last_check", (unsigned int) di.last_check, doc.GetAllocator());
    doc.PushBack(jdi, doc.GetAllocator());
  }
  resp->setBody(doc);
}

static void apiServerZoneDetail(HttpRequest* req, HttpResponse* resp) {
  string zonename = apiZoneIdToName(req->parameters["id"]);

  if(req->method == "PUT" && !::arg().mustDo("experimental-api-readonly")) {
    // update domain settings
    UeberBackend B;
    DomainInfo di;
    if(!B.getDomainInfo(zonename, di))
      throw ApiException("Could not find domain '"+zonename+"'");

    Document document;
    req->json(document);

    updateDomainSettingsFromDocument(di, zonename, document);

    fillZone(zonename, resp);
    return;
  }
  else if(req->method == "DELETE" && !::arg().mustDo("experimental-api-readonly")) {
    // delete domain
    UeberBackend B;
    DomainInfo di;
    if(!B.getDomainInfo(zonename, di))
      throw ApiException("Could not find domain '"+zonename+"'");

    if(!di.backend->deleteDomain(zonename))
      throw ApiException("Deleting domain '"+zonename+"' failed: backend delete failed/unsupported");

    // empty body on success
    resp->body = "";
    resp->status = 204; // No Content: declare that the zone is gone now
    return;
  } else if (req->method == "PATCH" && !::arg().mustDo("experimental-api-readonly")) {
    patchZone(req, resp);
    return;
  } else if (req->method == "GET") {
    fillZone(zonename, resp);
    return;
  }

  throw HttpMethodNotAllowedException();
}

static string makeDotted(string in) {
  if (in.empty()) {
    return ".";
  }
  if (in[in.size()-1] != '.') {
    return in + ".";
  }
  return in;
}

static void apiServerZoneExport(HttpRequest* req, HttpResponse* resp) {
  string zonename = apiZoneIdToName(req->parameters["id"]);

  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  ostringstream ss;

  UeberBackend B;
  DomainInfo di;
  if(!B.getDomainInfo(zonename, di))
    throw ApiException("Could not find domain '"+zonename+"'");

  DNSResourceRecord rr;
  SOAData sd;
  di.backend->list(zonename, di.id);
  while(di.backend->get(rr)) {
    if (!rr.qtype.getCode())
      continue; // skip empty non-terminals

    string content = rr.content;

    switch(rr.qtype.getCode()) {
    case QType::SOA:
      fillSOAData(rr.content, sd);
      sd.nameserver = makeDotted(sd.nameserver);
      sd.hostmaster = makeDotted(sd.hostmaster);
      content = serializeSOAData(sd);
      break;
    case QType::MX:
    case QType::SRV:
    case QType::CNAME:
    case QType::NS:
    case QType::AFSDB:
      content = makeDotted(rr.content);
      break;
    default:
      break;
    }

    ss <<
      makeDotted(rr.qname) << "\t" <<
      rr.ttl << "\t" <<
      rr.qtype.getName() << "\t" <<
      content <<
      endl;
  }

  if (req->accept_json) {
    Document doc;
    doc.SetObject();
    Value val(ss.str().c_str(), doc.GetAllocator()); // copy
    doc.AddMember("zone", val, doc.GetAllocator());
    resp->body = makeStringFromDocument(doc);
  } else {
    resp->headers["Content-Type"] = "text/plain; charset=us-ascii";
    resp->body = ss.str();
  }
}

static void makePtr(const DNSResourceRecord& rr, DNSResourceRecord* ptr) {
  if (rr.qtype.getCode() == QType::A) {
    uint32_t ip;
    if (!IpToU32(rr.content, &ip)) {
      throw ApiException("PTR: Invalid IP address given");
    }
    ptr->qname = (boost::format("%u.%u.%u.%u.in-addr.arpa")
                  % ((ip >> 24) & 0xff)
                  % ((ip >> 16) & 0xff)
                  % ((ip >>  8) & 0xff)
                  % ((ip      ) & 0xff)
      ).str();
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
    ptr->qname = string(tmp.rbegin(), tmp.rend()) + ".ip6.arpa";
  } else {
    throw ApiException("Unsupported PTR source '" + rr.qname + "' type '" + rr.qtype.getName() + "'");
  }

  ptr->qtype = "PTR";
  ptr->ttl = rr.ttl;
  ptr->disabled = rr.disabled;
  ptr->content = rr.qname;
}

static void patchZone(HttpRequest* req, HttpResponse* resp) {
  UeberBackend B;
  DomainInfo di;
  string zonename = apiZoneIdToName(req->parameters["id"]);
  if (!B.getDomainInfo(zonename, di))
    throw ApiException("Could not find domain '"+zonename+"'");

  string dotsuffix = "." + zonename;
  vector<DNSResourceRecord> new_records;
  vector<Comment> new_comments;
  vector<DNSResourceRecord> new_ptrs;

  Document document;
  req->json(document);

  const Value& rrsets = document["rrsets"];
  if (!rrsets.IsArray())
    throw ApiException("No rrsets given in update request");

  di.backend->startTransaction(zonename);

  try {
    string soa_edit_api_kind;
    di.backend->getDomainMetadataOne(zonename, "SOA-EDIT-API", soa_edit_api_kind);
    bool soa_edit_done = false;

    for(SizeType rrsetIdx = 0; rrsetIdx < rrsets.Size(); ++rrsetIdx) {
      const Value& rrset = rrsets[rrsetIdx];
      string qname, changetype;
      QType qtype;
      qname = stringFromJson(rrset, "name");
      qtype = stringFromJson(rrset, "type");
      changetype = toUpper(stringFromJson(rrset, "changetype"));

      if (!iends_with(qname, dotsuffix) && !pdns_iequals(qname, zonename))
        throw ApiException("RRset "+qname+" IN "+qtype.getName()+": Name is out of zone");

      if (changetype == "DELETE") {
        // delete all matching qname/qtype RRs (and, implictly comments).
        if (!di.backend->replaceRRSet(di.id, qname, qtype, vector<DNSResourceRecord>())) {
          throw ApiException("Hosting backend does not support editing records.");
        }
      }
      else if (changetype == "REPLACE") {
        new_records.clear();
        new_comments.clear();
        // new_ptrs is merged
        gatherRecords(rrset, new_records, new_ptrs);
        gatherComments(rrset, new_comments, true);

        BOOST_FOREACH(DNSResourceRecord& rr, new_records) {
          rr.domain_id = di.id;

          if (rr.qname != qname || rr.qtype != qtype)
            throw ApiException("Record "+rr.qname+"/"+rr.qtype.getName()+" "+rr.content+": Record wrongly bundled with RRset " + qname + "/" + qtype.getName());

          if (rr.qtype.getCode() == QType::SOA && pdns_iequals(rr.qname, zonename)) {
            soa_edit_done = editSOARecord(rr, soa_edit_api_kind);
          }
        }

        BOOST_FOREACH(Comment& c, new_comments) {
          c.domain_id = di.id;
        }

        bool replace_records = rrset["records"].IsArray();
        bool replace_comments = rrset["comments"].IsArray();

        if (!replace_records && !replace_comments) {
          throw ApiException("No change for RRset " + qname + "/" + qtype.getName());
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
        throw ApiException("No SOA found for domain '"+zonename+"'");

      DNSResourceRecord rr;
      rr.qname = zonename;
      rr.content = serializeSOAData(sd);
      rr.qtype = "SOA";
      rr.domain_id = di.id;
      rr.auth = 1;
      rr.ttl = sd.ttl;
      editSOARecord(rr, soa_edit_api_kind);

      if (!di.backend->replaceRRSet(di.id, rr.qname, rr.qtype, vector<DNSResourceRecord>(1, rr))) {
        throw ApiException("Hosting backend does not support editing records.");
      }
    }

  } catch(...) {
    di.backend->abortTransaction();
    throw;
  }
  di.backend->commitTransaction();

  extern PacketCache PC;
  PC.purge(zonename);

  // now the PTRs
  BOOST_FOREACH(const DNSResourceRecord& rr, new_ptrs) {
    DNSPacket fakePacket;
    SOAData sd;
    sd.db = (DNSBackend *)-1;
    fakePacket.qtype = QType::PTR;

    if (!B.getAuth(&fakePacket, &sd, rr.qname, 0))
      throw ApiException("Could not find domain for PTR '"+rr.qname+"' requested for '"+rr.content+"' (while saving)");

    sd.db->startTransaction(rr.qname);
    if (!sd.db->replaceRRSet(sd.domain_id, rr.qname, rr.qtype, vector<DNSResourceRecord>(1, rr))) {
      sd.db->abortTransaction();
      throw ApiException("PTR-Hosting backend for "+rr.qname+"/"+rr.qtype.getName()+" does not support editing records.");
    }
    sd.db->commitTransaction();
    PC.purge(rr.qname);
  }

  // success
  fillZone(zonename, resp);
}

static void apiServerSearchData(HttpRequest* req, HttpResponse* resp) {
  if(req->method != "GET")
    throw HttpMethodNotAllowedException();

  string q = req->getvars["q"];
  if (q.empty())
    throw ApiException("Query q can't be blank");

  UeberBackend B;

  vector<DomainInfo> domains;
  B.getAllDomains(&domains, true); // incl. disabled

  Document doc;
  doc.SetArray();

  DNSResourceRecord rr;
  Comment comment;

  BOOST_FOREACH(const DomainInfo& di, domains) {
    string zoneId = apiZoneNameToId(di.zone);

    if (pdns_ci_find(di.zone, q) != string::npos) {
      Value object;
      object.SetObject();
      object.AddMember("type", "zone", doc.GetAllocator());
      Value jzoneId(zoneId.c_str(), doc.GetAllocator()); // copy
      object.AddMember("zone_id", jzoneId, doc.GetAllocator());
      Value jzoneName(di.zone.c_str(), doc.GetAllocator()); // copy
      object.AddMember("name", jzoneName, doc.GetAllocator());
      doc.PushBack(object, doc.GetAllocator());
    }

    // if zone name is an exact match, don't bother with returning all records/comments in it
    if (di.zone == q) {
      continue;
    }
    // the code below is too slow
#if 0
    di.backend->list(di.zone, di.id, true); // incl. disabled
    while(di.backend->get(rr)) {
      if (!rr.qtype.getCode())
        continue; // skip empty non-terminals

      if (pdns_ci_find(rr.qname, q) == string::npos && pdns_ci_find(rr.content, q) == string::npos)
        continue;

      Value object;
      object.SetObject();
      object.AddMember("type", "record", doc.GetAllocator());
      Value jzoneId(zoneId.c_str(), doc.GetAllocator()); // copy
      object.AddMember("zone_id", jzoneId, doc.GetAllocator());
      Value jzoneName(di.zone.c_str(), doc.GetAllocator()); // copy
      object.AddMember("zone_name", jzoneName, doc.GetAllocator());
      Value jname(rr.qname.c_str(), doc.GetAllocator()); // copy
      object.AddMember("name", jname, doc.GetAllocator());
      Value jcontent(rr.content.c_str(), doc.GetAllocator()); // copy
      object.AddMember("content", jcontent, doc.GetAllocator());
      doc.PushBack(object, doc.GetAllocator());
    }

    di.backend->listComments(di.id);
    while(di.backend->getComment(comment)) {
      if (pdns_ci_find(comment.qname, q) == string::npos && pdns_ci_find(comment.content, q) == string::npos)
        continue;

      Value object;
      object.SetObject();
      object.AddMember("type", "comment", doc.GetAllocator());
      Value jzoneId(zoneId.c_str(), doc.GetAllocator()); // copy
      object.AddMember("zone_id", jzoneId, doc.GetAllocator());
      Value jzoneName(di.zone.c_str(), doc.GetAllocator()); // copy
      object.AddMember("zone_name", jzoneName, doc.GetAllocator());
      Value jname(comment.qname.c_str(), doc.GetAllocator()); // copy
      object.AddMember("name", jname, doc.GetAllocator());
      Value jcontent(comment.content.c_str(), doc.GetAllocator()); // copy
      object.AddMember("content", jcontent, doc.GetAllocator());
      doc.PushBack(object, doc.GetAllocator());
    }
#endif
  }

  resp->setBody(doc);
}

void AuthWebServer::jsonstat(HttpRequest* req, HttpResponse* resp)
{
  string command;

  if(req->getvars.count("command")) {
    command = req->getvars["command"];
    req->getvars.erase("command");
  }

  if(command == "flush-cache") {
    extern PacketCache PC;
    int number; 
    if(req->getvars["domain"].empty())
      number = PC.purge();
    else
      number = PC.purge(req->getvars["domain"]);
      
    map<string, string> object;
    object["number"]=lexical_cast<string>(number);
    //cerr<<"Flushed cache for '"<<parameters["domain"]<<"', cleaned "<<number<<" records"<<endl;
    resp->body = returnJsonObject(object);
    resp->status = 200;
    return;
  }
  else if(command == "pdns-control") {
    if(req->method!="POST")
      throw HttpMethodNotAllowedException();
    // cout<<"post: "<<post<<endl;
    rapidjson::Document document;
    req->json(document);
    // cout<<"Parameters: '"<<document["parameters"].GetString()<<"'\n";
    vector<string> parameters;
    stringtok(parameters, document["parameters"].GetString(), " \t");
    
    DynListener::g_funk_t* ptr=0;
    if(!parameters.empty())
      ptr = DynListener::getFunc(toUpper(parameters[0]));
    map<string, string> m;
    
    if(ptr) {
      resp->status = 200;
      m["result"] = (*ptr)(parameters, 0);
    } else {
      resp->status = 404;
      m["error"]="No such function "+toUpper(parameters[0]);
    }
    resp->body = returnJsonObject(m);
    return;
  }
  else if(command=="log-grep") {
    // legacy parameter name hack
    req->getvars["q"] = req->getvars["needle"];
    apiServerSearchLog(req, resp);
    return;
  }

  resp->body = returnJsonError("No or unknown command given");
  resp->status = 404;
  return;
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
    if(::arg().mustDo("experimental-json-interface")) {
      d_ws->registerApiHandler("/servers/localhost/config", &apiServerConfig);
      d_ws->registerApiHandler("/servers/localhost/search-log", &apiServerSearchLog);
      d_ws->registerApiHandler("/servers/localhost/search-data", &apiServerSearchData);
      d_ws->registerApiHandler("/servers/localhost/statistics", &apiServerStatistics);
      d_ws->registerApiHandler("/servers/localhost/zones/<id>/cryptokeys/<key_id>", &apiZoneCryptokeys);
      d_ws->registerApiHandler("/servers/localhost/zones/<id>/cryptokeys", &apiZoneCryptokeys);
      d_ws->registerApiHandler("/servers/localhost/zones/<id>/export", &apiServerZoneExport);
      d_ws->registerApiHandler("/servers/localhost/zones/<id>", &apiServerZoneDetail);
      d_ws->registerApiHandler("/servers/localhost/zones", &apiServerZones);
      d_ws->registerApiHandler("/servers/localhost", &apiServerDetail);
      d_ws->registerApiHandler("/servers", &apiServer);
      // legacy dispatch
      d_ws->registerApiHandler("/jsonstat", boost::bind(&AuthWebServer::jsonstat, this, _1, _2));
    }
    d_ws->registerWebHandler("/style.css", boost::bind(&AuthWebServer::cssfunction, this, _1, _2));
    d_ws->registerWebHandler("/", boost::bind(&AuthWebServer::indexfunction, this, _1, _2));
    d_ws->go();
  }
  catch(...) {
    L<<Logger::Error<<"AuthWebServer thread caught an exception, dying"<<endl;
    exit(1);
  }
}
