/*
    Copyright (C) 2002 - 2012  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 
    as published by the Free Software Foundation

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
#include "ws.hh"
#include "json.hh"
#include "webserver.hh"
#include "logger.hh"
#include "packetcache.hh"
#include "statbag.hh"
#include "misc.hh"
#include "arguments.hh"
#include "dns.hh"
#include "ueberbackend.hh"
#include <boost/format.hpp>
#include <boost/foreach.hpp>
#include "namespaces.hh"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

using namespace rapidjson;

extern StatBag S;

StatWebServer::StatWebServer()
{
  d_start=time(0);
  d_min10=d_min5=d_min1=0;
  d_ws = 0;
  if(arg().mustDo("webserver"))
    d_ws = new WebServer(arg()["webserver-address"], arg().asNum("webserver-port"),arg()["webserver-password"]);
}

void StatWebServer::go()
{
  if(arg().mustDo("webserver"))
  {
    S.doRings();
    pthread_create(&d_tid, 0, threadHelper, this);
    pthread_create(&d_tid, 0, statThreadHelper, this);
  }
}

void StatWebServer::statThread()
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

void *StatWebServer::statThreadHelper(void *p)
{
  StatWebServer *sws=static_cast<StatWebServer *>(p);
  sws->statThread();
  return 0; // never reached
}


void *StatWebServer::threadHelper(void *p)
{
  StatWebServer *sws=static_cast<StatWebServer *>(p);
  sws->launch();
  return 0; // never reached
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


  ret<<"<table border=1><tr><td colspan=3 bgcolor=\"#0000ff\">"
    "<a href=\"?ring="<<ringname<<"\"><font color=\"#ffffff\">Top-"<<limit<<" of ";
  ret<<entries<<": "<<title<<"</font></a></td>"<<endl;

  ret<<"<tr><td colspan=3><table bgcolor=\"#ff0000\" width=\"100%\"><tr><td align=left>"
    "<a href=\"?resetring="<<ringname<<"\"><font color=\"#ffffff\">Reset</font></a></td>";
  ret<<"<td align=right>Resize: ";
  
  unsigned int sizes[]={10,100,500,1000,10000,500000,0};
  for(int i=0;sizes[i];++i) {
    if(S.getRingSize(ringname)!=sizes[i])
      ret<<"<a href=\"?resizering="<<ringname<<"&amp;size="<<sizes[i]<<"\">"<<sizes[i]<<"</a> ";
    else
      ret<<"("<<sizes[i]<<") ";
  }
  ret<<"</td></table>"<<endl;


  int printed=0;
  for(vector<pair<string,unsigned int> >::const_iterator i=ring.begin();limit && i!=ring.end();++i,--limit) {
    ret<<"<tr><td>"<<i->first<<"</td><td>"<<i->second<<"</td><td align=right>"<< StatWebServer::makePercentage(i->second*100.0/tot)<<"</td>"<<endl;
    printed+=i->second;
  }
  ret<<"<tr><td colspan=3></td></tr>"<<endl;
  if(printed!=tot)
    ret<<"<tr><td><b>Rest:</b></td><td><b>"<<tot-printed<<"</b></td><td align=right><b>"<< StatWebServer::makePercentage((tot-printed)*100.0/tot)<<"</b></td>"<<endl;

  ret<<"<tr><td><b>Total:</b></td><td><b>"<<tot<<"</b></td><td align=right><b>100%</b></td>";
  ret<<"</table><br>"<<endl;
}

void StatWebServer::printvars(ostringstream &ret)
{
  ret<<"<table border=1><tr><td colspan=3 bgcolor=\"#0000ff\"><font color=\"#ffffff\">Variables</font></td>"<<endl;
  

  vector<string>entries=S.getEntries();
  for(vector<string>::const_iterator i=entries.begin();i!=entries.end();++i) {
    ret<<"<tr><td>"<<*i<<"</td><td>"<<S.read(*i)<<"</td><td>"<<S.getDescrip(*i)<<"</td>"<<endl;
  }

  ret<<"</table>"<<endl;
}

void StatWebServer::printargs(ostringstream &ret)
{
  ret<<"<table border=1><tr><td colspan=3 bgcolor=\"#0000ff\"><font color=\"#ffffff\">Arguments</font></td>"<<endl;

  vector<string>entries=arg().list();
  for(vector<string>::const_iterator i=entries.begin();i!=entries.end();++i) {
    ret<<"<tr><td>"<<*i<<"</td><td>"<<arg()[*i]<<"</td><td>"<<arg().getHelp(*i)<<"</td>"<<endl;
  }
}

string StatWebServer::makePercentage(const double& val)
{
  return (boost::format("%.01f%%") % val).str();
}

string StatWebServer::indexfunction(const string& method, const string& post, const map<string,string> &varmap, void *ptr, bool *custom)
{
  StatWebServer *sws=static_cast<StatWebServer *>(ptr);
  map<string,string>rvarmap=varmap;
  if(!rvarmap["resetring"].empty()){
    *custom=true;
    S.resetRing(rvarmap["resetring"]);
    return "HTTP/1.1 301 Moved Permanently\nLocation: /\nConnection: close\n\n";
  }
  if(!rvarmap["resizering"].empty()){
    *custom=true;
    S.resizeRing(rvarmap["resizering"], atoi(rvarmap["size"].c_str()));
    return "HTTP/1.1 301 Moved Permanently\nLocation: /\nConnection: close\n\n";
  }

  ostringstream ret;

  ret<<"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">"<<endl;
  ret<<"<html><head><title>PowerDNS Operational Monitor</title></head><body bgcolor=\"#ffffff\">"<<endl;


  ret<<"<h2>";
  if(!arg()["config-name"].empty())
    ret<<"["<<arg()["config-name"]<<"]";
  if(rvarmap["ring"].empty())
    ret<<"PDNS "VERSION" Main Page</h2>"<<endl;
  else
    ret<<"Details page</h2><a href=\"/\">Back to main page</a>"<<endl;

  time_t passed=time(0)-s_starttime;

  ret<<"<p>Uptime: "<<
    humanDuration(passed)<<
    "<br>"<<endl;

  ret<<"Queries/second, 1, 5, 10 minute averages:  "<<std::setprecision(3)<<
    sws->d_queries.get1()<<", "<<
    sws->d_queries.get5()<<", "<<
    sws->d_queries.get10()<<". Max queries/second: "<<sws->d_queries.getMax()<<
    "<br>"<<endl;
  
  if(sws->d_cachemisses.get10()+sws->d_cachehits.get10()>0)
    ret<<"Cache hitrate, 1, 5, 10 minute averages: "<<
      makePercentage((sws->d_cachehits.get1()*100.0)/((sws->d_cachehits.get1())+(sws->d_cachemisses.get1())))<<", "<<
      makePercentage((sws->d_cachehits.get5()*100.0)/((sws->d_cachehits.get5())+(sws->d_cachemisses.get5())))<<", "<<
      makePercentage((sws->d_cachehits.get10()*100.0)/((sws->d_cachehits.get10())+(sws->d_cachemisses.get10())))<<
      "<br>"<<endl;

  if(sws->d_qcachemisses.get10()+sws->d_qcachehits.get10()>0)
    ret<<"Backend query cache hitrate, 1, 5, 10 minute averages: "<<std::setprecision(2)<<
      makePercentage((sws->d_qcachehits.get1()*100.0)/((sws->d_qcachehits.get1())+(sws->d_qcachemisses.get1())))<<", "<<
      makePercentage((sws->d_qcachehits.get5()*100.0)/((sws->d_qcachehits.get5())+(sws->d_qcachemisses.get5())))<<", "<<
      makePercentage((sws->d_qcachehits.get10()*100.0)/((sws->d_qcachehits.get10())+(sws->d_qcachemisses.get10())))<<
      "<br>"<<endl;

  ret<<"Backend query load, 1, 5, 10 minute averages: "<<std::setprecision(3)<<
    sws->d_qcachemisses.get1()<<", "<<
    sws->d_qcachemisses.get5()<<", "<<
    sws->d_qcachemisses.get10()<<". Max queries/second: "<<sws->d_qcachemisses.getMax()<<
    "<br>"<<endl;

  ret<<"Total queries: "<<S.read("udp-queries")<<". Question/answer latency: "<<S.read("latency")/1000.0<<"ms</p>"<<endl;
  if(rvarmap["ring"].empty()) {
    vector<string>entries=S.listRings();
    for(vector<string>::const_iterator i=entries.begin();i!=entries.end();++i)
      printtable(ret,*i,S.getRingTitle(*i));

    sws->printvars(ret);
    if(arg().mustDo("webserver-print-arguments"))
      sws->printargs(ret);
  }
  else
    printtable(ret,rvarmap["ring"],S.getRingTitle(rvarmap["ring"]),100);

  ret<<"</body></html>"<<endl;

  return ret.str();
}


string StatWebServer::jsonstat(const string& method, const string& post, const map<string,string> &varmap, void *ptr, bool *custom)
{
  *custom=1; // indicates we build the response
  string ret="HTTP/1.1 200 OK\r\n"
  "Server: PowerDNS/"VERSION"\r\n"
  "Connection: close\r\n"
  "Access-Control-Allow-Origin: *\r\n"
  "Content-Type: application/json\r\n"
  "\r\n" ;

  typedef map<string,string> varmap_t;
  varmap_t ourvarmap=varmap;
  string callback;
  string command;

  if(ourvarmap.count("callback")) {
    callback=ourvarmap["callback"];
    ourvarmap.erase("callback");
  }
  
  if(ourvarmap.count("command")) {
    command=ourvarmap["command"];
    ourvarmap.erase("command");
  }
  
  ourvarmap.erase("_");
  if(!callback.empty())
      ret += callback+"(";
    
  if(command=="get") {
    if(ourvarmap.empty()) {
      vector<string> entries = S.getEntries();
      BOOST_FOREACH(string& ent, entries) {
        ourvarmap[ent];
      }
      ourvarmap["version"];
      ourvarmap["uptime"];
    }

    string variable, value;
    
    Document doc;
    doc.SetObject();
    for(varmap_t::const_iterator iter = ourvarmap.begin(); iter != ourvarmap.end() ; ++iter) {
      variable = iter->first;
      if(variable == "version") {
        value =VERSION;
      }
      else if(variable == "uptime") {
        value = lexical_cast<string>(time(0) - s_starttime);
      }
      else 
        value = lexical_cast<string>(S.read(variable));
      Value jval;
      jval.SetString(value.c_str(), value.length(), doc.GetAllocator());
      doc.AddMember(variable.c_str(), jval, doc.GetAllocator());
    }
    ret+=makeStringFromDocument(doc);
  }
 
  if(command=="config") {
    vector<string> items = ::arg().list();
    Document doc;
    doc.SetArray();
    BOOST_FOREACH(const string& var, items) {
      Value kv, key, value;
      kv.SetArray();
      key.SetString(var.c_str(), var.length());
      kv.PushBack(key, doc.GetAllocator());
      
      if(var.find("password") != string::npos)
        value="*****";
      else 
        value.SetString(::arg()[var].c_str(), ::arg()[var].length(), doc.GetAllocator());
      
      kv.PushBack(value, doc.GetAllocator());
      doc.PushBack(kv, doc.GetAllocator());
    }
    ret += makeStringFromDocument(doc);
  }

  if(command == "flush-cache") {
    extern PacketCache PC;
    int number; 
    if(ourvarmap["domain"].empty())
      number = PC.purge();
    else
      number = PC.purge(ourvarmap["domain"]);
      
    map<string, string> object;
    object["number"]=lexical_cast<string>(number);
    //cerr<<"Flushed cache for '"<<ourvarmap["domain"]<<"', cleaned "<<number<<" records"<<endl;
    ret += returnJSONObject(object);
  }
  if(command=="get-zone") {
    UeberBackend B;
    SOAData sd;
    sd.db= (DNSBackend*)-1;
    if(!B.getSOA(ourvarmap["zone"], sd) || !sd.db) {
      cerr<<"Could not find domain '"<<ourvarmap["zone"]<<"'\n";
      return "";
    }
    sd.db->list(ourvarmap["zone"], sd.domain_id);
    DNSResourceRecord rr;
    
    ret+="[";
    map<string, string> object;
    bool first=1;
    while(sd.db->get(rr)) {
      if(!first) ret += ", ";
      first=false;
      object.clear();
      object["name"] = rr.qname;
      object["type"] = rr.qtype.getName();
      object["ttl"] = lexical_cast<string>(rr.ttl);
      object["priority"] = lexical_cast<string>(rr.priority);
      object["content"] = rr.content;
      ret+=returnJSONObject(object);
    }

    ret += "]";
  }
  if(command == "pdns-control") {
    if(method!="POST") {
      map<string, string> m;
      m["error"]="pdns-control requires a POST";
      return ret + returnJSONObject(m);
    }
    // cout<<"post: "<<post<<endl;
    rapidjson::Document document;
    if(document.Parse<0>(post.c_str()).HasParseError()) {
      return ret+"{\"error\": \"Unable to parse JSON\"";
    }
    // cout<<"Parameters: '"<<document["parameters"].GetString()<<"'\n";
    vector<string> parameters;
    stringtok(parameters, document["parameters"].GetString(), " \t");
    
    DynListener::g_funk_t* ptr=0;
    if(!parameters.empty())
      ptr = DynListener::getFunc(toUpper(parameters[0]));
    map<string, string> m;
    
    if(ptr) {
      m["result"] = (*ptr)(parameters, 0);
    } else {
      m["error"]="No such function "+toUpper(parameters[0]);
    }
    ret+= returnJSONObject(m);
      
  }
  if(command == "zone-rest") { // http://jsonstat?command=zone-rest&rest=/powerdns.nl/www.powerdns.nl/a
    vector<string> parts;
    stringtok(parts, ourvarmap["rest"], "/");
    if(parts.size() != 3) 
      return ret+"{\"error\": \"Could not parse rest parameter\"}";
    UeberBackend B;
    SOAData sd;
    sd.db = (DNSBackend*)-1;
    if(!B.getSOA(parts[0], sd) || !sd.db) {
      map<string, string> err;
      err["error"]= "Could not find domain '"+parts[0]+"'";
      return ret+returnJSONObject(err);
    }
    
    QType qtype;
    qtype=parts[2];
    string qname=parts[1];
    extern PacketCache PC;
    PC.purge(qname);
    // cerr<<"domain id: "<<sd.domain_id<<", lookup name: '"<<parts[1]<<"', for type: '"<<qtype.getName()<<"'"<<endl;
    
    if(method == "GET" ) {
      B.lookup(qtype, parts[1], 0, sd.domain_id);
      
      DNSResourceRecord rr;
      ret+="{ \"records\": [";
      map<string, string> object;
      bool first=1;
      
      while(B.get(rr)) {
        if(!first) ret += ", ";
          first=false;
        object.clear();
        object["name"] = rr.qname;
        object["type"] = rr.qtype.getName();
        object["ttl"] = lexical_cast<string>(rr.ttl);
        object["priority"] = lexical_cast<string>(rr.priority);
        object["content"] = rr.content;
        ret+=returnJSONObject(object);
      }
      ret+="]}";
    }
    else if(method=="DELETE") {
      sd.db->replaceRRSet(sd.domain_id, qname, qtype, vector<DNSResourceRecord>());
      
    }
    else if(method=="POST") {
      rapidjson::Document document;
      if(document.Parse<0>(post.c_str()).HasParseError()) {
        return ret+"{\"error\": \"Unable to parse JSON\"";
      }
      
      DNSResourceRecord rr;
      vector<DNSResourceRecord> rrset;
      const rapidjson::Value &records= document["records"];
      for(rapidjson::SizeType i = 0; i < records.Size(); ++i) {
        const rapidjson::Value& record = records[i];
        rr.qname=record["name"].GetString();
        rr.content=record["content"].GetString();
        rr.qtype=record["type"].GetString();
        rr.domain_id = sd.domain_id;
        rr.auth=0;
        rr.ttl=atoi(record["ttl"].GetString());
        rr.priority=atoi(record["priority"].GetString());
        
        rrset.push_back(rr);
        
        if(rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::SRV) 
          rr.content = lexical_cast<string>(rr.priority)+" "+rr.content;
          
        try {
          shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(rr.qtype.getCode(), 1, rr.content));
          string tmp=drc->serialize(rr.qname);
        }
        catch(std::exception& e) 
        {
          map<string, string> err;
          err["error"]= "Following record had a problem: "+rr.qname+" IN " +rr.qtype.getName()+ " " + rr.content+": "+e.what();
          return ret+returnJSONObject(err);
        }
      }
      // but now what
      sd.db->startTransaction(qname);
      sd.db->replaceRRSet(sd.domain_id, qname, qtype, rrset);
      sd.db->commitTransaction();
      return ret+post;
    }  
  }
  if(command=="log-grep") {
    ret += makeLogGrepJSON(ourvarmap, ::arg()["experimental-logfile"], " pdns[");
  }
 
  const char *kinds[]={"Master", "Slave", "Native"};
  if(command=="domains") {
    UeberBackend B;
    vector<DomainInfo> domains;
    B.getAllDomains(&domains);
    
    Document doc;
    doc.SetObject();
    
    Value jdomains;
    jdomains.SetArray();
    
    BOOST_FOREACH(const DomainInfo& di, domains) {
      Value jdi;
      jdi.SetObject();
      jdi.AddMember("name", di.zone.c_str(), doc.GetAllocator());
      jdi.AddMember("kind", kinds[di.kind], doc.GetAllocator());
      string masters = boost::join(di.masters, " ");
      Value jmasters;
      jmasters.SetString(masters.c_str(), masters.size(), doc.GetAllocator());
      jdi.AddMember("masters", jmasters, doc.GetAllocator()); // ^^^ this makes an actual copy, otherwise the zerocopy behaviour bites us!
      jdi.AddMember("serial", di.serial, doc.GetAllocator());
      jdi.AddMember("notified_serial", di.notified_serial, doc.GetAllocator());
      jdi.AddMember("last_check", (unsigned int) di.last_check, doc.GetAllocator());
      jdomains.PushBack(jdi, doc.GetAllocator());
    }
    doc.AddMember("domains", jdomains, doc.GetAllocator());
    ret.append(makeStringFromDocument(doc));
  }
  
  if(!callback.empty()) {
    ret += ");";
  }
  return ret;
}

void StatWebServer::launch()
{
  try {
    d_ws->setCaller(this);
    d_ws->registerHandler("",&indexfunction);
    if(::arg().mustDo("experimental-json-interface"))
      d_ws->registerHandler("jsonstat", &jsonstat);
    d_ws->go();
  }
  catch(...) {
    L<<Logger::Error<<"StatWebserver thread caught an exception, dying"<<endl;
    exit(1);
  }
}
