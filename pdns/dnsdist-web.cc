#include "dnsdist.hh"
#include "sstuff.hh"
#include "ext/json11/json11.hpp"
#include "ext/incbin/incbin.h"
#include "dolog.hh"
#include <thread>
#include <sstream>
#include <yahttp/yahttp.hpp>
#include "namespaces.hh"
#include <sys/time.h>
#include <sys/resource.h>
#include "ext/incbin/incbin.h"
#include "htmlfiles.h"
#include "base64.hh"


bool compareAuthorization(YaHTTP::Request& req, const string &expected_password)
{
  // validate password
  YaHTTP::strstr_map_t::iterator header = req.headers.find("authorization");
  bool auth_ok = false;
  if (header != req.headers.end() && toLower(header->second).find("basic ") == 0) {
    string cookie = header->second.substr(6);

    string plain;
    B64Decode(cookie, plain);

    vector<string> cparts;
    stringtok(cparts, plain, ":");

    // this gets rid of terminating zeros
    auth_ok = (cparts.size()==2 && (0==strcmp(cparts[1].c_str(), expected_password.c_str())));
  }
  return auth_ok;
}


static void connectionThread(int sock, ComboAddress remote, string password)
{
  using namespace json11;
  infolog("Webserver handling connection from %s", remote.toStringWithPort());
  FILE* fp=0;
  fp=fdopen(sock, "r");
  try {
    string line;
    string request;
    while(stringfgets(fp, line)) {
      request+=line;
      trim(line);

      if(line.empty())
	break;
    }
  
    std::istringstream ifs(request);
    YaHTTP::Request req;
    ifs >> req;

    string command=req.getvars["command"];

    string callback;

    if(req.getvars.count("callback")) {
      callback=req.getvars["callback"];
      req.getvars.erase("callback");
    }

    req.getvars.erase("_"); // jQuery cache buster

    YaHTTP::Response resp(req);

    if (!compareAuthorization(req, password)) {
      errlog("HTTP Request \"%s\" from %s: Web Authentication failed", req.url.path, remote.toStringWithPort());
      resp.status=401;
      resp.body="<h1>Unauthorized</h1>";
      resp.headers["WWW-Authenticate"] = "basic realm=\"PowerDNS\"";

    }
    else if(command=="stats") {
      resp.status=200;

      auto obj=Json::object {
	{ "packetcache-hits", 0},
	{ "packetcache-misses", 0},
	{ "over-capacity-drops", 0 },
	{ "too-old-drops", 0 },
	{ "server-policy", g_policy.getLocal()->name}
      };

      for(const auto& e : g_stats.entries) {
	if(const auto& val = boost::get<DNSDistStats::stat_t*>(&e.second))
	  obj.insert({e.first, (int)(*val)->load()});
	else if (const auto& val = boost::get<double*>(&e.second))
	  obj.insert({e.first, (**val)});
	else
	  obj.insert({e.first, (int)(*boost::get<DNSDistStats::statfunction_t>(&e.second))(e.first)});
      }
      Json my_json = obj;

      resp.headers["Content-Type"] = "application/json";
      resp.body=my_json.dump();
    }
    else if(command=="dynblocklist") {
      resp.status=200;
 
      Json::object obj;
      auto slow = g_dynblockNMG.getCopy();
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      for(const auto& e: slow) {
	if(now < e->second.until ) {
	  Json::object thing{{"reason", e->second.reason}, {"seconds", (double)(e->second.until.tv_sec - now.tv_sec)},
							     {"blocks", (double)e->second.blocks} };
	  obj.insert({e->first.toString(), thing});
	}
      }
      Json my_json=obj;

      resp.headers["Content-Type"] = "application/json";
      resp.body=my_json.dump();
    }
    else if(req.url.path=="/api/v1/servers/localhost") {
      resp.status=200;

      Json::array servers;
      auto localServers = g_dstates.getCopy();
      int num=0;
      for(const auto& a : localServers) {
	string status;
	if(a->availability == DownstreamState::Availability::Up) 
	  status = "UP";
	else if(a->availability == DownstreamState::Availability::Down) 
	  status = "DOWN";
	else 
	  status = (a->upStatus ? "up" : "down");
	string pools;
	for(const auto& p: a->pools)
	  pools+=p+" ";
	Json::object server{ 
	  {"id", num++}, 
	  {"name", a->name},
	    {"address", a->remote.toStringWithPort()}, 
	      {"state", status}, 
		{"qps", (int)a->queryLoad}, 
		  {"qpsLimit", (int)a->qps.getRate()}, 
		    {"outstanding", (int)a->outstanding}, 
		      {"reuseds", (int)a->reuseds},
			{"weight", (int)a->weight}, 
			  {"order", (int)a->order}, 
			    {"pools", pools},
			      {"queries", (int)a->queries}};
      
	servers.push_back(server);
      }

      Json::array rules;
      auto localRules = g_rulactions.getCopy();
      num=0;
      for(const auto& a : localRules) {
	Json::object rule{
	  {"id", num++},
	    {"matches", (int)a.first->d_matches},
	      {"rule", a.first->toString()},
		{"action", a.second->toString()} };
	rules.push_back(rule);
      }
      

      string acl;

      vector<string> vec;

      g_ACL.getCopy().toStringVector(&vec);

      for(const auto& s : vec) {
        if(!acl.empty()) acl += ", ";
        acl+=s;      
      }
      string localaddresses;
      for(const auto& loc : g_locals) {
        if(!localaddresses.empty()) localaddresses += ", ";
        localaddresses += loc.first.toStringWithPort();
      }
 
      Json my_json = Json::object {
	{ "daemon_type", "dnsdist" },
	{ "version", VERSION},
	{ "servers", servers},
	{ "rules", rules},
	{ "acl", acl},
	{ "local", localaddresses}
      };
      resp.headers["Content-Type"] = "application/json";
      resp.body=my_json.dump();

    }
    else if(!resp.url.path.empty() && g_urlmap.count(resp.url.path.c_str()+1)) {
      resp.body.assign(g_urlmap[resp.url.path.c_str()+1]);
      vector<string> parts;
      stringtok(parts, resp.url.path, ".");
      if(parts.back() == "html")
        resp.headers["Content-Type"] = "text/html";
      else if(parts.back() == "css")
        resp.headers["Content-Type"] = "text/css";
      else if(parts.back() == "js")
        resp.headers["Content-Type"] = "application/javascript";
      resp.status=200;
    }
    else if(resp.url.path=="/") {
      resp.body.assign(g_urlmap["index.html"]);
      resp.headers["Content-Type"] = "text/html";
      resp.status=200;
    }
    else {
      // cerr<<"404 for: "<<resp.url.path<<endl;
      resp.status=404;
    }

    if(!callback.empty()) {
      resp.body = callback + "(" + resp.body + ");";
    }

    std::ostringstream ofs;
    ofs << resp;
    string done;
    done=ofs.str();
    writen2(sock, done.c_str(), done.size());

    fclose(fp);
    fp=0;
  }
  catch(...)
    {
      errlog("Webserver thread died with exception");
      if(fp)
	fclose(fp);
    }
}
void dnsdistWebserverThread(int sock, const ComboAddress& local, const std::string& password)
{
  warnlog("Webserver launched on %s", local.toStringWithPort());
  for(;;) {
    try {
      ComboAddress remote(local);
      int fd = SAccept(sock, remote);
      vinfolog("Got connection from %s", remote.toStringWithPort());
      std::thread t(connectionThread, fd, remote, password);
      t.detach();
    }
    catch(std::exception& e) {
      errlog("Had an error accepting new webserver connection: %s", e.what());
    }
  }
}
