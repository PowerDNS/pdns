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
#include "gettime.hh"


static bool compareAuthorization(YaHTTP::Request& req, const string &expected_password, const string& expectedApiKey)
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
  if (!auth_ok && !expectedApiKey.empty()) {
    /* if this is a request for the API,
       check if the API key is correct */
    if (req.url.path=="/jsonstat" ||
        req.url.path=="/api/v1/servers/localhost" ||
        req.url.path=="/api/v1/servers/localhost/config" ||
        req.url.path=="/api/v1/servers/localhost/statistics") {
      header = req.headers.find("x-api-key");
      if (header != req.headers.end()) {
        auth_ok = (0==strcmp(header->second.c_str(), expectedApiKey.c_str()));
      }
    }
  }
  return auth_ok;
}

static void handleCORS(YaHTTP::Request& req, YaHTTP::Response& resp)
{
  YaHTTP::strstr_map_t::iterator origin = req.headers.find("Origin");
  if (origin != req.headers.end()) {
    if (req.method == "OPTIONS") {
      /* Pre-flight request */
      resp.headers["Access-Control-Allow-Methods"] = "GET";
      resp.headers["Access-Control-Allow-Headers"] = "Authorization, X-API-Key";
    }

    resp.headers["Access-Control-Allow-Origin"] = origin->second;
    resp.headers["Access-Control-Allow-Credentials"] = "true";
  }
}

static void addSecurityHeaders(YaHTTP::Response& resp, const boost::optional<std::map<std::string, std::string> >& customHeaders)
{
  static const std::vector<std::pair<std::string, std::string> > headers = {
    { "X-Content-Type-Options", "nosniff" },
    { "X-Frame-Options", "deny" },
    { "X-Permitted-Cross-Domain-Policies", "none" },
    { "X-XSS-Protection", "1; mode=block" },
    { "Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'" },
  };

  for (const auto& h : headers) {
    if (customHeaders) {
      const auto& custom = customHeaders->find(h.first);
      if (custom != customHeaders->end()) {
        continue;
      }
    }
    resp.headers[h.first] = h.second;
  }
}

static void addCustomHeaders(YaHTTP::Response& resp, const boost::optional<std::map<std::string, std::string> >& customHeaders)
{
  if (!customHeaders)
    return;

  for (const auto& c : *customHeaders) {
    if (!c.second.empty()) {
      resp.headers[c.first] = c.second;
    }
  }
}

static void connectionThread(int sock, ComboAddress remote, string password, string apiKey, const boost::optional<std::map<std::string, std::string> >& customHeaders)
{
  using namespace json11;
  vinfolog("Webserver handling connection from %s", remote.toStringWithPort());
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

    req.getvars.erase("_"); // jQuery cache buster

    YaHTTP::Response resp;
    resp.version = req.version;
    const string charset = "; charset=utf-8";

    addCustomHeaders(resp, customHeaders);
    addSecurityHeaders(resp, customHeaders);

    /* no need to send back the API key if any */
    resp.headers.erase("X-API-Key");

    if(req.method == "OPTIONS") {
      /* the OPTIONS method should not require auth, otherwise it breaks CORS */
      handleCORS(req, resp);
      resp.status=200;
    }
    else if (!compareAuthorization(req, password, apiKey)) {
      YaHTTP::strstr_map_t::iterator header = req.headers.find("authorization");
      if (header != req.headers.end())
        errlog("HTTP Request \"%s\" from %s: Web Authentication failed", req.url.path, remote.toStringWithPort());
      resp.status=401;
      resp.body="<h1>Unauthorized</h1>";
      resp.headers["WWW-Authenticate"] = "basic realm=\"PowerDNS\"";

    }
    else if(req.method != "GET") {
      resp.status=405;
    }
    else if(req.url.path=="/jsonstat") {
      handleCORS(req, resp);
      resp.status=200;

      if(command=="stats") {
        auto obj=Json::object {
          { "packetcache-hits", 0},
          { "packetcache-misses", 0},
          { "over-capacity-drops", 0 },
          { "too-old-drops", 0 },
          { "server-policy", g_policy.getLocal()->name}
        };

        for(const auto& e : g_stats.entries) {
          if(const auto& val = boost::get<DNSDistStats::stat_t*>(&std::get<1>(e)))
            obj.insert({std::get<0>(e), (double)(*val)->load()});
          else if (const auto& val = boost::get<double*>(&std::get<1>(e)))
            obj.insert({std::get<0>(e), (**val)});
          else
            obj.insert({std::get<0>(e), (int)(*boost::get<DNSDistStats::statfunction_t>(&std::get<1>(e)))(std::get<0>(e))});
        }
        Json my_json = obj;
        resp.body=my_json.dump();
        resp.headers["Content-Type"] = "application/json";
      }
      else if(command=="dynblocklist") {
        Json::object obj;
        auto slow = g_dynblockNMG.getCopy();
        struct timespec now;
        gettime(&now);
        for(const auto& e: slow) {
          if(now < e->second.until ) {
            Json::object thing{{"reason", e->second.reason}, {"seconds", (double)(e->second.until.tv_sec - now.tv_sec)},
							     {"blocks", (double)e->second.blocks} };
            obj.insert({e->first.toString(), thing});
          }
        }
        Json my_json = obj;
        resp.body=my_json.dump();
        resp.headers["Content-Type"] = "application/json";
      }
      else {
        resp.status=404;
      }
    }
    else if(req.url.path=="/api/v1/servers/localhost") {
      handleCORS(req, resp);
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
                {"latency", (int)(a->latencyUsec/1000.0)},
			      {"queries", (int)a->queries}};
      
	servers.push_back(server);
      }

      Json::array frontends;
      num=0;
      for(const auto& front : g_frontends) {
        if (front->udpFD == -1 && front->tcpFD == -1)
          continue;
        Json::object frontend{
          { "id", num++ },
          { "address", front->local.toStringWithPort() },
          { "udp", front->udpFD >= 0 },
          { "tcp", front->tcpFD >= 0 },
          { "queries", (double) front->queries.load() }
        };
        frontends.push_back(frontend);
      }

      Json::array rules;
      auto localRules = g_rulactions.getCopy();
      num=0;
      for(const auto& a : localRules) {
	Json::object rule{
	  {"id", num++},
	  {"matches", (int)a.first->d_matches},
	  {"rule", a.first->toString()},
          {"action", a.second->toString()}, 
          {"action-stats", a.second->getStats()} 
        };
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
        localaddresses += std::get<0>(loc).toStringWithPort();
      }
 
      Json my_json = Json::object {
	{ "daemon_type", "dnsdist" },
	{ "version", VERSION},
	{ "servers", servers},
	{ "frontends", frontends },
	{ "rules", rules},
	{ "acl", acl},
	{ "local", localaddresses}
      };
      resp.headers["Content-Type"] = "application/json";
      resp.body=my_json.dump();
    }
    else if(req.url.path=="/prometheus") {
        handleCORS(req, resp);
        resp.status=200;

        ostringstream str;
        str<<"# a first stab at reporting prometheus metrics from inside powerdns\n";
        string mainPool = "main";
        for(const auto& e : g_stats.entries) {
          string metricName = std::get<0>(e);
          boost::replace_all(metricName, "-", "_");

          str<<"# HELP "<<metricName<<' '<< std::get<3>(e)<<"\n";
          str<<"# TYPE "<<metricName<<' '<< std::get<2>(e)<<"\n";
          str<<"dnsdist_"<<metricName<<' ';
          if(const auto& val = boost::get<DNSDistStats::stat_t*>(&std::get<1>(e)))
            str<<(*val)->load();
          else if (const auto& val = boost::get<double*>(&std::get<1>(e)))
            str<<**val;
          else
            str<<(*boost::get<DNSDistStats::statfunction_t>(&std::get<1>(e)))(std::get<0>(e));
          str<<"\n";
        }
        const auto states = g_dstates.getCopy();
        for(const auto& s : states) {
          const string base = "dnsdist_backend_";
          const string label = "{backend=\"" + s->getName() + "\"}";
          //for(const auto& m : s.metrics) {
              //str<<"# HELP"<<std::get<0>(m)<<std::get<3>(m)<<"\n";
              //str<<"# TYPE"<<std::get<0>(m)<<std::get<2>(m)<<"\n";
              //str<<"dnsdist_backend_"<<std::get<0>(m)<<"{backend="<<s->getName()<<"}";
              //const auto& val = boost::get<std::atomic<uint64_t>*>(&std::get<1>(m));
              //str<<(*val)->load()<<"\n";
          //}
	  str<<base<<"queries"<<label<<' '<< s->queries.load() <<"\n";
          str<<base<<"drops"<<label<<' '<< s->reuseds.load() << "\n";
          str<<base<<"latency"<<label<<' '<< s->latencyUsec/1000.0 << "\n";
          str<<base<<"senderrors"<<label<<' '<< s->sendErrors.load() << "\n";
          str<<base<<"outstanding"<<label<<' '<< s->outstanding.load() << "\n";
        }
        for(const auto& front : g_frontends) {
          if (front->udpFD == -1 && front->tcpFD == -1)
            continue;

          string frontName = front->local.toStringWithPort();
          string proto = (front->udpFD >= 0 ? "udp" : "tcp");
          /* for(const auto& m : front.metrics) {
              str<<"# HELP"<<std::get<0>(m)<<std::get<3>(m)<<"\n";
              str<<"# TYPE"<<std::get<0>(m)<<std::get<2>(m)<<"\n";
              str<<"dnsdist_frontend_"<<std::get<0>(m)<<"{frontend="<<frontName<<",proto="<<proto<<"}";
              const auto& val = boost::get<std::atomic<uint64_t>*>(&std::get<1>(m));
              str<<(*val)->load()<<"\n";
          } */
          str<<"dnsdist_frontend_queries{frontend=\""<<frontName<<"\",proto=\""<<proto<<"\"} "<< front->queries.load() << "\n";
        }
        const auto localPools = g_pools.getCopy();
        for (const auto& entry : localPools) {
          string poolName = entry.first;
          if (poolName.empty()) {
            poolName = "default";
          }

          const string label = "{pool=\"" + poolName + "\"}";
          const std::shared_ptr<ServerPool> pool = entry.second;
          str<<"dnsdist_pool_servers{pool=\""<<poolName<<"\"} "<< pool->servers.size() <<"\n";
          if (pool->packetCache != nullptr) {
            const string cachebase = "dnsdist_pool_cache_";
            const auto& cache = pool->packetCache;
            str<<cachebase<<"size"<<label << ' ' << cache->getMaxEntries() << "\n";
            str<<cachebase<<"entries"<<label << ' ' << cache->getEntriesCount() << "\n";
            str<<cachebase<<"hits"<<label << ' ' << cache->getHits() << "\n";
            str<<cachebase<<"misses"<<label << ' ' << cache->getMisses() << "\n";
            str<<cachebase<<"deferred_inserts"<<label << ' ' << cache->getDeferredInserts() << "\n";
            str<<cachebase<<"deferred_lookups"<<label << ' ' << cache->getDeferredLookups() << "\n";
            str<<cachebase<<"lookup_collisions"<<label << ' ' << cache->getLookupCollisions() << "\n";
            str<<cachebase<<"insert_collisions"<<label << ' ' << cache->getInsertCollisions() << "\n";
            str<<cachebase<<"ttl_too_shorts"<<label << ' ' << cache->getTTLTooShorts() << "\n";
          }
        }
        resp.body=str.str();
        resp.headers["Content-Type"] = "text/plain";
    }
    else if(req.url.path=="/api/v1/servers/localhost/statistics") {
      handleCORS(req, resp);
      resp.status=200;

      Json::array doc;
      for(const auto& item : g_stats.entries) {
        if(const auto& val = boost::get<DNSDistStats::stat_t*>(&std::get<1>(item))) {
          doc.push_back(Json::object {
              { "type", "StatisticItem" },
              { "name", std::get<0>(item) },
              { "value", (double)(*val)->load() }
            });
        }
        else if (const auto& val = boost::get<double*>(&std::get<1>(item))) {
          doc.push_back(Json::object {
              { "type", "StatisticItem" },
              { "name", std::get<0>(item) },
              { "value", (**val) }
            });
        }
        else {
          doc.push_back(Json::object {
              { "type", "StatisticItem" },
              { "name", std::get<0>(item) },
              { "value", (int)(*boost::get<DNSDistStats::statfunction_t>(&std::get<1>(item)))(std::get<0>(item)) }
            });
        }
      }
      Json my_json = doc;
      resp.body=my_json.dump();
      resp.headers["Content-Type"] = "application/json";
    }
    else if(req.url.path=="/api/v1/servers/localhost/config") {
      handleCORS(req, resp);
      resp.status=200;

      Json::array doc;
      typedef boost::variant<bool, double, std::string> configentry_t;
      std::vector<std::pair<std::string, configentry_t> > configEntries {
        { "acl", g_ACL.getCopy().toString() },
        { "control-socket", g_serverControl.toStringWithPort() },
        { "ecs-override", g_ECSOverride },
        { "ecs-source-prefix-v4", (double) g_ECSSourcePrefixV4 },
        { "ecs-source-prefix-v6", (double)  g_ECSSourcePrefixV6 },
        { "fixup-case", g_fixupCase },
        { "max-outstanding", (double) g_maxOutstanding },
        { "server-policy", g_policy.getLocal()->name },
        { "stale-cache-entries-ttl", (double) g_staleCacheEntriesTTL },
        { "tcp-recv-timeout", (double) g_tcpRecvTimeout },
        { "tcp-send-timeout", (double) g_tcpSendTimeout },
        { "truncate-tc", g_truncateTC },
        { "verbose", g_verbose },
        { "verbose-health-checks", g_verboseHealthChecks }
      };
      for(const auto& item : configEntries) {
        if (const auto& val = boost::get<bool>(&item.second)) {
          doc.push_back(Json::object {
              { "type", "ConfigSetting" },
              { "name", item.first },
              { "value", *val }
          });
        }
        else if (const auto& val = boost::get<string>(&item.second)) {
          doc.push_back(Json::object {
              { "type", "ConfigSetting" },
              { "name", item.first },
              { "value", *val }
          });
        }
        else if (const auto& val = boost::get<double>(&item.second)) {
          doc.push_back(Json::object {
              { "type", "ConfigSetting" },
              { "name", item.first },
              { "value", *val }
          });
        }
      }
      Json my_json = doc;
      resp.body=my_json.dump();
      resp.headers["Content-Type"] = "application/json";
    }
    else if(!req.url.path.empty() && g_urlmap.count(req.url.path.c_str()+1)) {
      resp.body.assign(g_urlmap[req.url.path.c_str()+1]);
      vector<string> parts;
      stringtok(parts, req.url.path, ".");
      if(parts.back() == "html")
        resp.headers["Content-Type"] = "text/html" + charset;
      else if(parts.back() == "css")
        resp.headers["Content-Type"] = "text/css" + charset;
      else if(parts.back() == "js")
        resp.headers["Content-Type"] = "application/javascript" + charset;
      else if(parts.back() == "png")
        resp.headers["Content-Type"] = "image/png";
      resp.status=200;
    }
    else if(req.url.path=="/") {
      resp.body.assign(g_urlmap["index.html"]);
      resp.headers["Content-Type"] = "text/html" + charset;
      resp.status=200;
    }
    else {
      // cerr<<"404 for: "<<req.url.path<<endl;
      resp.status=404;
    }

    std::ostringstream ofs;
    ofs << resp;
    string done;
    done=ofs.str();
    writen2(sock, done.c_str(), done.size());

    fclose(fp);
    fp=0;
  }
  catch(const YaHTTP::ParseError& e) {
    vinfolog("Webserver thread died with parse error exception while processing a request from %s: %s", remote.toStringWithPort(), e.what());
    if(fp)
      fclose(fp);
  }
  catch(const std::exception& e) {
    errlog("Webserver thread died with exception while processing a request from %s: %s", remote.toStringWithPort(), e.what());
    if(fp)
      fclose(fp);
  }
  catch(...) {
    errlog("Webserver thread died with exception while processing a request from %s", remote.toStringWithPort());
    if(fp)
      fclose(fp);
  }
}
void dnsdistWebserverThread(int sock, const ComboAddress& local, const std::string& password, const std::string& apiKey, const boost::optional<std::map<std::string, std::string> >& customHeaders)
{
  warnlog("Webserver launched on %s", local.toStringWithPort());
  for(;;) {
    try {
      ComboAddress remote(local);
      int fd = SAccept(sock, remote);
      vinfolog("Got connection from %s", remote.toStringWithPort());
      std::thread t(connectionThread, fd, remote, password, apiKey, customHeaders);
      t.detach();
    }
    catch(std::exception& e) {
      errlog("Had an error accepting new webserver connection: %s", e.what());
    }
  }
}
