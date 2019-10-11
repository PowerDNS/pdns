#include "version.hh"
#include "ext/luawrapper/include/LuaContext.hpp"
#include "lua-auth4.hh"
#include <thread>
#include "sstuff.hh"
#include <mutex>
#include "minicurl.hh"
#include "ueberbackend.hh"
#include <boost/format.hpp>
#include "dnsrecords.hh"
#include "dns_random.hh"

#include "../modules/geoipbackend/geoipinterface.hh" // only for the enum

/* to do:
   block AXFR unless TSIG, or override

   investigate IPv6

   check the wildcard 'no cache' stuff, we may get it wrong

   ponder ECS scopemask setting

   ponder netmask tree from file for huge number of netmasks

   unify ifupurl/ifupport
      add attribute for certificate check
   add list of current monitors
      expire them too?

   pool of UeberBackends?

   Pool checks ?
 */

extern int  g_luaRecordExecLimit;

using iplist_t = vector<pair<int, string> >;
using wiplist_t = std::unordered_map<int, string>;
using ipunitlist_t = vector<pair<int, iplist_t> >;
using opts_t = std::unordered_map<string,string>;

class IsUpOracle
{
private:
  struct CheckDesc
  {
    ComboAddress rem;
    string url;
    opts_t opts;
    bool operator<(const CheckDesc& rhs) const
    {
      std::map<string,string> oopts, rhsoopts;
      for(const auto& m : opts)
        oopts[m.first]=m.second;
      for(const auto& m : rhs.opts)
        rhsoopts[m.first]=m.second;

      return std::make_tuple(rem, url, oopts) <
        std::make_tuple(rhs.rem, rhs.url, rhsoopts);
    }
  };
public:
  bool isUp(const ComboAddress& remote, const opts_t& opts);
  bool isUp(const ComboAddress& remote, const std::string& url, const opts_t& opts);
  bool isUp(const CheckDesc& cd);

private:
  void checkURLThread(ComboAddress rem, std::string url, const opts_t& opts);
  void checkTCPThread(ComboAddress rem, const opts_t& opts);

  struct Checker
  {
    std::thread thr;
    bool status;
  };

  typedef map<CheckDesc, Checker> statuses_t;
  statuses_t d_statuses;

  std::mutex d_mutex;

  void setStatus(const CheckDesc& cd, bool status)
  {
    std::lock_guard<std::mutex> l(d_mutex);
    d_statuses[cd].status=status;
  }

  void setDown(const ComboAddress& rem, const std::string& url=std::string(), const opts_t& opts = opts_t())
  {
    CheckDesc cd{rem, url, opts};
    setStatus(cd, false);
  }

  void setUp(const ComboAddress& rem, const std::string& url=std::string(), const opts_t& opts = opts_t())
  {
    CheckDesc cd{rem, url, opts};

    setStatus(cd, true);
  }

  void setDown(const CheckDesc& cd)
  {
    setStatus(cd, false);
  }

  void setUp(const CheckDesc& cd)
  {
    setStatus(cd, true);
  }

  bool upStatus(const ComboAddress& rem, const std::string& url=std::string(), const opts_t& opts = opts_t())
  {
    CheckDesc cd{rem, url, opts};
    std::lock_guard<std::mutex> l(d_mutex);
    return d_statuses[cd].status;
  }
};

bool IsUpOracle::isUp(const CheckDesc& cd)
{
  std::lock_guard<std::mutex> l(d_mutex);
  auto iter = d_statuses.find(cd);
  if(iter == d_statuses.end()) {
    d_statuses[cd]=Checker{std::thread(&IsUpOracle::checkTCPThread, this, cd.rem, cd.opts), false};
    return false;
  }
  return iter->second.status;

}

bool IsUpOracle::isUp(const ComboAddress& remote, const opts_t& opts)
{
  CheckDesc cd{remote, "", opts};
  return isUp(cd);
}

bool IsUpOracle::isUp(const ComboAddress& remote, const std::string& url, const opts_t& opts)
{
  CheckDesc cd{remote, url, opts};
  std::lock_guard<std::mutex> l(d_mutex);
  auto iter = d_statuses.find(cd);
  if(iter == d_statuses.end()) {
    //    g_log<<Logger::Warning<<"Launching HTTP(s) status checker for "<<remote.toStringWithPort()<<" and URL "<<url<<endl;
    d_statuses[cd]=Checker{std::thread(&IsUpOracle::checkURLThread, this, remote, url, opts), false};
    return false;
  }

  return iter->second.status;
}

void IsUpOracle::checkTCPThread(ComboAddress rem, const opts_t& opts)
{
  CheckDesc cd{rem, "", opts};
  setDown(cd);
  for(bool first=true;;first=false) {
    try {
      Socket s(rem.sin4.sin_family, SOCK_STREAM);
      ComboAddress src;
      s.setNonBlocking();
      if(opts.count("source")) {
        src=ComboAddress(opts.at("source"));
        s.bind(src);
      }
      s.connect(rem, 1);
      if(!isUp(cd)) {
        g_log<<Logger::Warning<<"Lua record monitoring declaring TCP/IP "<<rem.toStringWithPort()<<" ";
        if(opts.count("source"))
          g_log<<"(source "<<src.toString()<<") ";
        g_log<<"UP!"<<endl;
      }
      setUp(cd);
    }
    catch(NetworkError& ne) {
      if(isUp(rem, opts) || first)
        g_log<<Logger::Warning<<"Lua record monitoring declaring TCP/IP "<<rem.toStringWithPort()<<" DOWN: "<<ne.what()<<endl;
      setDown(cd);
    }
    sleep(1);
  }
}


void IsUpOracle::checkURLThread(ComboAddress rem, std::string url, const opts_t& opts)
{
  setDown(rem, url, opts);
  for(bool first=true;;first=false) {
    try {
      string useragent = productName();
      if (opts.count("useragent")) {
        useragent = opts.at("useragent");
      }
      MiniCurl mc(useragent);

      string content;
      if(opts.count("source")) {
        ComboAddress src(opts.at("source"));
        content=mc.getURL(url, &rem, &src);
      }
      else {
        content=mc.getURL(url, &rem);
      }
      if(opts.count("stringmatch") && content.find(opts.at("stringmatch")) == string::npos) {
        throw std::runtime_error(boost::str(boost::format("unable to match content with `%s`") % opts.at("stringmatch")));
      }
      if(!upStatus(rem,url,opts))
        g_log<<Logger::Warning<<"LUA record monitoring declaring "<<rem.toString()<<" UP for URL "<<url<<"!"<<endl;
      setUp(rem, url,opts);
    }
    catch(std::exception& ne) {
      if(upStatus(rem,url,opts) || first)
        g_log<<Logger::Warning<<"LUA record monitoring declaring "<<rem.toString()<<" DOWN for URL "<<url<<", error: "<<ne.what()<<endl;
      setDown(rem,url,opts);
    }
    sleep(5);
  }
}


IsUpOracle g_up;
namespace {
template<typename T, typename C>
bool doCompare(const T& var, const std::string& res, const C& cmp)
{
  if(auto country = boost::get<string>(&var))
    return cmp(*country, res);

  auto countries=boost::get<vector<pair<int,string> > >(&var);
  for(const auto& country : *countries) {
    if(cmp(country.second, res))
      return true;
  }
  return false;
}
}


std::string getGeo(const std::string& ip, GeoIPInterface::GeoIPQueryAttribute qa)
{
  static bool initialized;
  extern std::function<std::string(const std::string& ip, int)> g_getGeo;
  if(!g_getGeo) {
    if(!initialized) {
      g_log<<Logger::Error<<"LUA Record attempted to use GeoIPBackend functionality, but backend not launched"<<endl;
      initialized=true;
    }
    return "unknown";
  }
  else
    return g_getGeo(ip, (int)qa);
}

static ComboAddress pickrandom(const vector<ComboAddress>& ips)
{
  if (ips.empty()) {
    throw std::invalid_argument("The IP list cannot be empty");
  }
  return ips[dns_random(ips.size())];
}

static ComboAddress hashed(const ComboAddress& who, const vector<ComboAddress>& ips)
{
  if (ips.empty()) {
    throw std::invalid_argument("The IP list cannot be empty");
  }
  ComboAddress::addressOnlyHash aoh;
  return ips[aoh(who) % ips.size()];
}


static ComboAddress pickwrandom(const vector<pair<int,ComboAddress> >& wips)
{
  if (wips.empty()) {
    throw std::invalid_argument("The IP list cannot be empty");
  }
  int sum=0;
  vector<pair<int, ComboAddress> > pick;
  for(auto& i : wips) {
    sum += i.first;
    pick.push_back({sum, i.second});
  }
  int r = dns_random(sum);
  auto p = upper_bound(pick.begin(), pick.end(), r, [](int rarg, const decltype(pick)::value_type& a) { return rarg < a.first; });
  return p->second;
}

static ComboAddress pickwhashed(const ComboAddress& bestwho, vector<pair<int,ComboAddress> >& wips)
{
  if (wips.empty()) {
    return ComboAddress();
  }
  int sum=0;
  vector<pair<int, ComboAddress> > pick;
  for(auto& i : wips) {
    sum += i.first;
    pick.push_back({sum, i.second});
  }
  ComboAddress::addressOnlyHash aoh;
  int r = aoh(bestwho) % sum;
  auto p = upper_bound(pick.begin(), pick.end(), r, [](int rarg, const decltype(pick)::value_type& a) { return rarg < a.first; });
  return p->second;
}

static bool getLatLon(const std::string& ip, double& lat, double& lon)
{
  string inp = getGeo(ip, GeoIPInterface::Location);
  if(inp.empty())
    return false;
  lat=atof(inp.c_str());
  auto pos=inp.find(' ');
  if(pos != string::npos)
    lon=atof(inp.c_str() + pos);
  return true;
}

static bool getLatLon(const std::string& ip, string& loc)
{
  int latdeg, latmin, londeg, lonmin;
  double latsec, lonsec;
  char lathem='X', lonhem='X';

  double lat, lon;
  if(!getLatLon(ip, lat, lon))
    return false;

  if(lat > 0) {
    lathem='N';
  }
  else {
    lat = -lat;
    lathem='S';
  }

  if(lon > 0) {
    lonhem='E';
  }
  else {
    lon = -lon;
    lonhem='W';
  }

  /*
    >>> deg = int(R)
    >>> min = int((R - int(R)) * 60.0)
    >>> sec = (((R - int(R)) * 60.0) - min) * 60.0
    >>> print("{}º {}' {}\"".format(deg, min, sec))
  */


  latdeg = lat;
  latmin = (lat - latdeg)*60.0;
  latsec = (((lat - latdeg)*60.0) - latmin)*60.0;

  londeg = lon;
  lonmin = (lon - londeg)*60.0;
  lonsec = (((lon - londeg)*60.0) - lonmin)*60.0;

  // 51 59 00.000 N 5 55 00.000 E 4.00m 1.00m 10000.00m 10.00m

  boost::format fmt("%d %d %d %c %d %d %d %c 0.00m 1.00m 10000.00m 10.00m");

  loc= (fmt % latdeg % latmin % latsec % lathem % londeg % lonmin % lonsec % lonhem ).str();
  return true;
}

static ComboAddress pickclosest(const ComboAddress& bestwho, const vector<ComboAddress>& wips)
{
  if (wips.empty()) {
    throw std::invalid_argument("The IP list cannot be empty");
  }
  map<double,vector<ComboAddress> > ranked;
  double wlat=0, wlon=0;
  getLatLon(bestwho.toString(), wlat, wlon);
  //        cout<<"bestwho "<<wlat<<", "<<wlon<<endl;
  vector<string> ret;
  for(const auto& c : wips) {
    double lat=0, lon=0;
    getLatLon(c.toString(), lat, lon);
    //          cout<<c.toString()<<": "<<lat<<", "<<lon<<endl;
    double latdiff = wlat-lat;
    double londiff = wlon-lon;
    if(londiff > 180)
      londiff = 360 - londiff;
    double dist2=latdiff*latdiff + londiff*londiff;
    //          cout<<"    distance: "<<sqrt(dist2) * 40000.0/360<<" km"<<endl; // length of a degree
    ranked[dist2].push_back(c);
  }
  return ranked.begin()->second[dns_random(ranked.begin()->second.size())];
}

static std::vector<DNSZoneRecord> lookup(const DNSName& name, uint16_t qtype, int zoneid)
{
  static UeberBackend ub;
  static std::mutex mut;
  std::lock_guard<std::mutex> lock(mut);
  ub.lookup(QType(qtype), name, zoneid);
  DNSZoneRecord dr;
  vector<DNSZoneRecord> ret;
  while(ub.get(dr)) {
    ret.push_back(dr);
  }
  return ret;
}

static std::string getOptionValue(const boost::optional<std::unordered_map<string, string>>& options, const std::string &name, const std::string &defaultValue)
{
  string selector=defaultValue;
  if(options) {
    if(options->count(name))
      selector=options->find(name)->second;
  }
  return selector;
}

static vector<ComboAddress> useSelector(const std::string &selector, const ComboAddress& bestwho, const vector<ComboAddress>& candidates)
{
  vector<ComboAddress> ret;

  if(selector=="all")
    return candidates;
  else if(selector=="random")
    ret.emplace_back(pickrandom(candidates));
  else if(selector=="pickclosest")
    ret.emplace_back(pickclosest(bestwho, candidates));
  else if(selector=="hashed")
    ret.emplace_back(hashed(bestwho, candidates));
  else {
    g_log<<Logger::Warning<<"LUA Record called with unknown selector '"<<selector<<"'"<<endl;
    ret.emplace_back(pickrandom(candidates));
  }

  return ret;
}

static vector<string> convIpListToString(const vector<ComboAddress> &comboAddresses)
{
  vector<string> ret;

  for (const auto& c : comboAddresses) {
    ret.emplace_back(c.toString());
  }

  return ret;
}

static vector<ComboAddress> convIplist(const iplist_t& src)
{
  vector<ComboAddress> ret;

  for(const auto& ip : src) {
    ret.emplace_back(ip.second);
  }

  return ret;
}

static vector<pair<int, ComboAddress> > convWIplist(std::unordered_map<int, wiplist_t > src)
{
  vector<pair<int,ComboAddress> > ret;

  for(const auto& i : src) {
    ret.emplace_back(atoi(i.second.at(1).c_str()), ComboAddress(i.second.at(2)));
  }

  return ret;
}

static thread_local unique_ptr<AuthLua4> s_LUA;
bool g_LuaRecordSharedState;

typedef struct AuthLuaRecordContext
{
  ComboAddress          bestwho;
  DNSName               qname;
  DNSName               zone;
  int                   zoneid;
} lua_record_ctx_t;

static thread_local unique_ptr<lua_record_ctx_t> s_lua_record_ctx;

void setupLuaRecords()
{
  LuaContext& lua = *s_LUA->getLua();

  lua.writeFunction("latlon", []() {
      double lat, lon;
      getLatLon(s_lua_record_ctx->bestwho.toString(), lat, lon);
      return std::to_string(lat)+" "+std::to_string(lon);
    });
  lua.writeFunction("latlonloc", []() {
      string loc;
      getLatLon(s_lua_record_ctx->bestwho.toString(), loc);
      return loc;
  });
  lua.writeFunction("closestMagic", []() {
      vector<ComboAddress> candidates;
      // Getting something like 192-0-2-1.192-0-2-2.198-51-100-1.example.org
      for(auto l : s_lua_record_ctx->qname.getRawLabels()) {
        boost::replace_all(l, "-", ".");
        try {
          candidates.emplace_back(l);
        } catch (const PDNSException& e) {
          // no need to continue as we most likely reached the end of the ip list
          break ;
        }
      }
      return pickclosest(s_lua_record_ctx->bestwho, candidates).toString();
    });
  lua.writeFunction("latlonMagic", [](){
      auto labels= s_lua_record_ctx->qname.getRawLabels();
      if(labels.size()<4)
        return std::string("unknown");
      double lat, lon;
      getLatLon(labels[3]+"."+labels[2]+"."+labels[1]+"."+labels[0], lat, lon);
      return std::to_string(lat)+" "+std::to_string(lon);
    });


  lua.writeFunction("createReverse", [](string suffix, boost::optional<std::unordered_map<string,string>> e){
      try {
        auto labels = s_lua_record_ctx->qname.getRawLabels();
        if(labels.size()<4)
          return std::string("unknown");
        
        vector<ComboAddress> candidates;
        
        // exceptions are relative to zone
        // so, query comes in for 4.3.2.1.in-addr.arpa, zone is called 2.1.in-addr.arpa
        // e["1.2.3.4"]="bert.powerdns.com" - should match, easy enough to do
        // the issue is with classless delegation..
        if(e) {
          ComboAddress req(labels[3]+"."+labels[2]+"."+labels[1]+"."+labels[0], 0);
          const auto& uom = *e;
          for(const auto& c : uom)
            if(ComboAddress(c.first, 0) == req)
              return c.second;
        }
        boost::format fmt(suffix);
        fmt.exceptions( boost::io::all_error_bits ^ ( boost::io::too_many_args_bit | boost::io::too_few_args_bit )  );
        fmt % labels[3] % labels[2] % labels[1] % labels[0];
        
        fmt % (labels[3]+"-"+labels[2]+"-"+labels[1]+"-"+labels[0]);

        boost::format fmt2("%02x%02x%02x%02x");
        for(int i=3; i>=0; --i)
          fmt2 % atoi(labels[i].c_str());

        fmt % (fmt2.str());

        return fmt.str();
      }
      catch(std::exception& ex) {
        g_log<<Logger::Error<<"error: "<<ex.what()<<endl;
      }
      return std::string("error");
    });
  lua.writeFunction("createForward", []() {
      DNSName rel=s_lua_record_ctx->qname.makeRelative(s_lua_record_ctx->zone);
      auto parts = rel.getRawLabels();
      if(parts.size()==4)
        return parts[0]+"."+parts[1]+"."+parts[2]+"."+parts[3];
      if(parts.size()==1) {
        // either hex string, or 12-13-14-15
        //        cout<<parts[0]<<endl;
        unsigned int x1, x2, x3, x4;
        if(sscanf(parts[0].c_str()+2, "%02x%02x%02x%02x", &x1, &x2, &x3, &x4)==4) {
          return std::to_string(x1)+"."+std::to_string(x2)+"."+std::to_string(x3)+"."+std::to_string(x4);
        }


      }
      return std::string("0.0.0.0");
    });

  lua.writeFunction("createForward6", []() {
      DNSName rel=s_lua_record_ctx->qname.makeRelative(s_lua_record_ctx->zone);
      auto parts = rel.getRawLabels();
      if(parts.size()==8) {
        string tot;
        for(int i=0; i<8; ++i) {
          if(i)
            tot.append(1,':');
          tot+=parts[i];
        }
        ComboAddress ca(tot);
        return ca.toString();
      }
      else if(parts.size()==1) {
        boost::replace_all(parts[0],"-",":");
        ComboAddress ca(parts[0]);
        return ca.toString();
      }

      return std::string("::");
    });
  lua.writeFunction("createReverse6", [](string suffix, boost::optional<std::unordered_map<string,string>> e){
      vector<ComboAddress> candidates;

      try {
        auto labels= s_lua_record_ctx->qname.getRawLabels();
        if(labels.size()<32)
          return std::string("unknown");
        boost::format fmt(suffix);
        fmt.exceptions( boost::io::all_error_bits ^ ( boost::io::too_many_args_bit | boost::io::too_few_args_bit )  );


        string together;
        vector<string> quads;
        for(int i=0; i<8; ++i) {
          if(i)
            together+=":";
          string quad;
          for(int j=0; j <4; ++j) {
            quad.append(1, labels[31-i*4-j][0]);
            together += labels[31-i*4-j][0];
          }
          quads.push_back(quad);
        }
        ComboAddress ip6(together,0);

        if(e) {
          auto& addrs=*e;
          for(const auto& addr: addrs) {
            // this makes sure we catch all forms of the address
            if(ComboAddress(addr.first,0)==ip6)
              return addr.second;
          }
        }

        string dashed=ip6.toString();
        boost::replace_all(dashed, ":", "-");

        for(int i=31; i>=0; --i)
          fmt % labels[i];
        fmt % dashed;

        for(const auto& quad : quads)
          fmt % quad;

        return fmt.str();
      }
      catch(std::exception& ex) {
        g_log<<Logger::Error<<"LUA Record xception: "<<ex.what()<<endl;
      }
      catch(PDNSException& ex) {
        g_log<<Logger::Error<<"LUA Record exception: "<<ex.reason<<endl;
      }
      return std::string("unknown");
    });

  /*
   * Simplistic test to see if an IP address listens on a certain port
   * Will return a single IP address from the set of available IP addresses. If
   * no IP address is available, will return a random element of the set of
   * addresses suppplied for testing.
   *
   * @example ifportup(443, { '1.2.3.4', '5.4.3.2' })"
   */
  lua.writeFunction("ifportup", [](int port, const vector<pair<int, string> >& ips, const boost::optional<std::unordered_map<string,string>> options) {
      vector<ComboAddress> candidates, unavailables;
      opts_t opts;
      vector<ComboAddress > conv;
      std::string selector;

      if(options)
        opts = *options;
      for(const auto& i : ips) {
        ComboAddress rem(i.second, port);
        if(g_up.isUp(rem, opts)) {
          candidates.push_back(rem);
        }
        else {
          unavailables.push_back(rem);
        }
      }
      if(!candidates.empty()) {
        // use regular selector
        selector = getOptionValue(options, "selector", "random");
      } else {
        // All units are down, apply backupSelector on all candidates
        candidates = std::move(unavailables);
        selector = getOptionValue(options, "backupSelector", "random");
      }

      vector<ComboAddress> res = useSelector(selector, s_lua_record_ctx->bestwho, candidates);
      return convIpListToString(res);
    });

  lua.writeFunction("ifurlup", [](const std::string& url,
                                          const boost::variant<iplist_t, ipunitlist_t>& ips,
                                          boost::optional<opts_t> options) {
      vector<vector<ComboAddress> > candidates;
      opts_t opts;
      if(options)
        opts = *options;
      if(auto simple = boost::get<iplist_t>(&ips)) {
        vector<ComboAddress> unit = convIplist(*simple);
        candidates.push_back(unit);
      } else {
        auto units = boost::get<ipunitlist_t>(ips);
        for(const auto& u : units) {
          vector<ComboAddress> unit = convIplist(u.second);
          candidates.push_back(unit);
        }
      }

      for(const auto& unit : candidates) {
        vector<ComboAddress> available;
        for(const auto& c : unit) {
          if(g_up.isUp(c, url, opts)) {
            available.push_back(c);
          }
        }
        if(!available.empty()) {
          vector<ComboAddress> res = useSelector(getOptionValue(options, "selector", "random"), s_lua_record_ctx->bestwho, available);
          return convIpListToString(res);
        }
      }

      // All units down, apply backupSelector on all candidates
      vector<ComboAddress> ret{};
      for(const auto& unit : candidates) {
        ret.insert(ret.end(), unit.begin(), unit.end());
      }

      vector<ComboAddress> res = useSelector(getOptionValue(options, "backupSelector", "random"), s_lua_record_ctx->bestwho, ret);
      return convIpListToString(res);
    });
  /*
   * Returns a random IP address from the supplied list
   * @example pickrandom({ '1.2.3.4', '5.4.3.2' })"
   */
  lua.writeFunction("pickrandom", [](const iplist_t& ips) {
      vector<ComboAddress> conv = convIplist(ips);

      return pickrandom(conv).toString();
    });


  /*
   * Returns a random IP address from the supplied list, as weighted by the
   * various ``weight`` parameters
   * @example pickwrandom({ {100, '1.2.3.4'}, {50, '5.4.3.2'}, {1, '192.168.1.0'} })
   */
  lua.writeFunction("pickwrandom", [](std::unordered_map<int, wiplist_t> ips) {
      vector<pair<int,ComboAddress> > conv = convWIplist(ips);

      return pickwrandom(conv).toString();
    });

  /*
   * Based on the hash of `bestwho`, returns an IP address from the list
   * supplied, as weighted by the various `weight` parameters
   * @example pickwhashed({ {15, '1.2.3.4'}, {50, '5.4.3.2'} })
   */
  lua.writeFunction("pickwhashed", [](std::unordered_map<int, wiplist_t > ips) {
      vector<pair<int,ComboAddress> > conv;

      for(auto& i : ips)
        conv.emplace_back(atoi(i.second[1].c_str()), ComboAddress(i.second[2]));

      return pickwhashed(s_lua_record_ctx->bestwho, conv).toString();
    });


  lua.writeFunction("pickclosest", [](const iplist_t& ips) {
      vector<ComboAddress > conv = convIplist(ips);

      return pickclosest(s_lua_record_ctx->bestwho, conv).toString();

    });

  if (g_luaRecordExecLimit > 0) {
      lua.executeCode(boost::str(boost::format("debug.sethook(report, '', %d)") % g_luaRecordExecLimit));
  }

  lua.writeFunction("report", [](string event, boost::optional<string> line){
      throw std::runtime_error("Script took too long");
    });

  lua.writeFunction("geoiplookup", [](const string &ip, const GeoIPInterface::GeoIPQueryAttribute attr) {
    return getGeo(ip, attr);
  });

  typedef const boost::variant<string,vector<pair<int,string> > > combovar_t;
  lua.writeFunction("continent", [](const combovar_t& continent) {
     string res=getGeo(s_lua_record_ctx->bestwho.toString(), GeoIPInterface::Continent);
      return doCompare(continent, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });
    });
  lua.writeFunction("asnum", [](const combovar_t& asns) {
      string res=getGeo(s_lua_record_ctx->bestwho.toString(), GeoIPInterface::ASn);
      return doCompare(asns, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });
    });
  lua.writeFunction("country", [](const combovar_t& var) {
      string res = getGeo(s_lua_record_ctx->bestwho.toString(), GeoIPInterface::Country2);
      return doCompare(var, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });

    });
  lua.writeFunction("netmask", [](const iplist_t& ips) {
      for(const auto& i :ips) {
        Netmask nm(i.second);
        if(nm.match(s_lua_record_ctx->bestwho))
          return true;
      }
      return false;
    });
  /* {
       {
        {'192.168.0.0/16', '10.0.0.0/8'},
        {'192.168.20.20', '192.168.20.21'}
       },
       {
        {'0.0.0.0/0'}, {'192.0.2.1'}
       }
     }
  */
  lua.writeFunction("view", [](const vector<pair<int, vector<pair<int, iplist_t> > > >& in) {
      for(const auto& rule : in) {
        const auto& netmasks=rule.second[0].second;
        const auto& destinations=rule.second[1].second;
        for(const auto& nmpair : netmasks) {
          Netmask nm(nmpair.second);
          if(nm.match(s_lua_record_ctx->bestwho)) {
            return destinations[dns_random(destinations.size())].second;
          }
        }
      }
      return std::string();
    }
    );


  lua.writeFunction("include", [&lua](string record) {
      try {
        vector<DNSZoneRecord> drs = lookup(DNSName(record) + s_lua_record_ctx->zone, QType::LUA, s_lua_record_ctx->zoneid);
        for(const auto& dr : drs) {
          auto lr = getRR<LUARecordContent>(dr.dr);
          lua.executeCode(lr->getCode());
        }
      }
      catch(std::exception& e) {
        g_log<<Logger::Error<<"Failed to load include record for LUArecord "<<(DNSName(record)+s_lua_record_ctx->zone)<<": "<<e.what()<<endl;
      }
    });
}

std::vector<shared_ptr<DNSRecordContent>> luaSynth(const std::string& code, const DNSName& query, const DNSName& zone, int zoneid, const DNSPacket& dnsp, uint16_t qtype)
{
  if(!s_LUA ||                  // we don't have a Lua state yet
     !g_LuaRecordSharedState) { // or we want a new one even if we had one
    s_LUA = make_unique<AuthLua4>();
    setupLuaRecords();
  }

  std::vector<shared_ptr<DNSRecordContent>> ret;

  LuaContext& lua = *s_LUA->getLua();

  s_lua_record_ctx = std::unique_ptr<lua_record_ctx_t>(new lua_record_ctx_t());
  s_lua_record_ctx->qname = query;
  s_lua_record_ctx->zone = zone;
  s_lua_record_ctx->zoneid = zoneid;
  
  lua.writeVariable("qname", query);
  lua.writeVariable("zone", zone);
  lua.writeVariable("zoneid", zoneid);
  lua.writeVariable("who", dnsp.getRemote());
  lua.writeVariable("dh", (dnsheader*)&dnsp.d);
  lua.writeVariable("dnssecOK", dnsp.d_dnssecOk);
  lua.writeVariable("tcp", dnsp.d_tcp);
  lua.writeVariable("ednsPKTSize", dnsp.d_ednsRawPacketSizeLimit);
  if(dnsp.hasEDNSSubnet()) {
    lua.writeVariable("ecswho", dnsp.getRealRemote());
    s_lua_record_ctx->bestwho = dnsp.getRealRemote().getNetwork();
  }
  else {
    lua.writeVariable("ecswho", nullptr);
    s_lua_record_ctx->bestwho = dnsp.getRemote();
  }
  lua.writeVariable("bestwho", s_lua_record_ctx->bestwho);

  try {
    string actual;
    if(!code.empty() && code[0]!=';')
      actual = "return " + code;
    else
      actual = code.substr(1);

    auto content=lua.executeCode<boost::variant<string, vector<pair<int, string> > > >(actual);

    vector<string> contents;
    if(auto str = boost::get<string>(&content))
      contents.push_back(*str);
    else
      for(const auto& c : boost::get<vector<pair<int,string>>>(content))
        contents.push_back(c.second);

    for(const auto& content_it: contents) {
      if(qtype==QType::TXT)
        ret.push_back(DNSRecordContent::mastermake(qtype, QClass::IN, '"'+content_it+'"' ));
      else
        ret.push_back(DNSRecordContent::mastermake(qtype, QClass::IN, content_it ));
    }
  } catch(std::exception &e) {
    g_log<<Logger::Error<<"Lua record reported: "<<e.what();
    try {
      std::rethrow_if_nested(e);
      g_log<<endl;
    } catch(const std::exception& ne) {
      g_log << ": " << ne.what() << std::endl;
    }
    catch(const PDNSException& ne) {
      g_log << ": " << ne.reason << std::endl;
    }
    throw ;
  }

  return ret;
}
