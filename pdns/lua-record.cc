#include <thread>
#include <future>
#include <boost/format.hpp>
#include <utility>
#include <algorithm>
#include <random>
#include "version.hh"
#include "ext/luawrapper/include/LuaContext.hpp"
#include "lock.hh"
#include "lua-auth4.hh"
#include "sstuff.hh"
#include "minicurl.hh"
#include "ueberbackend.hh"
#include "dnsrecords.hh"
#include "dns_random.hh"
#include "auth-main.hh"
#include "../modules/geoipbackend/geoipinterface.hh" // only for the enum

/* to do:
   block AXFR unless TSIG, or override

   investigate IPv6

   check the wildcard 'no cache' stuff, we may get it wrong

   ponder ECS scopemask setting

   ponder netmask tree from file for huge number of netmasks

   unify ifurlup/ifportup
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
  struct CheckState
  {
    CheckState(time_t _lastAccess): lastAccess(_lastAccess) {}
    /* current status */
    std::atomic<bool> status{false};
    /* first check ? */
    std::atomic<bool> first{true};
    /* last time the status was accessed */
    std::atomic<time_t> lastAccess{0};
  };

public:
  IsUpOracle()
  {
    d_checkerThreadStarted.clear();
  }
  ~IsUpOracle()
  {
  }
  bool isUp(const ComboAddress& remote, const opts_t& opts);
  bool isUp(const ComboAddress& remote, const std::string& url, const opts_t& opts);
  bool isUp(const CheckDesc& cd);

private:
  void checkURL(const CheckDesc& cd, const bool status, const bool first = false)
  {
    string remstring;
    try {
      int timeout = 2;
      if (cd.opts.count("timeout")) {
        timeout = std::atoi(cd.opts.at("timeout").c_str());
      }
      string useragent = productName();
      if (cd.opts.count("useragent")) {
        useragent = cd.opts.at("useragent");
      }
      MiniCurl mc(useragent);

      string content;
      const ComboAddress* rem = nullptr;
      if(cd.rem.sin4.sin_family != AF_UNSPEC) {
        rem = &cd.rem;
        remstring = rem->toString();
      } else {
        remstring = "[externally checked IP]";
      }

      if (cd.opts.count("source")) {
        ComboAddress src(cd.opts.at("source"));
        content=mc.getURL(cd.url, rem, &src, timeout);
      }
      else {
        content=mc.getURL(cd.url, rem, nullptr, timeout);
      }
      if (cd.opts.count("stringmatch") && content.find(cd.opts.at("stringmatch")) == string::npos) {
        throw std::runtime_error(boost::str(boost::format("unable to match content with `%s`") % cd.opts.at("stringmatch")));
      }

      if(!status) {
        g_log<<Logger::Info<<"LUA record monitoring declaring "<<remstring<<" UP for URL "<<cd.url<<"!"<<endl;
      }
      setUp(cd);
    }
    catch(std::exception& ne) {
      if(status || first)
        g_log<<Logger::Info<<"LUA record monitoring declaring "<<remstring<<" DOWN for URL "<<cd.url<<", error: "<<ne.what()<<endl;
      setDown(cd);
    }
  }
  void checkTCP(const CheckDesc& cd, const bool status, const bool first = false) {
    try {
      int timeout = 2;
      if (cd.opts.count("timeout")) {
        timeout = std::atoi(cd.opts.at("timeout").c_str());
      }
      Socket s(cd.rem.sin4.sin_family, SOCK_STREAM);
      ComboAddress src;
      s.setNonBlocking();
      if (cd.opts.count("source")) {
        src = ComboAddress(cd.opts.at("source"));
        s.bind(src);
      }
      s.connect(cd.rem, timeout);
      if (!status) {
        g_log<<Logger::Info<<"Lua record monitoring declaring TCP/IP "<<cd.rem.toStringWithPort()<<" ";
        if(cd.opts.count("source"))
          g_log<<"(source "<<src.toString()<<") ";
        g_log<<"UP!"<<endl;
      }
      setUp(cd);
    }
    catch (const NetworkError& ne) {
      if(status || first) {
        g_log<<Logger::Info<<"Lua record monitoring declaring TCP/IP "<<cd.rem.toStringWithPort()<<" DOWN: "<<ne.what()<<endl;
      }
      setDown(cd);
    }
  }
  void checkThread()
  {
    while (true)
    {
      std::chrono::system_clock::time_point checkStart = std::chrono::system_clock::now();
      std::vector<std::future<void>> results;
      std::vector<CheckDesc> toDelete;
      {
        // make sure there's no insertion
        auto statuses = d_statuses.read_lock();
        for (auto& it: *statuses) {
          auto& desc = it.first;
          auto& state = it.second;

          if (desc.url.empty()) { // TCP
            results.push_back(std::async(std::launch::async, &IsUpOracle::checkTCP, this, desc, state->status.load(), state->first.load()));
          } else { // URL
            results.push_back(std::async(std::launch::async, &IsUpOracle::checkURL, this, desc, state->status.load(), state->first.load()));
          }
          if (std::chrono::system_clock::from_time_t(state->lastAccess) < (checkStart - std::chrono::seconds(g_luaHealthChecksExpireDelay))) {
            toDelete.push_back(desc);
          }
        }
      }
      // we can release the lock as nothing will be deleted
      for (auto& future: results) {
        future.wait();
      }
      if (!toDelete.empty()) {
        auto statuses = d_statuses.write_lock();
        for (auto& it: toDelete) {
          statuses->erase(it);
        }
      }
      std::this_thread::sleep_until(checkStart + std::chrono::seconds(g_luaHealthChecksInterval));
    }
  }

  typedef map<CheckDesc, std::unique_ptr<CheckState>> statuses_t;
  SharedLockGuarded<statuses_t> d_statuses;

  std::unique_ptr<std::thread> d_checkerThread;
  std::atomic_flag d_checkerThreadStarted;

  void setStatus(const CheckDesc& cd, bool status)
  {
    auto statuses = d_statuses.write_lock();
    auto& state = (*statuses)[cd];
    state->status = status;
    if (state->first) {
      state->first = false;
    }
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
};

bool IsUpOracle::isUp(const CheckDesc& cd)
{
  if (!d_checkerThreadStarted.test_and_set()) {
    d_checkerThread = std::make_unique<std::thread>([this] { return checkThread(); });
  }
  time_t now = time(nullptr);
  {
    auto statuses = d_statuses.read_lock();
    auto iter = statuses->find(cd);
    if (iter != statuses->end()) {
      iter->second->lastAccess = now;
      return iter->second->status;
    }
  }
  // try to parse options so we don't insert any malformed content
  if (cd.opts.count("source")) {
    ComboAddress src(cd.opts.at("source"));
  }
  {
    auto statuses = d_statuses.write_lock();
    // Make sure we don't insert new entry twice now we have the lock
    if (statuses->find(cd) == statuses->end()) {
      (*statuses)[cd] = std::make_unique<CheckState>(now);
    }
  }
  return false;
}

bool IsUpOracle::isUp(const ComboAddress& remote, const opts_t& opts)
{
  CheckDesc cd{remote, "", opts};
  return isUp(cd);
}

bool IsUpOracle::isUp(const ComboAddress& remote, const std::string& url, const opts_t& opts)
{
  CheckDesc cd{remote, url, opts};
  return isUp(cd);
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


static std::string getGeo(const std::string& ip, GeoIPInterface::GeoIPQueryAttribute qa)
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

template <typename T>
static T pickRandom(const vector<T>& items)
{
  if (items.empty()) {
    throw std::invalid_argument("The items list cannot be empty");
  }
  return items[dns_random(items.size())];
}

template <typename T>
static T pickHashed(const ComboAddress& who, const vector<T>& items)
{
  if (items.empty()) {
    throw std::invalid_argument("The items list cannot be empty");
  }
  ComboAddress::addressOnlyHash aoh;
  return items[aoh(who) % items.size()];
}

template <typename T>
static T pickWeightedRandom(const vector< pair<int, T> >& items)
{
  if (items.empty()) {
    throw std::invalid_argument("The items list cannot be empty");
  }
  int sum=0;
  vector< pair<int, T> > pick;
  pick.reserve(items.size());

  for(auto& i : items) {
    sum += i.first;
    pick.emplace_back(sum, i.second);
  }
  
  if (sum == 0) {
    throw std::invalid_argument("The sum of items cannot be zero");
  }
  
  int r = dns_random(sum);
  auto p = upper_bound(pick.begin(), pick.end(), r, [](int rarg, const typename decltype(pick)::value_type& a) { return rarg < a.first; });
  return p->second;
}

template <typename T>
static T pickWeightedHashed(const ComboAddress& bestwho, vector< pair<int, T> >& items)
{
  if (items.empty()) {
    throw std::invalid_argument("The items list cannot be empty");
  }
  int sum=0;
  vector< pair<int, T> > pick;
  pick.reserve(items.size());

  for(auto& i : items) {
    sum += i.first;
    pick.push_back({sum, i.second});
  }
  
  if (sum == 0) {
    throw std::invalid_argument("The sum of items cannot be zero");
  }

  ComboAddress::addressOnlyHash aoh;
  int r = aoh(bestwho) % sum;
  auto p = upper_bound(pick.begin(), pick.end(), r, [](int rarg, const typename decltype(pick)::value_type& a) { return rarg < a.first; });
  return p->second;
}

template <typename T>
static vector<T> pickRandomSample(int n, const vector<T>& items) 
{
  if (items.empty()) {
    throw std::invalid_argument("The items list cannot be empty");
  }
  
  vector<T> pick;
  pick.reserve(items.size());
  
  for(auto& item : items) {
    pick.push_back(item);
  }
  
  int count = std::min(std::max<size_t>(0, n), items.size());

  if (count == 0) {
    return vector<T>();
  }  

  std::shuffle(pick.begin(), pick.end(), pdns::dns_random_engine());
  
  vector<T> result = {pick.begin(), pick.begin() + count};
  return result;
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

  double lat = 0, lon = 0;
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
  map<double, vector<ComboAddress> > ranked;
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
  static LockGuarded<UeberBackend> s_ub;

  DNSZoneRecord dr;
  vector<DNSZoneRecord> ret;
  {
    auto ub = s_ub.lock();
    ub->lookup(QType(qtype), name, zoneid);
    while (ub->get(dr)) {
      ret.push_back(dr);
    }
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
    ret.emplace_back(pickRandom<ComboAddress>(candidates));
  else if(selector=="pickclosest")
    ret.emplace_back(pickclosest(bestwho, candidates));
  else if(selector=="hashed")
    ret.emplace_back(pickHashed<ComboAddress>(bestwho, candidates));
  else {
    g_log<<Logger::Warning<<"LUA Record called with unknown selector '"<<selector<<"'"<<endl;
    ret.emplace_back(pickRandom<ComboAddress>(candidates));
  }

  return ret;
}

static vector<string> convComboAddressListToString(const vector<ComboAddress>& items)
{
  vector<string> result;
  result.reserve(items.size());

  for (const auto& item : items) {
    result.emplace_back(item.toString());
  }

  return result;
}

static vector<ComboAddress> convComboAddressList(const iplist_t& items)
{
  vector<ComboAddress> result;
  result.reserve(items.size());

  for(const auto& item : items) {
    result.emplace_back(ComboAddress(item.second));
  }

  return result;
}

static vector<string> convStringList(const iplist_t& items)
{
  vector<string> result;
  result.reserve(items.size());

  for(const auto& item : items) {
    result.emplace_back(item.second);
  }

  return result;
}

static vector< pair<int, string> > convIntStringPairList(const std::unordered_map<int, wiplist_t >& items)
{
  vector<pair<int,string> > result;
  result.reserve(items.size());

  for(const auto& item : items) {
    result.emplace_back(atoi(item.second.at(1).c_str()), item.second.at(2));
  }

  return result;
}

bool g_LuaRecordSharedState;

typedef struct AuthLuaRecordContext
{
  ComboAddress          bestwho;
  DNSName               qname;
  DNSName               zone;
  int                   zoneid;
} lua_record_ctx_t;

static thread_local unique_ptr<lua_record_ctx_t> s_lua_record_ctx;

static void setupLuaRecords(LuaContext& lua)
{
  lua.writeFunction("latlon", []() {
      double lat = 0, lon = 0;
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
      double lat = 0, lon = 0;
      getLatLon(labels[3]+"."+labels[2]+"."+labels[1]+"."+labels[0], lat, lon);
      return std::to_string(lat)+" "+std::to_string(lon);
    });


  lua.writeFunction("createReverse", [](string format, boost::optional<std::unordered_map<string,string>> e){
      try {
        auto labels = s_lua_record_ctx->qname.getRawLabels();
        if(labels.size()<4)
          return std::string("unknown");
        
        vector<ComboAddress> candidates;
        
        // so, query comes in for 4.3.2.1.in-addr.arpa, zone is called 2.1.in-addr.arpa
        // e["1.2.3.4"]="bert.powerdns.com" then provides an exception
        if(e) {
          ComboAddress req(labels[3]+"."+labels[2]+"."+labels[1]+"."+labels[0], 0);
          const auto& uom = *e;
          for(const auto& c : uom)
            if(ComboAddress(c.first, 0) == req)
              return c.second;
        }
        boost::format fmt(format);
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
      static string allZerosIP{"0.0.0.0"};
      try {
        DNSName rel{s_lua_record_ctx->qname.makeRelative(s_lua_record_ctx->zone)};

        // parts is something like ["1", "2", "3", "4", "static"] or
        // ["1", "2", "3", "4"] or ["ip40414243", "ip-addresses", ...]
        auto parts = rel.getRawLabels();
        // Yes, this still breaks if an 1-2-3-4.XXXX is nested too deeply...
        if (parts.size() >= 4) {
          ComboAddress address(parts[0]+"."+parts[1]+"."+parts[2]+"."+parts[3]);
          return address.toString();
        }
	if (!parts.empty()) {
          auto& input = parts.at(0);
          // either hex string, or 12-13-14-15
          vector<string> ip_parts;

          stringtok(ip_parts, input, "-");
          if (ip_parts.size() >= 4) {
            // 1-2-3-4 with any prefix (e.g. ip-foo-bar-1-2-3-4)
            string ret;
            for (size_t index=4; index > 0; index--) {
              auto octet = ip_parts.at(ip_parts.size() - index);
              auto octetVal = std::stol(octet); // may throw
              if (octetVal >= 0 && octetVal <= 255) {
                ret += octet + ".";
              } else {
                return allZerosIP;
              }
            }
            ret.resize(ret.size() - 1); // remove trailing dot after last octet
            return ret;
          }
          if (input.length() == 10) {
            auto last8 = input.substr(input.length()-8);
            unsigned int part1{0};
            unsigned int part2{0};
            unsigned int part3{0};
            unsigned int part4{0};
            if (sscanf(last8.c_str(), "%02x%02x%02x%02x", &part1, &part2, &part3, &part4) == 4) {
              ComboAddress address(std::to_string(part1) + "." + std::to_string(part2) + "." + std::to_string(part3) + "." + std::to_string(part4));
              return address.toString();
            }
          }
        }
        return allZerosIP;
      } catch (const PDNSException &e) {
        return allZerosIP;
      }
    });

  lua.writeFunction("createForward6", []() {
      static string allZerosIP{"::"};
      try {
        DNSName rel{s_lua_record_ctx->qname.makeRelative(s_lua_record_ctx->zone)};

        auto parts = rel.getRawLabels();
        if (parts.size() == 8) {
          string tot;
          for (int chunk = 0; chunk < 8; ++chunk) {
            if (chunk != 0) {
              tot.append(1, ':');
	      }
            tot += parts.at(chunk);
          }
          ComboAddress address(tot);
          return address.toString();
        }
        if (parts.size() == 1) {
          if (parts[0].find('-') != std::string::npos) {
            std::replace(parts[0].begin(), parts[0].end(), '-', ':');
            ComboAddress address(parts[0]);
            return address.toString();
          }
        }
        return allZerosIP;
      } catch (const PDNSException &e) {
        return allZerosIP;
      }
    });
  lua.writeFunction("createReverse6", [](const string &format, boost::optional<std::unordered_map<string,string>> excp){
      vector<ComboAddress> candidates;

      try {
        auto labels= s_lua_record_ctx->qname.getRawLabels();
        if (labels.size()<32) {
          return std::string("unknown");
	}
        boost::format fmt(format);
        fmt.exceptions( boost::io::all_error_bits ^ ( boost::io::too_many_args_bit | boost::io::too_few_args_bit )  );


        string together;
        vector<string> quads;
        for (int chunk = 0; chunk < 8; ++chunk) {
          if (chunk != 0) {
            together += ":";
	  }
          string lquad;
          for (int quartet = 0; quartet < 4; ++quartet) {
            lquad.append(1, labels[31 - chunk * 4 - quartet][0]);
            together += labels[31 - chunk * 4 - quartet][0];
          }
          quads.push_back(lquad);
        }
	ComboAddress ip6(together,0);

	if (excp) {
          auto& addrs=*excp;
          for(const auto& addr: addrs) {
            // this makes sure we catch all forms of the address
            if (ComboAddress(addr.first, 0) == ip6) {
              return addr.second;
	    }
          }
        }

        string dashed=ip6.toString();
        boost::replace_all(dashed, ":", "-");

        for (int byte = 31; byte >= 0; --byte) {
          fmt % labels[byte];
	}
        fmt % dashed;

        for(const auto& lquad : quads) {
          fmt % lquad;
	}

        return fmt.str();
      }
      catch(std::exception& ex) {
        g_log<<Logger::Error<<"LUA Record exception: "<<ex.what()<<endl;
      }
      catch(PDNSException& ex) {
        g_log<<Logger::Error<<"LUA Record exception: "<<ex.reason<<endl;
      }
      return std::string("unknown");
    });

  lua.writeFunction("filterForward", [](string address, NetmaskGroup& nmg, boost::optional<string> fallback) {
      ComboAddress ca(address);

      if (nmg.match(ComboAddress(address))) {
        return address;
      } else {
        if (fallback) {
          return *fallback;
        }

        if (ca.isIPv4()) {
          return string("0.0.0.0");
        } else {
          return string("::");
        }
      }
    });

  /*
   * Simplistic test to see if an IP address listens on a certain port
   * Will return a single IP address from the set of available IP addresses. If
   * no IP address is available, will return a random element of the set of
   * addresses supplied for testing.
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
      return convComboAddressListToString(res);
    });

  lua.writeFunction("ifurlextup", [](const vector<pair<int, opts_t> >& ipurls, boost::optional<opts_t> options) {
      vector<ComboAddress> candidates;
      opts_t opts;
      if(options)
        opts = *options;

      ComboAddress ca_unspec;
      ca_unspec.sin4.sin_family=AF_UNSPEC;

      // ipurls: { { ["192.0.2.1"] = "https://example.com", ["192.0.2.2"] = "https://example.com/404" } }
      for (const auto& [count, unitmap] : ipurls) {
        // unitmap: 1 = { ["192.0.2.1"] = "https://example.com", ["192.0.2.2"] = "https://example.com/404" }
        vector<ComboAddress> available;

        for (const auto& [ipStr, url] : unitmap) {
          // unit: ["192.0.2.1"] = "https://example.com"
          ComboAddress ip(ipStr);
          candidates.push_back(ip);
          if (g_up.isUp(ca_unspec, url, opts)) {
            available.push_back(ip);
          }
        }
        if(!available.empty()) {
          vector<ComboAddress> res = useSelector(getOptionValue(options, "selector", "random"), s_lua_record_ctx->bestwho, available);
          return convComboAddressListToString(res);
        }
      }

      // All units down, apply backupSelector on all candidates
      vector<ComboAddress> res = useSelector(getOptionValue(options, "backupSelector", "random"), s_lua_record_ctx->bestwho, candidates);
      return convComboAddressListToString(res);
    });

  lua.writeFunction("ifurlup", [](const std::string& url,
                                          const boost::variant<iplist_t, ipunitlist_t>& ips,
                                          boost::optional<opts_t> options) {
      vector<vector<ComboAddress> > candidates;
      opts_t opts;
      if(options)
        opts = *options;
      if(auto simple = boost::get<iplist_t>(&ips)) {
        vector<ComboAddress> unit = convComboAddressList(*simple);
        candidates.push_back(unit);
      } else {
        auto units = boost::get<ipunitlist_t>(ips);
        for(const auto& u : units) {
          vector<ComboAddress> unit = convComboAddressList(u.second);
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
          return convComboAddressListToString(res);
        }
      }

      // All units down, apply backupSelector on all candidates
      vector<ComboAddress> ret{};
      for(const auto& unit : candidates) {
        ret.insert(ret.end(), unit.begin(), unit.end());
      }

      vector<ComboAddress> res = useSelector(getOptionValue(options, "backupSelector", "random"), s_lua_record_ctx->bestwho, ret);
      return convComboAddressListToString(res);
    });
  /*
   * Returns a random IP address from the supplied list
   * @example pickrandom({ '1.2.3.4', '5.4.3.2' })"
   */
  lua.writeFunction("pickrandom", [](const iplist_t& ips) {
      vector<string> items = convStringList(ips);
      return pickRandom<string>(items);
    });

  lua.writeFunction("pickrandomsample", [](int n, const iplist_t& ips) {
      vector<string> items = convStringList(ips);
	  return pickRandomSample<string>(n, items);
    });

  lua.writeFunction("pickhashed", [](const iplist_t& ips) {
      vector<string> items = convStringList(ips);
      return pickHashed<string>(s_lua_record_ctx->bestwho, items);
    });
  /*
   * Returns a random IP address from the supplied list, as weighted by the
   * various ``weight`` parameters
   * @example pickwrandom({ {100, '1.2.3.4'}, {50, '5.4.3.2'}, {1, '192.168.1.0'} })
   */
  lua.writeFunction("pickwrandom", [](std::unordered_map<int, wiplist_t> ips) {
      vector< pair<int, string> > items = convIntStringPairList(ips);
      return pickWeightedRandom<string>(items);
    });

  /*
   * Based on the hash of `bestwho`, returns an IP address from the list
   * supplied, as weighted by the various `weight` parameters
   * @example pickwhashed({ {15, '1.2.3.4'}, {50, '5.4.3.2'} })
   */
  lua.writeFunction("pickwhashed", [](std::unordered_map<int, wiplist_t > ips) {
      vector< pair<int, string> > items;

      items.reserve(ips.size());
      for(auto& i : ips)
        items.emplace_back(atoi(i.second[1].c_str()), i.second[2]);

      return pickWeightedHashed<string>(s_lua_record_ctx->bestwho, items);
    });


  lua.writeFunction("pickclosest", [](const iplist_t& ips) {
      vector<ComboAddress> conv = convComboAddressList(ips);

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

  lua.writeFunction("asnum", [](const combovar_t& asns) {
      string res=getGeo(s_lua_record_ctx->bestwho.toString(), GeoIPInterface::ASn);
      return doCompare(asns, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });
    });
  lua.writeFunction("continent", [](const combovar_t& continent) {
     string res=getGeo(s_lua_record_ctx->bestwho.toString(), GeoIPInterface::Continent);
      return doCompare(continent, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });
    });
  lua.writeFunction("continentCode", []() {
      string unknown("unknown");
      string res = getGeo(s_lua_record_ctx->bestwho.toString(), GeoIPInterface::Continent);
      if ( res == unknown ) {
       return std::string("--");
      }
      return res;
    });
  lua.writeFunction("country", [](const combovar_t& var) {
      string res = getGeo(s_lua_record_ctx->bestwho.toString(), GeoIPInterface::Country2);
      return doCompare(var, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });

    });
  lua.writeFunction("countryCode", []() {
      string unknown("unknown");
      string res = getGeo(s_lua_record_ctx->bestwho.toString(), GeoIPInterface::Country2);
      if ( res == unknown ) {
       return std::string("--");
      }
      return res;
    });
  lua.writeFunction("region", [](const combovar_t& var) {
      string res = getGeo(s_lua_record_ctx->bestwho.toString(), GeoIPInterface::Region);
      return doCompare(var, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });

    });
  lua.writeFunction("regionCode", []() {
      string unknown("unknown");
      string res = getGeo(s_lua_record_ctx->bestwho.toString(), GeoIPInterface::Region);
      if ( res == unknown ) {
       return std::string("--");
      }
      return res;
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
            if (destinations.empty()) {
              throw std::invalid_argument("The IP list cannot be empty (for netmask " + nm.toString() + ")");
            }
            return destinations[dns_random(destinations.size())].second;
          }
        }
      }
      return std::string();
    });

  lua.writeFunction("all", [](const vector< pair<int,string> >& ips) {
      vector<string> result;
	  result.reserve(ips.size());
	  
      for(const auto& ip : ips) {
          result.emplace_back(ip.second);
      }
      if(result.empty()) {
        throw std::invalid_argument("The IP list cannot be empty");
      }
      return result;
    });

  lua.writeFunction("include", [&lua](string record) {
      DNSName rec;
      try {
        rec = DNSName(record) + s_lua_record_ctx->zone;
      } catch (const std::exception &e){
        g_log<<Logger::Error<<"Included record cannot be loaded, the name ("<<record<<") is malformed: "<<e.what()<<endl;
        return;
      }
      try {
        vector<DNSZoneRecord> drs = lookup(rec, QType::LUA, s_lua_record_ctx->zoneid);
        for(const auto& dr : drs) {
          auto lr = getRR<LUARecordContent>(dr.dr);
          lua.executeCode(lr->getCode());
        }
      }
      catch(std::exception& e) {
        g_log<<Logger::Error<<"Failed to load include record for LUArecord "<<rec<<": "<<e.what()<<endl;
      }
    });
}

std::vector<shared_ptr<DNSRecordContent>> luaSynth(const std::string& code, const DNSName& query, const DNSName& zone, int zoneid, const DNSPacket& dnsp, uint16_t qtype, unique_ptr<AuthLua4>& LUA)
{
  if(!LUA ||                  // we don't have a Lua state yet
     !g_LuaRecordSharedState) { // or we want a new one even if we had one
    LUA = make_unique<AuthLua4>();
    setupLuaRecords(*LUA->getLua());
  }

  std::vector<shared_ptr<DNSRecordContent>> ret;

  LuaContext& lua = *LUA->getLua();

  s_lua_record_ctx = std::make_unique<lua_record_ctx_t>();
  s_lua_record_ctx->qname = query;
  s_lua_record_ctx->zone = zone;
  s_lua_record_ctx->zoneid = zoneid;
  
  lua.writeVariable("qname", query);
  lua.writeVariable("zone", zone);
  lua.writeVariable("zoneid", zoneid);
  lua.writeVariable("who", dnsp.getInnerRemote());
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
    s_lua_record_ctx->bestwho = dnsp.getInnerRemote();
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
    g_log << Logger::Info << "Lua record ("<<query<<"|"<<QType(qtype).toString()<<") reported: " << e.what();
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
