#include "ext/luawrapper/include/LuaContext.hpp"
#include "lua-auth4.hh"
#include <thread>
#include "sstuff.hh"
#include <mutex>
#include "minicurl.hh"
#include "ueberbackend.hh"
#include <boost/format.hpp>
// this is only for the ENUM
#include "../../modules/geoipbackend/geoipbackend.hh"

/* to do:
   global allow-lua-record setting
   zone metadata setting
   fix compilation/linking with/without geoipbackend
        use weak symbol?
   unify ifupurl/ifupport
      add attribute for query source 
      add attribute for certificate chedk
   add list of current monitors
      expire them too?

 */

class IsUpOracle
{
private:
  typedef std::unordered_map<string,string> opts_t;
  struct CheckDesc
  {
    ComboAddress rem;
    string url;
    opts_t opts;
    bool operator<(const CheckDesc& rhs) const
    {
      return std::make_tuple(rem, url) <
        std::make_tuple(rhs.rem, rhs.url);
    }
  };
public:
  bool isUp(const ComboAddress& remote);
  bool isUp(const ComboAddress& remote, const std::string& url, opts_t opts=opts_t());
    
private:
  void checkURLThread(ComboAddress rem, std::string url, opts_t opts);
  void checkTCPThread(const ComboAddress& rem) {
    CheckDesc cd{rem};
    setDown(cd);
    for(bool first=true;;first=false) {
      try {
        Socket s(rem.sin4.sin_family, SOCK_STREAM);
        s.setNonBlocking();
        s.connect(rem, 1);
        if(!isUp(rem))
          L<<Logger::Warning<<"Lua record monitoring declaring TCP/IP "<<rem.toStringWithPort()<<" UP!"<<endl;
        setUp(cd);
      }
      catch(NetworkError& ne) {
        if(isUp(rem) || first)
          L<<Logger::Warning<<"Lua record monitoring declaring TCP/IP "<<rem.toStringWithPort()<<" DOWN!"<<endl;
        setDown(cd);
      }
      sleep(1);
    }
  }


  struct Checker
  {
    std::thread* thr;
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

  void setDown(const ComboAddress& rem, const std::string& url=std::string(), opts_t opts=opts_t())
  {
    CheckDesc cd{rem, url, opts};
    setStatus(cd, false);
  }

  void setUp(const ComboAddress& rem, const std::string& url=std::string(), opts_t opts=opts_t())
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

  bool upStatus(const ComboAddress& rem, const std::string& url=std::string(), opts_t opts=opts_t())
  {
    CheckDesc cd{rem, url, opts};
    std::lock_guard<std::mutex> l(d_mutex);
    return d_statuses[cd].status;
  }

  statuses_t getStatus()
  {
    std::lock_guard<std::mutex> l(d_mutex);
    return d_statuses;
  }

};

bool IsUpOracle::isUp(const ComboAddress& remote)
{
  std::lock_guard<std::mutex> l(d_mutex);
  CheckDesc cd{remote};
  auto iter = d_statuses.find(cd);
  if(iter == d_statuses.end()) {
    L<<Logger::Warning<<"Launching TCP/IP status checker for "<<remote.toStringWithPort()<<endl;
    std::thread* checker = new std::thread(&IsUpOracle::checkTCPThread, this, remote);
    d_statuses[cd]=Checker{checker, false};
    return false;
  }
  return iter->second.status;
}

bool IsUpOracle::isUp(const ComboAddress& remote, const std::string& url, std::unordered_map<string,string> opts)
{
  CheckDesc cd{remote, url, opts};
  std::lock_guard<std::mutex> l(d_mutex);
  auto iter = d_statuses.find(cd);
  if(iter == d_statuses.end()) {
    //    L<<Logger::Warning<<"Launching HTTP(s) status checker for "<<remote.toStringWithPort()<<" and URL "<<url<<endl;
    std::thread* checker = new std::thread(&IsUpOracle::checkURLThread, this, remote, url, opts);
    d_statuses[cd]=Checker{checker, false};
    return false;
  }
  
  return iter->second.status;
}

void IsUpOracle::checkURLThread(ComboAddress rem, std::string url, opts_t opts) 
{
  setDown(rem, url, opts);
  for(bool first=true;;first=false) {
    try {
      MiniCurl mc;
      //      cout<<"Checking URL "<<url<<" at "<<rem.toString()<<endl;
      string content=mc.getURL(url, &rem);
      if(opts.count("stringmatch") && content.find(opts["stringmatch"]) == string::npos) {
        //        cout<<"URL "<<url<<" is up at "<<rem.toString()<<", but could not find stringmatch "<<opts["stringmatch"]<<" in page content, setting DOWN"<<endl;
        setDown(rem, url, opts);
        goto loop;
      }
      if(!upStatus(rem,url))
        L<<Logger::Warning<<"LUA record monitoring declaring "<<rem.toString()<<" UP for URL "<<url<<"!"<<endl;
      setUp(rem, url);
    }
    catch(std::exception& ne) {
      if(upStatus(rem,url,opts) || first)
        L<<Logger::Warning<<"LUA record monitoring declaring "<<rem.toString()<<" DOWN for URL "<<url<<", error: "<<ne.what()<<endl;
      setDown(rem,url);
    }
  loop:;
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


std::function<std::string(const std::string&, GeoIPBackend::GeoIPQueryAttribute)> g_getGeo;

std::string getGeo(const std::string& ip, GeoIPBackend::GeoIPQueryAttribute qa)
{
  static bool intialized;
  if(!g_getGeo) {
    if(!initialized) {
      L<<Logger::Error<<"LUA Record attempted to use GeoIPBackend functionality, but backend not launched"<<endl;
      initialized=true;
    }
    return "unknown";
  }
  else
    return g_getGeo(ip, qa);
}

static ComboAddress pickrandom(vector<ComboAddress>& ips)
{
  return ips[random() % ips.size()];
}

static ComboAddress hashed(const ComboAddress& who, vector<ComboAddress>& ips)
{
  ComboAddress::addressOnlyHash aoh;
  return ips[aoh(who) % ips.size()];
}


static ComboAddress wrandom(vector<pair<int,ComboAddress> >& wips)
{
  int sum=0;
  vector<pair<int, ComboAddress> > pick;
  for(auto& i : wips) {
    sum += i.first;
    pick.push_back({sum, i.second});
  }
  int r = random() % sum;
  auto p = upper_bound(pick.begin(), pick.end(),r, [](int r, const decltype(pick)::value_type& a) { return  r < a.first;});
  return p->second;
}

static ComboAddress whashed(const ComboAddress& bestwho, vector<pair<int,ComboAddress> >& wips)
{
  int sum=0;
  vector<pair<int, ComboAddress> > pick;
  for(auto& i : wips) {
    sum += i.first;
    pick.push_back({sum, i.second});
  }
  ComboAddress::addressOnlyHash aoh;
  int r = aoh(bestwho) % sum;
  auto p = upper_bound(pick.begin(), pick.end(),r, [](int r, const decltype(pick)::value_type& a) { return  r < a.first;});
  return p->second;
}

static bool getLatLon(const std::string& ip, double& lat, double& lon)
{
  string inp = getGeo(ip, GeoIPBackend::LatLon);
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
                      
                      

static ComboAddress closest(const ComboAddress& bestwho, vector<ComboAddress>& wips)
{
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
  return ranked.begin()->second[random() % ranked.begin()->second.size()];
}



std::vector<shared_ptr<DNSRecordContent>> luaSynth(const std::string& code, const DNSName& query, const DNSName& zone, int zoneid, const DNSPacket& dnsp, uint16_t qtype) 
{
  //  cerr<<"Called for "<<query<<", in zone "<<zone<<" for type "<<qtype<<endl;
  
  AuthLua4 alua("");
  std::vector<shared_ptr<DNSRecordContent>> ret;
  
  LuaContext& lua = *alua.getLua();
  lua.writeVariable("qname", query);
  lua.writeVariable("who", dnsp.getRemote());
  ComboAddress bestwho;
  if(dnsp.hasEDNSSubnet()) {
    lua.writeVariable("ecswho", dnsp.getRealRemote());
    bestwho=dnsp.getRealRemote().getNetwork();
    lua.writeVariable("bestwho", dnsp.getRealRemote().getNetwork());
  }
  else {
    bestwho=dnsp.getRemote();
  }

  lua.writeFunction("latlon", [&bestwho]() {
      double lat, lon;
      getLatLon(bestwho.toString(), lat, lon);
      return std::to_string(lat)+" "+std::to_string(lon);
    });

  lua.writeFunction("latlonloc", [&bestwho]() {
      string loc;
      getLatLon(bestwho.toString(), loc);
      cout<<"loc: "<<loc<<endl;
      return loc;
  });

  
  lua.writeFunction("closestMagic", [&bestwho,&query](){
      vector<ComboAddress> candidates;
      for(auto l : query.getRawLabels()) {
        boost::replace_all(l, "-", ".");
        try {
          candidates.emplace_back(l);
        }
        catch(...) {
          break;
        }
      }
      
      return closest(bestwho, candidates).toString();
    });
  
  
  lua.writeFunction("ifportup", [&bestwho](int port, const vector<pair<int, string> >& ips, const boost::optional<std::unordered_map<string,string>> options) {
      vector<ComboAddress> candidates;
      for(const auto& i : ips) {
        ComboAddress rem(i.second, port);
        if(g_up.isUp(rem))
          candidates.push_back(rem);
      }
      vector<string> ret;
      if(candidates.empty()) {
        //        cout<<"Everything is down. Returning all of them"<<endl;
        for(const auto& i : ips) 
          ret.push_back(i.second);
      }
      else {
        ComboAddress res;
        string selector="random";
        if(options) {
          if(options->count("selector"))
            selector=options->find("selector")->second;
        }
        if(selector=="random")
          res=pickrandom(candidates);
        else if(selector=="closest")
          res=closest(bestwho, candidates);
        else if(selector=="hashed")
          res=hashed(bestwho, candidates);
        else {
          L<<Logger::Warning<<"LUA Record ifportup called with unknown selector '"<<selector<<"'"<<endl;
          res=pickrandom(candidates);
        }
        ret.push_back(res.toString());
      }
      return ret;
    });


  lua.writeFunction("ifurlup", [](const std::string& url,
                                  const boost::variant<
                                  vector<pair<int, string> >,
                                  vector<pair<int, vector<pair<int, string> > > >
                                  > & ips, boost::optional<std::unordered_map<string,string>> options) {

      vector<vector<ComboAddress> > candidates;
      std::unordered_map<string,string> opts;
      if(options)
        opts = *options;
      if(auto simple = boost::get<vector<pair<int,string>>>(&ips)) {
        vector<ComboAddress> unit;
        for(const auto& i : *simple) {
          ComboAddress rem(i.second, 80);
          unit.push_back(rem);
        }
        candidates.push_back(unit);
      } else {
        auto units = boost::get<vector<pair<int, vector<pair<int, string> > > >>(ips);
        for(const auto& u : units) {
          vector<ComboAddress> unit;
          for(const auto& c : u.second) {
            ComboAddress rem(c.second, 80);
            unit.push_back(rem);
          }
          candidates.push_back(unit);
        }
      }

      //
      //      cout<<"Have "<<candidates.size()<<" units of IP addresses: "<<endl;
      vector<string> ret;
      for(const auto& unit : candidates) {
        vector<ComboAddress> available;
        for(const auto& c : unit)
          if(g_up.isUp(c, url, opts))
            available.push_back(c);
        if(available.empty()) {
          //  cerr<<"Entire unit is down, trying next one if available"<<endl;
          continue;
        }
        ret.push_back(available[random() % available.size()].toString());
        return ret;
      }      
      //      cerr<<"ALL units are down, returning all IP addresses"<<endl;
      for(const auto& unit : candidates) {
        for(const auto& c : unit)
          ret.push_back(c.toString());
      }

      return ret;
                    });



  /* idea: we have policies on vectors of ComboAddresses, like
     random, wrandom, whashed, closest. In C++ this is ComboAddress in,
     ComboAddress out. In Lua, vector string in, string out */
  
  lua.writeFunction("pickrandom", [](const vector<pair<int, string> >& ips) {
      return ips[random()%ips.size()].second;
    });

  // wrandom({ {100, '1.2.3.4'}, {50, '5.4.3.2'}, {1, '192.168.1.0'}})"

  lua.writeFunction("wrandom", [](std::unordered_map<int, std::unordered_map<int, string> > ips) {
      vector<pair<int,ComboAddress> > conv;
      for(auto& i : ips) 
        conv.emplace_back(atoi(i.second[1].c_str()), ComboAddress(i.second[2]));
      
      return wrandom(conv).toString();
    });

  lua.writeFunction("whashed", [&bestwho](std::unordered_map<int, std::unordered_map<int, string> > ips) {
      vector<pair<int,ComboAddress> > conv;
      for(auto& i : ips) 
        conv.emplace_back(atoi(i.second[1].c_str()), ComboAddress(i.second[2]));
      
      return whashed(bestwho, conv).toString();
      
    });


  lua.writeFunction("closest", [&bestwho](std::unordered_map<int, std::unordered_map<int, string> > ips) {
      vector<ComboAddress > conv;
      for(auto& i : ips) 
        conv.emplace_back(i.second[2]);
      
      return closest(bestwho, conv).toString();
      
    });

  
  int counter=0;
  lua.writeFunction("report", [&counter](string event, boost::optional<string> line){
      throw std::runtime_error("Script took too long");
    });
  lua.executeCode("debug.sethook(report, '', 1000)");

  lua.writeFunction("latlon", [&bestwho]() {
      return getGeo(bestwho.toString(), GeoIPBackend::LatLon);
    });
  
  typedef const boost::variant<string,vector<pair<int,string> > > combovar_t;
  lua.writeFunction("continent", [&bestwho](const combovar_t& continent) {
      string res=getGeo(bestwho.toString(), GeoIPBackend::Continent);
      return doCompare(continent, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });
    });

  lua.writeFunction("asnum", [&bestwho](const combovar_t& asns) {
      string res=getGeo(bestwho.toString(), GeoIPBackend::ASn);
      return doCompare(asns, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });
    });
  
  lua.writeFunction("country", [&bestwho](const combovar_t& var) {
      string res = getGeo(bestwho.toString(), GeoIPBackend::Country2);
      return doCompare(var, res, [](const std::string& a, const std::string& b) {
          return !strcasecmp(a.c_str(), b.c_str());
        });
       
    });

  lua.writeFunction("netmask", [bestwho](const vector<pair<int,string>>& ips) {
      for(const auto& i :ips) {
        Netmask nm(i.second);
        if(nm.match(bestwho))
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
  lua.writeFunction("view", [bestwho](const vector<pair<int, vector<pair<int, vector<pair<int, string> > > > > >& in) {
      for(const auto& rule : in) {
        const auto& netmasks=rule.second[0].second;
        const auto& destinations=rule.second[1].second;
        for(const auto& nmpair : netmasks) {
          Netmask nm(nmpair.second);
          if(nm.match(bestwho)) {
            return destinations[random() % destinations.size()].second;
          }
        }
      }
      return std::string();
    }
    );
  
  
  lua.writeFunction("include", [&lua,zone,zoneid](string record) {
      try {
        UeberBackend ub;
        ub.lookup(QType(QType::LUA), DNSName(record) +zone, 0, zoneid);
        DNSZoneRecord dr;
        while(ub.get(dr)) {
          auto lr = getRR<LUARecordContent>(dr.dr);
          lua.executeCode(lr->getCode());
        }
      }catch(std::exception& e) { cerr<<"Oops: "<<e.what()<<endl; }
    });

  
  try {
    string actual;
    if(!code.empty() && code[0]!=';')
      actual = "return ";
    actual+=code;
    auto content=lua.executeCode<boost::variant<string, vector<pair<int, string> > > >(actual);
    //  cout<<"Counter: "<<counter<<endl;
    vector<string> contents;
    if(auto str = boost::get<string>(&content))
      contents.push_back(*str);
    else
      for(const auto& c : boost::get<vector<pair<int,string>>>(content))
        contents.push_back(c.second);
    
    for(const auto& content: contents) {
      if(qtype==QType::TXT)
        ret.push_back(std::shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(qtype, 1, '"'+content+'"' )));
      else
        ret.push_back(std::shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(qtype, 1, content )));
    }
  }catch(std::exception &e) {
    cerr<<"Lua reported: "<<e.what()<<endl;
  }

  return ret;
}
