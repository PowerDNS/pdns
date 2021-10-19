#include "config.h"
#include "ext/luawrapper/include/LuaContext.hpp"

#include <fstream>
#include <thread>
#include "namespaces.hh"
#include "logger.hh"
#include "rec-lua-conf.hh"
#include "sortlist.hh"
#include "filterpo.hh"
#include "syncres.hh"
#include "rpzloader.hh"
#include "base64.hh"
#include "remote_logger.hh"
#include "validate.hh"
#include "validate-recursor.hh"
#include "root-dnssec.hh"

GlobalStateHolder<LuaConfigItems> g_luaconfs; 

/* SO HOW DOES THIS WORK! AND PLEASE PAY ATTENTION!
   This function can be called at any time. It is expected to overwrite all the contents
   of LuaConfigItems, which is held in a GlobalStateHolder for RCU properties.

   This function can be called again at a later date, so you must make sure that anything you
   allow to be configured from here lives in g_luaconfs AND NOWHERE ELSE.

   If someone loads an empty Lua file, the default LuaConfigItems struct MUST MAKE SENSE.

   To make this easy on you, here is a LuaConfigItems constructor where you
   can set sane defaults:
*/

LuaConfigItems::LuaConfigItems()
{
  DNSName root("."); // don't use g_rootdnsname here, it might not exist yet
  for (const auto &dsRecord : rootDSs) {
    auto ds=std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(dsRecord));
    dsAnchors[root].insert(*ds);
  }
}

/* DID YOU READ THE STORY ABOVE? */

template <typename C>
typename C::value_type::second_type constGet(const C& c, const std::string& name)
{
  auto iter = c.find(name);
  if(iter == c.end())
    return 0;
  return iter->second;
}

typedef std::unordered_map<std::string, boost::variant<bool, uint32_t, std::string, std::vector<std::pair<int, std::string>> > > rpzOptions_t;

static void parseRPZParameters(rpzOptions_t& have, std::shared_ptr<DNSFilterEngine::Zone>& zone, std::string& polName, std::optional<DNSFilterEngine::Policy>& defpol, bool& defpolOverrideLocal, uint32_t& maxTTL)
{
  if (have.count("policyName")) {
    polName = boost::get<std::string>(have["policyName"]);
  }
  if (have.count("defpol")) {
    defpol=DNSFilterEngine::Policy();
    defpol->d_kind = (DNSFilterEngine::PolicyKind)boost::get<uint32_t>(have["defpol"]);
    defpol->setName(polName);
    if(defpol->d_kind == DNSFilterEngine::PolicyKind::Custom) {
      defpol->d_custom.push_back(DNSRecordContent::mastermake(QType::CNAME, QClass::IN,
                                                              boost::get<string>(have["defcontent"])));

      if(have.count("defttl"))
        defpol->d_ttl = static_cast<int32_t>(boost::get<uint32_t>(have["defttl"]));
      else
        defpol->d_ttl = -1; // get it from the zone
    }

    if (have.count("defpolOverrideLocalData")) {
      defpolOverrideLocal = boost::get<bool>(have["defpolOverrideLocalData"]);
    }
  }
  if (have.count("maxTTL")) {
    maxTTL = boost::get<uint32_t>(have["maxTTL"]);
  }
  if (have.count("zoneSizeHint")) {
    auto zoneSizeHint = static_cast<size_t>(boost::get<uint32_t>(have["zoneSizeHint"]));
    if (zoneSizeHint > 0) {
      zone->reserve(zoneSizeHint);
    }
  }
  if (have.count("tags")) {
    const auto tagsTable = boost::get<std::vector<std::pair<int, std::string>>>(have["tags"]);
    std::unordered_set<std::string> tags;
    for (const auto& tag : tagsTable) {
      tags.insert(tag.second);
    }
    zone->setTags(std::move(tags));
  }
  if (have.count("overridesGettag")) {
    zone->setPolicyOverridesGettag(boost::get<bool>(have["overridesGettag"]));
  }
  if (have.count("extendedErrorCode")) {
    auto code = boost::get<uint32_t>(have["extendedErrorCode"]);
    if (code > std::numeric_limits<uint16_t>::max()) {
      throw std::runtime_error("Invalid extendedErrorCode value " + std::to_string(code) + " in RPZ configuration");
    }

    zone->setExtendedErrorCode(static_cast<uint16_t>(code));
    if (have.count("extendedErrorExtra")) {
      zone->setExtendedErrorExtra(boost::get<std::string>(have["extendedErrorExtra"]));
    }
  }
}

typedef std::unordered_map<std::string, boost::variant<bool, uint64_t, std::string, std::vector<std::pair<int,std::string> > > > protobufOptions_t;

static void parseProtobufOptions(std::optional<protobufOptions_t> vars, ProtobufExportConfig& config)
{
  if (!vars) {
    return;
  }

  if (vars->count("timeout")) {
    config.timeout = boost::get<uint64_t>((*vars)["timeout"]);
  }

  if (vars->count("maxQueuedEntries")) {
    config.maxQueuedEntries = boost::get<uint64_t>((*vars)["maxQueuedEntries"]);
  }

  if (vars->count("reconnectWaitTime")) {
    config.reconnectWaitTime = boost::get<uint64_t>((*vars)["reconnectWaitTime"]);
  }

  if (vars->count("asyncConnect")) {
    config.asyncConnect = boost::get<bool>((*vars)["asyncConnect"]);
  }

  if (vars->count("taggedOnly")) {
    config.taggedOnly = boost::get<bool>((*vars)["taggedOnly"]);
  }

  if (vars->count("logQueries")) {
    config.logQueries = boost::get<bool>((*vars)["logQueries"]);
  }

  if (vars->count("logResponses")) {
    config.logResponses = boost::get<bool>((*vars)["logResponses"]);
  }

  if (vars->count("exportTypes")) {
    config.exportTypes.clear();

    auto types =  boost::get<std::vector<std::pair<int, std::string>>>((*vars)["exportTypes"]);
    for (const auto& pair : types) {
      const auto type = pair.second;
      bool found = false;

      for (const auto& entry : QType::names) {
        if (entry.first == type) {
          found = true;
          config.exportTypes.insert(entry.second);
          break;
        }
      }

      if (!found) {
        throw std::runtime_error("Unknown QType '" + type + "' in protobuf's export types");
      }
    }
  }
}

#ifdef HAVE_FSTRM
typedef std::unordered_map<std::string, boost::variant<bool, uint64_t, std::string, std::vector<std::pair<int,std::string> > > > frameStreamOptions_t;

static void parseFrameStreamOptions(std::optional<frameStreamOptions_t> vars, FrameStreamExportConfig& config)
{
  if (!vars) {
    return;
  }

  if (vars->count("logQueries")) {
    config.logQueries = boost::get<bool>((*vars)["logQueries"]);
  }
  if (vars->count("logResponses")) {
    config.logResponses = boost::get<bool>((*vars)["logResponses"]);
  }

  if (vars->count("bufferHint")) {
    config.bufferHint = boost::get<uint64_t>((*vars)["bufferHint"]);
  }
  if (vars->count("flushTimeout")) {
    config.flushTimeout = boost::get<uint64_t>((*vars)["flushTimeout"]);
  }
  if (vars->count("inputQueueSize")) {
    config.inputQueueSize = boost::get<uint64_t>((*vars)["inputQueueSize"]);
  }
  if (vars->count("outputQueueSize")) {
    config.outputQueueSize = boost::get<uint64_t>((*vars)["outputQueueSize"]);
  }
  if (vars->count("queueNotifyThreshold")) {
    config.queueNotifyThreshold = boost::get<uint64_t>((*vars)["queueNotifyThreshold"]);
  }
  if (vars->count("reopenInterval")) {
    config.reopenInterval = boost::get<uint64_t>((*vars)["reopenInterval"]);
  }
}
#endif /* HAVE_FSTRM */

static void rpzPrimary(LuaConfigItems& lci, luaConfigDelayedThreads& delayedThreads, const boost::variant<string, std::vector<std::pair<int, string>>>& primaries_, const string& zoneName, std::optional<rpzOptions_t> options)
{
  std::optional<DNSFilterEngine::Policy> defpol;
  bool defpolOverrideLocal = true;
  std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
  TSIGTriplet tt;
  uint32_t refresh=0;
  size_t maxReceivedXFRMBytes = 0;
  uint16_t axfrTimeout = 20;
  uint32_t maxTTL = std::numeric_limits<uint32_t>::max();
  ComboAddress localAddress;
  std::vector<ComboAddress> primaries;
  if (primaries_.type() == typeid(string)) {
    primaries.push_back(ComboAddress(boost::get<std::string>(primaries_), 53));
  }
  else {
    for (const auto& primary : boost::get<std::vector<std::pair<int, std::string>>>(primaries_)) {
      primaries.push_back(ComboAddress(primary.second, 53));
    }
  }

  size_t zoneIdx;
  std::string dumpFile;
  std::shared_ptr<SOARecordContent> sr = nullptr;

  try {
    std::string seedFile;
    std::string polName(zoneName);

    if (options) {
      auto& have = *options;
      parseRPZParameters(have, zone, polName, defpol, defpolOverrideLocal, maxTTL);

      if(have.count("tsigname")) {
        tt.name=DNSName(toLower(boost::get<string>(have["tsigname"])));
        tt.algo=DNSName(toLower(boost::get<string>(have[ "tsigalgo"])));
        if(B64Decode(boost::get<string>(have[ "tsigsecret"]), tt.secret))
          throw std::runtime_error("TSIG secret is not valid Base-64 encoded");
      }

      if(have.count("refresh")) {
        refresh = boost::get<uint32_t>(have["refresh"]);
        if (refresh == 0) {
          g_log<<Logger::Warning<<"rpzPrimary refresh value of 0 ignored"<<endl;
        }
      }

      if(have.count("maxReceivedMBytes")) {
        maxReceivedXFRMBytes = static_cast<size_t>(boost::get<uint32_t>(have["maxReceivedMBytes"]));
      }

      if(have.count("localAddress")) {
        localAddress = ComboAddress(boost::get<string>(have["localAddress"]));
      }

      if(have.count("axfrTimeout")) {
        axfrTimeout = static_cast<uint16_t>(boost::get<uint32_t>(have["axfrTimeout"]));
      }

      if(have.count("seedFile")) {
        seedFile = boost::get<std::string>(have["seedFile"]);
      }

      if(have.count("dumpFile")) {
        dumpFile = boost::get<std::string>(have["dumpFile"]);
      }
    }

    if (localAddress != ComboAddress()) {
      // We were passed a localAddress, check if its AF matches the primaries'
      for (const auto& primary : primaries) {
        if (localAddress.sin4.sin_family != primary.sin4.sin_family) {
          throw PDNSException("Primary address("+primary.toString()+") is not of the same Address Family as the local address ("+localAddress.toString()+").");
        }
      }
    }

    DNSName domain(zoneName);
    zone->setDomain(domain);
    zone->setName(polName);
    zoneIdx = lci.dfe.addZone(zone);

    if (!seedFile.empty()) {
      g_log<<Logger::Info<<"Pre-loading RPZ zone "<<zoneName<<" from seed file '"<<seedFile<<"'"<<endl;
      try {
        sr = loadRPZFromFile(seedFile, zone, defpol, defpolOverrideLocal, maxTTL);

        if (zone->getDomain() != domain) {
          throw PDNSException("The RPZ zone " + zoneName + " loaded from the seed file (" + zone->getDomain().toString() + ") does not match the one passed in parameter (" + domain.toString() + ")");
        }

        if (sr == nullptr) {
          throw PDNSException("The RPZ zone " + zoneName + " loaded from the seed file (" + zone->getDomain().toString() + ") has no SOA record");
        }
      }
      catch(const PDNSException& e) {
        g_log<<Logger::Warning<<"Unable to pre-load RPZ zone "<<zoneName<<" from seed file '"<<seedFile<<"': "<<e.reason<<endl;
        zone->clear();
      }
      catch(const std::exception& e) {
        g_log<<Logger::Warning<<"Unable to pre-load RPZ zone "<<zoneName<<" from seed file '"<<seedFile<<"': "<<e.what()<<endl;
        zone->clear();
      }
    }
  }
  catch(const std::exception& e) {
    g_log<<Logger::Error<<"Problem configuring 'rpzPrimary': "<<e.what()<<endl;
    exit(1);  // FIXME proper exit code?
  }
  catch(const PDNSException& e) {
    g_log<<Logger::Error<<"Problem configuring 'rpzPrimary': "<<e.reason<<endl;
    exit(1);  // FIXME proper exit code?
  }

  delayedThreads.rpzPrimaryThreads.push_back(std::make_tuple(primaries, defpol, defpolOverrideLocal, maxTTL, zoneIdx, tt, maxReceivedXFRMBytes, localAddress, axfrTimeout, refresh, sr, dumpFile));
}

void loadRecursorLuaConfig(const std::string& fname, luaConfigDelayedThreads& delayedThreads)
{
  LuaConfigItems lci;

  LuaContext Lua;
  if(fname.empty())
    return;
  ifstream ifs(fname);
  if(!ifs)
    throw PDNSException("Cannot open file '"+fname+"': "+stringerror());

  auto luaconfsLocal = g_luaconfs.getLocal();
  lci.generation = luaconfsLocal->generation + 1;

  // pdnslog here is compatible with pdnslog in lua-base4.cc.
  Lua.writeFunction("pdnslog", [](const std::string& msg, std::optional<int> loglevel) { g_log << (Logger::Urgency)loglevel.value_or(Logger::Warning) << msg<<endl; });
  std::unordered_map<string, std::unordered_map<string, int>> pdns_table;
  pdns_table["loglevels"] = std::unordered_map<string, int>{
    {"Alert", LOG_ALERT},
    {"Critical", LOG_CRIT},
    {"Debug", LOG_DEBUG},
    {"Emergency", LOG_EMERG},
    {"Info", LOG_INFO},
    {"Notice", LOG_NOTICE},
    {"Warning", LOG_WARNING},
    {"Error", LOG_ERR}
  };
  Lua.writeVariable("pdns", pdns_table);

  Lua.writeFunction("clearSortlist", [&lci]() { lci.sortlist.clear(); });
  
  /* we can get: "1.2.3.4"
                 {"1.2.3.4", "4.5.6.7"}
		 {"1.2.3.4", {"4.5.6.7", "8.9.10.11"}}
  */

  map<string,DNSFilterEngine::PolicyKind> pmap{
    {"NoAction", DNSFilterEngine::PolicyKind::NoAction}, 
    {"Drop", DNSFilterEngine::PolicyKind::Drop},
    {"NXDOMAIN", DNSFilterEngine::PolicyKind::NXDOMAIN},
    {"NODATA", DNSFilterEngine::PolicyKind::NODATA},
    {"Truncate", DNSFilterEngine::PolicyKind::Truncate},
    {"Custom", DNSFilterEngine::PolicyKind::Custom}
  };
  Lua.writeVariable("Policy", pmap);

  Lua.writeFunction("rpzFile", [&lci](const string& filename, std::optional<rpzOptions_t> options) {
      try {
        std::optional<DNSFilterEngine::Policy> defpol;
        bool defpolOverrideLocal = true;
        std::string polName("rpzFile");
        std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
        uint32_t maxTTL = std::numeric_limits<uint32_t>::max();
        if (options) {
          auto& have = *options;
          parseRPZParameters(have, zone, polName, defpol, defpolOverrideLocal, maxTTL);
        }
        g_log<<Logger::Warning<<"Loading RPZ from file '"<<filename<<"'"<<endl;
        zone->setName(polName);
        loadRPZFromFile(filename, zone, defpol, defpolOverrideLocal, maxTTL);
        lci.dfe.addZone(zone);
        g_log<<Logger::Warning<<"Done loading RPZ from file '"<<filename<<"'"<<endl;
      }
      catch(const std::exception& e) {
        g_log<<Logger::Error<<"Unable to load RPZ zone from '"<<filename<<"': "<<e.what()<<endl;
      }
    });

  Lua.writeFunction("rpzMaster", [&lci, &delayedThreads](const boost::variant<string, std::vector<std::pair<int, string> > >& primaries_, const string& zoneName, std::optional<rpzOptions_t> options) {
    g_log<<Logger::Warning<<"'rpzMaster' is deprecated and will be removed in a future release, use 'rpzPrimary' instead"<< endl;
    rpzPrimary(lci, delayedThreads, primaries_, zoneName, options);
      });
  Lua.writeFunction("rpzPrimary", [&lci, &delayedThreads](const boost::variant<string, std::vector<std::pair<int, string> > >& primaries_, const string& zoneName, std::optional<rpzOptions_t> options) {
    rpzPrimary(lci, delayedThreads, primaries_, zoneName, options);
      });

  typedef std::unordered_map<std::string, boost::variant<uint32_t, std::string>> zoneToCacheOptions_t;

  Lua.writeFunction("zoneToCache", [&delayedThreads](const string& zoneName, const string& method, const boost::variant<string, std::vector<std::pair<int, string>>>& srcs, std::optional<zoneToCacheOptions_t> options) {
    try {
      RecZoneToCache::Config conf;
      DNSName validZoneName(zoneName);
      conf.d_zone = zoneName;
      const set<string> methods = {"axfr", "url", "file"};
      if (methods.count(method) == 0) {
        throw std::runtime_error("unknwon method '" + method + "'");
      }
      conf.d_method = method;
      if (srcs.type() == typeid(std::string)) {
        conf.d_sources.push_back(boost::get<std::string>(srcs));
      }
      else {
        for (const auto& src : boost::get<std::vector<std::pair<int, std::string>>>(srcs)) {
          conf.d_sources.push_back(src.second);
        }
      }
      if (conf.d_sources.size() == 0) {
        throw std::runtime_error("at least one source required");
      }
      if (options) {
        auto& have = *options;
        if (have.count("timeout")) {
          conf.d_timeout = boost::get<uint32_t>(have.at("timeout"));
        }
        if (have.count("tsigname")) {
          conf.d_tt.name = DNSName(toLower(boost::get<string>(have.at("tsigname"))));
          conf.d_tt.algo = DNSName(toLower(boost::get<string>(have.at("tsigalgo"))));
          if (B64Decode(boost::get<string>(have.at("tsigsecret")), conf.d_tt.secret)) {
            throw std::runtime_error("TSIG secret is not valid Base-64 encoded");
          }
        }
        if (have.count("maxReceivedMBytes")) {
          conf.d_maxReceivedBytes = static_cast<size_t>(boost::get<uint32_t>(have.at("maxReceivedMBytes")));
          conf.d_maxReceivedBytes *= 1024 * 1024;
        }
        if (have.count("localAddress")) {
          conf.d_local = ComboAddress(boost::get<string>(have.at("localAddress")));
        }
        if (have.count("refreshPeriod")) {
          conf.d_refreshPeriod = boost::get<uint32_t>(have.at("refreshPeriod"));
        }
        if (have.count("retryOnErrorPeriod")) {
          conf.d_retryOnError = boost::get<uint32_t>(have.at("retryOnErrorPeriod"));
        }
      }

      delayedThreads.ztcConfigs.push_back(conf);
    }
    catch (const std::exception& e) {
      g_log<<Logger::Error<<"Problem configuring zoneToCache for zone '" << zoneName << "': " << e.what() << endl;
    }
  });

  typedef vector<pair<int,boost::variant<string, vector<pair<int, string> > > > > argvec_t;
  Lua.writeFunction("addSortList", 
		    [&lci](const std::string& formask_, 
		       const boost::variant<string, argvec_t>& masks,
		       std::optional<int> order_) 
		    {
		      try {
			Netmask formask(formask_);
			int order = order_ ? (*order_) : lci.sortlist.getMaxOrder(formask)+1;
			if(auto str = boost::get<string>(&masks)) 
			  lci.sortlist.addEntry(formask, Netmask(*str), order);
			else {
	
			  auto vec = boost::get<argvec_t>(&masks);
			  for(const auto& e : *vec) {
			    if(auto s = boost::get<string>(&e.second)) {
			      lci.sortlist.addEntry(formask, Netmask(*s), order);
			    }
			    else {
			      const auto& v =boost::get<vector<pair<int, string> > >(e.second);
			      for(const auto& entry : v)
				lci.sortlist.addEntry(formask, Netmask(entry.second), order);
			    }
			    ++order;
			  }
			}
		      }
		      catch(std::exception& e) {
			g_log<<Logger::Error<<"Error in addSortList: "<<e.what()<<endl;
		      }
		    });

  Lua.writeFunction("addTA", [&lci](const std::string& who, const std::string& what) {
      warnIfDNSSECDisabled("Warning: adding Trust Anchor for DNSSEC (addTA), but dnssec is set to 'off'!");
      DNSName zone(who);
      auto ds = std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(what));
      lci.dsAnchors[zone].insert(*ds);
  });

  Lua.writeFunction("clearTA", [&lci](std::optional<string> who) {
      warnIfDNSSECDisabled("Warning: removing Trust Anchor for DNSSEC (clearTA), but dnssec is set to 'off'!");
      if(who)
        lci.dsAnchors.erase(DNSName(*who));
      else
        lci.dsAnchors.clear();
    });

  /* Remove in 4.3 */
  Lua.writeFunction("addDS", [&lci](const std::string& who, const std::string& what) {
      warnIfDNSSECDisabled("Warning: adding Trust Anchor for DNSSEC (addDS), but dnssec is set to 'off'!");
      g_log<<Logger::Warning<<"addDS is deprecated and will be removed in the future, switch to addTA"<<endl;
      DNSName zone(who);
      auto ds = std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(what));
      lci.dsAnchors[zone].insert(*ds);
  });

  /* Remove in 4.3 */
  Lua.writeFunction("clearDS", [&lci](std::optional<string> who) {
      g_log<<Logger::Warning<<"clearDS is deprecated and will be removed in the future, switch to clearTA"<<endl;
      warnIfDNSSECDisabled("Warning: removing Trust Anchor for DNSSEC (clearDS), but dnssec is set to 'off'!");
      if(who)
        lci.dsAnchors.erase(DNSName(*who));
      else
        lci.dsAnchors.clear();
    });

  Lua.writeFunction("addNTA", [&lci](const std::string& who, const std::optional<std::string> why) {
      warnIfDNSSECDisabled("Warning: adding Negative Trust Anchor for DNSSEC (addNTA), but dnssec is set to 'off'!");
      if(why)
        lci.negAnchors[DNSName(who)] = static_cast<string>(*why);
      else
        lci.negAnchors[DNSName(who)] = "";
    });

  Lua.writeFunction("clearNTA", [&lci](std::optional<string> who) {
      warnIfDNSSECDisabled("Warning: removing Negative Trust Anchor for DNSSEC (clearNTA), but dnssec is set to 'off'!");
      if(who)
        lci.negAnchors.erase(DNSName(*who));
      else
        lci.negAnchors.clear();
    });

  Lua.writeFunction("readTrustAnchorsFromFile", [&lci](const std::string& fnamearg, const std::optional<uint32_t> interval) {
      uint32_t realInterval = 24;
      if (interval) {
        realInterval = static_cast<uint32_t>(*interval);
      }
      warnIfDNSSECDisabled("Warning: reading Trust Anchors from file (readTrustAnchorsFromFile), but dnssec is set to 'off'!");
      lci.trustAnchorFileInfo.fname = fnamearg;
      lci.trustAnchorFileInfo.interval = realInterval;
      updateTrustAnchorsFromFile(fnamearg, lci.dsAnchors);
    });

  Lua.writeFunction("setProtobufMasks", [&lci](const uint8_t maskV4, uint8_t maskV6) {
      lci.protobufMaskV4 = maskV4;
      lci.protobufMaskV6 = maskV6;
    });

  Lua.writeFunction("protobufServer", [&lci](boost::variant<const std::string, const std::unordered_map<int, std::string>> servers, std::optional<protobufOptions_t> vars) {
        if (!lci.protobufExportConfig.enabled) {

          lci.protobufExportConfig.enabled = true;

          try {
            if (servers.type() == typeid(std::string)) {
              auto server = boost::get<const std::string>(servers);

              lci.protobufExportConfig.servers.emplace_back(server);
            }
            else {
              auto serversMap = boost::get<const std::unordered_map<int,std::string>>(servers);
              for (const auto& serverPair : serversMap) {
                lci.protobufExportConfig.servers.emplace_back(serverPair.second);
              }
            }

            parseProtobufOptions(vars, lci.protobufExportConfig);
          }
          catch(std::exception& e) {
            g_log<<Logger::Error<<"Error while adding protobuf logger: "<<e.what()<<endl;
          }
          catch(PDNSException& e) {
            g_log<<Logger::Error<<"Error while adding protobuf logger: "<<e.reason<<endl;
          }
        }
        else {
          g_log<<Logger::Error<<"Only one protobufServer() directive can be configured, we already have "<<lci.protobufExportConfig.servers.at(0).toString()<<endl;
        }
    });

  Lua.writeFunction("outgoingProtobufServer", [&lci](boost::variant<const std::string, const std::unordered_map<int, std::string>> servers, std::optional<protobufOptions_t> vars) {
      if (!lci.outgoingProtobufExportConfig.enabled) {

        lci.outgoingProtobufExportConfig.enabled = true;

          try {
            if (servers.type() == typeid(std::string)) {
              auto server = boost::get<const std::string>(servers);

              lci.outgoingProtobufExportConfig.servers.emplace_back(server);
            }
            else {
              auto serversMap = boost::get<const std::unordered_map<int,std::string>>(servers);
              for (const auto& serverPair : serversMap) {
                lci.outgoingProtobufExportConfig.servers.emplace_back(serverPair.second);
              }
            }

            parseProtobufOptions(vars, lci.outgoingProtobufExportConfig);
          }
          catch(std::exception& e) {
            g_log<<Logger::Error<<"Error while starting outgoing protobuf logger: "<<e.what()<<endl;
          }
          catch(PDNSException& e) {
            g_log<<Logger::Error<<"Error while starting outgoing protobuf logger: "<<e.reason<<endl;
          }
      }
      else {
        g_log<<Logger::Error<<"Only one outgoingProtobufServer() directive can be configured, we already have "<<lci.outgoingProtobufExportConfig.servers.at(0).toString()<<endl;
      }
    });

#ifdef HAVE_FSTRM
  Lua.writeFunction("dnstapFrameStreamServer", [&lci](boost::variant<const std::string, const std::unordered_map<int, std::string>> servers, std::optional<frameStreamOptions_t> vars) {
      if (!lci.frameStreamExportConfig.enabled) {

        lci.frameStreamExportConfig.enabled = true;

          try {
            if (servers.type() == typeid(std::string)) {
              auto server = boost::get<const std::string>(servers);
              if (!boost::starts_with(server, "/")) {
                ComboAddress parsecheck(server);
              }
              lci.frameStreamExportConfig.servers.emplace_back(server);
            }
            else {
              auto serversMap = boost::get<const std::unordered_map<int,std::string>>(servers);
              for (const auto& serverPair : serversMap) {
                lci.frameStreamExportConfig.servers.emplace_back(serverPair.second);
              }
            }

            parseFrameStreamOptions(vars, lci.frameStreamExportConfig);
          }
          catch(std::exception& e) {
            g_log<<Logger::Error<<"Error reading config for dnstap framestream logger: "<<e.what()<<endl;
          }
          catch(PDNSException& e) {
            g_log<<Logger::Error<<"Error reading config for dnstap framestream logger: "<<e.reason<<endl;
          }
      }
      else {
        g_log<<Logger::Error<<"Only one dnstapFrameStreamServer() directive can be configured, we already have "<<lci.frameStreamExportConfig.servers.at(0)<<endl;
      }
    });
#endif /* HAVE_FSTRM */

  try {
    Lua.executeCode(ifs);
    g_luaconfs.setState(std::move(lci));
  }
  catch(const LuaContext::ExecutionErrorException& e) {
    g_log<<Logger::Error<<"Unable to load Lua script from '"+fname+"': ";
    try {
      std::rethrow_if_nested(e);
    } catch(const std::exception& exp) {
      // exp is the exception that was thrown from inside the lambda
      g_log << exp.what() << std::endl;
    }
    catch(const PDNSException& exp) {
      // exp is the exception that was thrown from inside the lambda
      g_log << exp.reason << std::endl;
    }
    throw;

  }
  catch(std::exception& err) {
    g_log<<Logger::Error<<"Unable to load Lua script from '"+fname+"': "<<err.what()<<endl;
    throw;
  }

}

void startLuaConfigDelayedThreads(const luaConfigDelayedThreads& delayedThreads, uint64_t generation)
{
  for (const auto& rpzPrimary : delayedThreads.rpzPrimaryThreads) {
    try {
      // The get calls all return a value object here. That is essential, since we want copies so that RPZIXFRTracker gets values
      // with the proper lifetime.
      std::thread t(RPZIXFRTracker, std::get<0>(rpzPrimary), std::get<1>(rpzPrimary), std::get<2>(rpzPrimary), std::get<3>(rpzPrimary), std::get<4>(rpzPrimary), std::get<5>(rpzPrimary), std::get<6>(rpzPrimary) * 1024 * 1024, std::get<7>(rpzPrimary), std::get<8>(rpzPrimary), std::get<9>(rpzPrimary), std::get<10>(rpzPrimary), std::get<11>(rpzPrimary), generation);
      t.detach();
    }
    catch(const std::exception& e) {
      g_log<<Logger::Error<<"Problem starting RPZIXFRTracker thread: "<<e.what()<<endl;
      exit(1);
    }
    catch(const PDNSException& e) {
      g_log<<Logger::Error<<"Problem starting RPZIXFRTracker thread: "<<e.reason<<endl;
      exit(1);
    }
  }

  for (const auto& ztcConfig: delayedThreads.ztcConfigs) {
    try {
      std::thread t(RecZoneToCache::ZoneToCache, ztcConfig, generation);
      t.detach();
    }
    catch(const std::exception& e) {
      g_log<<Logger::Error<<"Problem starting zoneToCache thread: "<<e.what()<<endl;
      exit(1);
    }
    catch(const PDNSException& e) {
      g_log<<Logger::Error<<"Problem starting zoneToCache thread: "<<e.reason<<endl;
      exit(1);
    }
  }
}
