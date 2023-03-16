#include "config.h"
#include "ext/luawrapper/include/LuaContext.hpp"

#include <fstream>
#include <thread>
#include "namespaces.hh"
#include "logger.hh"
#include "lua-base4.hh"
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
  for (const auto& dsRecord : rootDSs) {
    auto ds = std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(dsRecord));
    dsAnchors[root].insert(*ds);
  }
}

/* DID YOU READ THE STORY ABOVE? */

bool operator==(const ProtobufExportConfig& configA, const ProtobufExportConfig& configB)
{
  // clang-format off
  return configA.exportTypes          == configB.exportTypes       &&
         configA.servers              == configB.servers           &&
         configA.maxQueuedEntries     == configB.maxQueuedEntries  &&
         configA.timeout              == configB.timeout           &&
         configA.reconnectWaitTime    == configB.reconnectWaitTime &&
         configA.asyncConnect         == configB.asyncConnect      &&
         configA.enabled              == configB.enabled           &&
         configA.logQueries           == configB.logQueries        &&
         configA.logResponses         == configB.logResponses      &&
         configA.taggedOnly           == configB.taggedOnly        &&
         configA.logMappedFrom        == configB.logMappedFrom;
  // clang-format on
}

bool operator!=(const ProtobufExportConfig& configA, const ProtobufExportConfig& configB)
{
  return !(configA == configB);
}

bool operator==(const FrameStreamExportConfig& configA, const FrameStreamExportConfig& configB)
{
  // clang-format off
  return configA.enabled              == configB.enabled              &&
         configA.logQueries           == configB.logQueries           &&
         configA.logResponses         == configB.logResponses         &&
         configA.logNODs              == configB.logNODs              &&
         configA.logUDRs              == configB.logUDRs              &&
         configA.bufferHint           == configB.bufferHint           &&
         configA.flushTimeout         == configB.flushTimeout         &&
         configA.inputQueueSize       == configB.inputQueueSize       &&
         configA.outputQueueSize      == configB.outputQueueSize      &&
         configA.queueNotifyThreshold == configB.queueNotifyThreshold &&
         configA.reopenInterval       == configB.reopenInterval       &&
         configA.servers              == configB.servers;
  // clang-format on
}

bool operator!=(const FrameStreamExportConfig& configA, const FrameStreamExportConfig& configB)
{
  return !(configA == configB);
}

template <typename C>
typename C::value_type::second_type constGet(const C& c, const std::string& name)
{
  auto iter = c.find(name);
  if (iter == c.end())
    return 0;
  return iter->second;
}

typedef std::unordered_map<std::string, boost::variant<bool, uint32_t, std::string, std::vector<std::pair<int, std::string>>>> rpzOptions_t;

static void parseRPZParameters(rpzOptions_t& have, std::shared_ptr<DNSFilterEngine::Zone>& zone, std::string& polName, boost::optional<DNSFilterEngine::Policy>& defpol, bool& defpolOverrideLocal, uint32_t& maxTTL)
{
  if (have.count("policyName")) {
    polName = boost::get<std::string>(have["policyName"]);
  }
  if (have.count("defpol")) {
    defpol = DNSFilterEngine::Policy();
    defpol->d_kind = (DNSFilterEngine::PolicyKind)boost::get<uint32_t>(have["defpol"]);
    defpol->setName(polName);
    if (defpol->d_kind == DNSFilterEngine::PolicyKind::Custom) {
      defpol->d_custom.push_back(DNSRecordContent::mastermake(QType::CNAME, QClass::IN,
                                                              boost::get<string>(have["defcontent"])));

      if (have.count("defttl"))
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

typedef std::unordered_map<std::string, boost::variant<bool, uint64_t, std::string, std::vector<std::pair<int, std::string>>>> protobufOptions_t;

static void parseProtobufOptions(boost::optional<protobufOptions_t> vars, ProtobufExportConfig& config)
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

  if (vars->count("logMappedFrom")) {
    config.logMappedFrom = boost::get<bool>((*vars)["logMappedFrom"]);
  }

  if (vars->count("exportTypes")) {
    config.exportTypes.clear();

    auto types = boost::get<std::vector<std::pair<int, std::string>>>((*vars)["exportTypes"]);
    for (const auto& pair : types) {
      const auto& type = pair.second;

      QType qtype;
      try {
        qtype = std::stoul(type);
      }
      catch (const std::exception& ex) {
        qtype = QType::chartocode(type.c_str());
        if (qtype == 0) {
          throw std::runtime_error("Unknown QType '" + type + "' in protobuf's export types");
        }
      }
      config.exportTypes.insert(qtype);
    }
  }
}

#ifdef HAVE_FSTRM
typedef std::unordered_map<std::string, boost::variant<bool, uint64_t, std::string, std::vector<std::pair<int, std::string>>>> frameStreamOptions_t;

static void parseFrameStreamOptions(boost::optional<frameStreamOptions_t> vars, FrameStreamExportConfig& config)
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
  if (vars->count("logNODs")) {
    config.logNODs = boost::get<bool>((*vars)["logNODs"]);
  }
  if (vars->count("logUDRs")) {
    config.logUDRs = boost::get<bool>((*vars)["logUDRs"]);
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

static void rpzPrimary(LuaConfigItems& lci, luaConfigDelayedThreads& delayedThreads, const boost::variant<string, std::vector<std::pair<int, string>>>& primaries_, const string& zoneName, boost::optional<rpzOptions_t> options)
{
  boost::optional<DNSFilterEngine::Policy> defpol;
  bool defpolOverrideLocal = true;
  std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
  TSIGTriplet tt;
  uint32_t refresh = 0;
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
  std::shared_ptr<const SOARecordContent> sr = nullptr;

  try {
    std::string seedFile;
    std::string polName(zoneName);

    if (options) {
      auto& have = *options;
      parseRPZParameters(have, zone, polName, defpol, defpolOverrideLocal, maxTTL);

      if (have.count("tsigname")) {
        tt.name = DNSName(toLower(boost::get<string>(have["tsigname"])));
        tt.algo = DNSName(toLower(boost::get<string>(have["tsigalgo"])));
        if (B64Decode(boost::get<string>(have["tsigsecret"]), tt.secret))
          throw std::runtime_error("TSIG secret is not valid Base-64 encoded");
      }

      if (have.count("refresh")) {
        refresh = boost::get<uint32_t>(have["refresh"]);
        if (refresh == 0) {
          SLOG(g_log << Logger::Warning << "rpzPrimary refresh value of 0 ignored" << endl,
               lci.d_slog->info(Logr::Warning, "rpzPrimary refresh value of 0 ignored"));
        }
      }

      if (have.count("maxReceivedMBytes")) {
        maxReceivedXFRMBytes = static_cast<size_t>(boost::get<uint32_t>(have["maxReceivedMBytes"]));
      }

      if (have.count("localAddress")) {
        localAddress = ComboAddress(boost::get<string>(have["localAddress"]));
      }

      if (have.count("axfrTimeout")) {
        axfrTimeout = static_cast<uint16_t>(boost::get<uint32_t>(have["axfrTimeout"]));
      }

      if (have.count("seedFile")) {
        seedFile = boost::get<std::string>(have["seedFile"]);
      }

      if (have.count("dumpFile")) {
        dumpFile = boost::get<std::string>(have["dumpFile"]);
      }
    }

    if (localAddress != ComboAddress()) {
      // We were passed a localAddress, check if its AF matches the primaries'
      for (const auto& primary : primaries) {
        if (localAddress.sin4.sin_family != primary.sin4.sin_family) {
          throw PDNSException("Primary address(" + primary.toString() + ") is not of the same Address Family as the local address (" + localAddress.toString() + ").");
        }
      }
    }

    DNSName domain(zoneName);
    zone->setDomain(domain);
    zone->setName(polName);
    zoneIdx = lci.dfe.addZone(zone);

    auto log = lci.d_slog->withValues("seedfile", Logging::Loggable(seedFile), "zone", Logging::Loggable(zoneName));
    if (!seedFile.empty()) {
      SLOG(g_log << Logger::Info << "Pre-loading RPZ zone " << zoneName << " from seed file '" << seedFile << "'" << endl,
           log->info(Logr::Info, "Pre-loading RPZ zone from seed file"));
      try {
        sr = loadRPZFromFile(seedFile, zone, defpol, defpolOverrideLocal, maxTTL);

        if (zone->getDomain() != domain) {
          throw PDNSException("The RPZ zone " + zoneName + " loaded from the seed file (" + zone->getDomain().toString() + ") does not match the one passed in parameter (" + domain.toString() + ")");
        }

        if (sr == nullptr) {
          throw PDNSException("The RPZ zone " + zoneName + " loaded from the seed file (" + zone->getDomain().toString() + ") has no SOA record");
        }
      }
      catch (const PDNSException& e) {
        SLOG(g_log << Logger::Warning << "Unable to pre-load RPZ zone " << zoneName << " from seed file '" << seedFile << "': " << e.reason << endl,
             log->error(Logr::Warning, e.reason, "Exception while pre-loadin RPZ zone", "exception", Logging::Loggable("PDNSException")));
        zone->clear();
      }
      catch (const std::exception& e) {
        SLOG(g_log << Logger::Warning << "Unable to pre-load RPZ zone " << zoneName << " from seed file '" << seedFile << "': " << e.what() << endl,
             log->error(Logr::Warning, e.what(), "Exception while pre-loadin RPZ zone", "exception", Logging::Loggable("std::exception")));
        zone->clear();
      }
    }
  }
  catch (const std::exception& e) {
    SLOG(g_log << Logger::Error << "Problem configuring 'rpzPrimary': " << e.what() << endl,
         lci.d_slog->error(Logr::Critical, e.what(), "Exception configuring 'rpzPrimary'", "exception", Logging::Loggable("std::exception")));
    exit(1); // FIXME proper exit code?
  }
  catch (const PDNSException& e) {
    SLOG(g_log << Logger::Error << "Problem configuring 'rpzPrimary': " << e.reason << endl,
         lci.d_slog->error(Logr::Critical, e.reason, "Exception configuring 'rpzPrimary'", Logging::Loggable("PDNSException")));
    exit(1); // FIXME proper exit code?
  }

  delayedThreads.rpzPrimaryThreads.push_back(std::make_tuple(primaries, defpol, defpolOverrideLocal, maxTTL, zoneIdx, tt, maxReceivedXFRMBytes, localAddress, axfrTimeout, refresh, sr, dumpFile));
}

// A wrapper class that loads the standard Lua defintions into the context, so that we can use things like pdns.A
class RecLuaConfigContext : public BaseLua4
{
public:
  RecLuaConfigContext()
  {
    prepareContext();
  }
  void postPrepareContext() override
  {
    // clang-format off
    d_pd.push_back({"AdditionalMode", in_t{
          {"Ignore", static_cast<int>(AdditionalMode::Ignore)},
          {"CacheOnly", static_cast<int>(AdditionalMode::CacheOnly)},
          {"CacheOnlyRequireAuth", static_cast<int>(AdditionalMode::CacheOnlyRequireAuth)},
          {"ResolveImmediately", static_cast<int>(AdditionalMode::ResolveImmediately)},
          {"ResolveDeferred", static_cast<int>(AdditionalMode::ResolveDeferred)}
        }});
  }
  void postLoad() override
  {
  }
  LuaContext* operator->()
  {
    return d_lw.get();
  }
};

void loadRecursorLuaConfig(const std::string& fname, luaConfigDelayedThreads& delayedThreads, ProxyMapping& proxyMapping)
{
  LuaConfigItems lci;
  lci.d_slog = g_slog->withName("luaconfig");

  RecLuaConfigContext Lua;

  if (fname.empty())
    return;
  ifstream ifs(fname);
  if (!ifs)
    throw PDNSException("Cannot open file '" + fname + "': " + stringerror());

  auto luaconfsLocal = g_luaconfs.getLocal();
  lci.generation = luaconfsLocal->generation + 1;

  Lua->writeFunction("clearSortlist", [&lci]() { lci.sortlist.clear(); });

  /* we can get: "1.2.3.4"
                 {"1.2.3.4", "4.5.6.7"}
                 {"1.2.3.4", {"4.5.6.7", "8.9.10.11"}}
  */

  map<string, DNSFilterEngine::PolicyKind> pmap{
    {"NoAction", DNSFilterEngine::PolicyKind::NoAction},
    {"Drop", DNSFilterEngine::PolicyKind::Drop},
    {"NXDOMAIN", DNSFilterEngine::PolicyKind::NXDOMAIN},
    {"NODATA", DNSFilterEngine::PolicyKind::NODATA},
    {"Truncate", DNSFilterEngine::PolicyKind::Truncate},
    {"Custom", DNSFilterEngine::PolicyKind::Custom}};
  Lua->writeVariable("Policy", pmap);

  Lua->writeFunction("rpzFile", [&lci](const string& filename, boost::optional<rpzOptions_t> options) {
    auto log = lci.d_slog->withValues("file", Logging::Loggable(filename));
    try {
      boost::optional<DNSFilterEngine::Policy> defpol;
      bool defpolOverrideLocal = true;
      std::string polName("rpzFile");
      std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
      uint32_t maxTTL = std::numeric_limits<uint32_t>::max();
      if (options) {
        auto& have = *options;
        parseRPZParameters(have, zone, polName, defpol, defpolOverrideLocal, maxTTL);
      }
      SLOG(g_log << Logger::Warning << "Loading RPZ from file '" << filename << "'" << endl,
           log->info(Logr::Info, "Loading RPZ from file"));
      zone->setName(polName);
      loadRPZFromFile(filename, zone, defpol, defpolOverrideLocal, maxTTL);
      lci.dfe.addZone(zone);
      SLOG(g_log << Logger::Warning << "Done loading RPZ from file '" << filename << "'" << endl,
           log->info(Logr::Info,  "Done loading RPZ from file"));
    }
    catch (const std::exception& e) {
      SLOG(g_log << Logger::Error << "Unable to load RPZ zone from '" << filename << "': " << e.what() << endl,
           log->error(Logr::Error, e.what(), "Exception while loading RPZ zone from file"));
    }
  });

  Lua->writeFunction("rpzMaster", [&lci, &delayedThreads](const boost::variant<string, std::vector<std::pair<int, string>>>& primaries_, const string& zoneName, boost::optional<rpzOptions_t> options) {
    SLOG(g_log << Logger::Warning << "'rpzMaster' is deprecated and will be removed in a future release, use 'rpzPrimary' instead" << endl,
         lci.d_slog->info(Logr::Warning, "'rpzMaster' is deprecated and will be removed in a future release, use 'rpzPrimary' instead"));
    rpzPrimary(lci, delayedThreads, primaries_, zoneName, options);
  });
  Lua->writeFunction("rpzPrimary", [&lci, &delayedThreads](const boost::variant<string, std::vector<std::pair<int, string>>>& primaries_, const string& zoneName, boost::optional<rpzOptions_t> options) {
    rpzPrimary(lci, delayedThreads, primaries_, zoneName, options);
  });

  typedef std::unordered_map<std::string, boost::variant<uint32_t, std::string>> zoneToCacheOptions_t;

  Lua->writeFunction("zoneToCache", [&lci](const string& zoneName, const string& method, const boost::variant<string, std::vector<std::pair<int, string>>>& srcs, boost::optional<zoneToCacheOptions_t> options) {
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
        const map<string, pdns::ZoneMD::Config> nameToVal = {
          {"ignore", pdns::ZoneMD::Config::Ignore},
          {"validate", pdns::ZoneMD::Config::Validate},
          {"require", pdns::ZoneMD::Config::Require},
        };
        if (have.count("zonemd")) {
          string zonemdValidation = boost::get<string>(have.at("zonemd"));
          auto it = nameToVal.find(zonemdValidation);
          if (it == nameToVal.end()) {
            throw std::runtime_error(zonemdValidation + " is not a valid value for `zonemd`");
          }
          else {
            conf.d_zonemd = it->second;
          }
        }
        if (have.count("dnssec")) {
          string dnssec = boost::get<string>(have.at("dnssec"));
          auto it = nameToVal.find(dnssec);
          if (it == nameToVal.end()) {
            throw std::runtime_error(dnssec + " is not a valid value for `dnssec`");
          }
          else {
            conf.d_dnssec = it->second;
          }
        }
      }

      lci.ztcConfigs[validZoneName] = conf;
    }
    catch (const std::exception& e) {
      SLOG(g_log << Logger::Error << "Problem configuring zoneToCache for zone '" << zoneName << "': " << e.what() << endl,
           lci.d_slog->error(Logr::Error, e.what(), "Problem configuring zoneToCache", "zone", Logging::Loggable(zoneName),
                             "exception", Logging::Loggable("std::exception")));
    }
  });

  typedef vector<pair<int, boost::variant<string, vector<pair<int, string>>>>> argvec_t;
  Lua->writeFunction("addSortList",
                     [&lci](const std::string& formask_,
                            const boost::variant<string, argvec_t>& masks,
                            boost::optional<int> order_) {
                       try {
                         Netmask formask(formask_);
                         int order = order_ ? (*order_) : lci.sortlist.getMaxOrder(formask) + 1;
                         if (auto str = boost::get<string>(&masks))
                           lci.sortlist.addEntry(formask, Netmask(*str), order);
                         else {

                           auto vec = boost::get<argvec_t>(&masks);
                           for (const auto& e : *vec) {
                             if (auto s = boost::get<string>(&e.second)) {
                               lci.sortlist.addEntry(formask, Netmask(*s), order);
                             }
                             else {
                               const auto& v = boost::get<vector<pair<int, string>>>(e.second);
                               for (const auto& entry : v)
                                 lci.sortlist.addEntry(formask, Netmask(entry.second), order);
                             }
                             ++order;
                           }
                         }
                       }
                       catch (std::exception& e) {
                         SLOG(g_log << Logger::Error << "Error in addSortList: " << e.what() << endl,
                              lci.d_slog->error(Logr::Error, e.what(), "Error in addSortList", "exception",  Logging::Loggable("std::exception")));
                       }
                     });

  Lua->writeFunction("addTA", [&lci](const std::string& who, const std::string& what) {
    warnIfDNSSECDisabled("Warning: adding Trust Anchor for DNSSEC (addTA), but dnssec is set to 'off'!");
    DNSName zone(who);
    auto ds = std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(what));
    lci.dsAnchors[zone].insert(*ds);
  });

  Lua->writeFunction("clearTA", [&lci](boost::optional<string> who) {
    warnIfDNSSECDisabled("Warning: removing Trust Anchor for DNSSEC (clearTA), but dnssec is set to 'off'!");
    if (who)
      lci.dsAnchors.erase(DNSName(*who));
    else
      lci.dsAnchors.clear();
  });

  /* Remove in 4.3 */
  Lua->writeFunction("addDS", [&lci](const std::string& who, const std::string& what) {
    warnIfDNSSECDisabled("Warning: adding Trust Anchor for DNSSEC (addDS), but dnssec is set to 'off'!");
    SLOG(g_log << Logger::Warning << "addDS is deprecated and will be removed in the future, switch to addTA" << endl,
         lci.d_slog->info(Logr::Warning, "addDS is deprecated and will be removed in the future, switch to addTA"));
    DNSName zone(who);
    auto ds = std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(what));
    lci.dsAnchors[zone].insert(*ds);
  });

  /* Remove in 4.3 */
  Lua->writeFunction("clearDS", [&lci](boost::optional<string> who) {
    SLOG(g_log << Logger::Warning << "clearDS is deprecated and will be removed in the future, switch to clearTA" << endl,
         lci.d_slog->info(Logr::Warning, "clearDS is deprecated and will be removed in the future, switch to clearTA"));
    warnIfDNSSECDisabled("Warning: removing Trust Anchor for DNSSEC (clearDS), but dnssec is set to 'off'!");
    if (who)
      lci.dsAnchors.erase(DNSName(*who));
    else
      lci.dsAnchors.clear();
  });

  Lua->writeFunction("addNTA", [&lci](const std::string& who, const boost::optional<std::string> why) {
    warnIfDNSSECDisabled("Warning: adding Negative Trust Anchor for DNSSEC (addNTA), but dnssec is set to 'off'!");
    if (why)
      lci.negAnchors[DNSName(who)] = static_cast<string>(*why);
    else
      lci.negAnchors[DNSName(who)] = "";
  });

  Lua->writeFunction("clearNTA", [&lci](boost::optional<string> who) {
    warnIfDNSSECDisabled("Warning: removing Negative Trust Anchor for DNSSEC (clearNTA), but dnssec is set to 'off'!");
    if (who)
      lci.negAnchors.erase(DNSName(*who));
    else
      lci.negAnchors.clear();
  });

  Lua->writeFunction("readTrustAnchorsFromFile", [&lci](const std::string& fnamearg, const boost::optional<uint32_t> interval) {
    uint32_t realInterval = 24;
    if (interval) {
      realInterval = static_cast<uint32_t>(*interval);
    }
    warnIfDNSSECDisabled("Warning: reading Trust Anchors from file (readTrustAnchorsFromFile), but dnssec is set to 'off'!");
    lci.trustAnchorFileInfo.fname = fnamearg;
    lci.trustAnchorFileInfo.interval = realInterval;
    updateTrustAnchorsFromFile(fnamearg, lci.dsAnchors, lci.d_slog);
  });

  Lua->writeFunction("setProtobufMasks", [&lci](const uint8_t maskV4, uint8_t maskV6) {
    lci.protobufMaskV4 = maskV4;
    lci.protobufMaskV6 = maskV6;
  });

  Lua->writeFunction("protobufServer", [&lci](boost::variant<const std::string, const std::unordered_map<int, std::string>> servers, boost::optional<protobufOptions_t> vars) {
    if (!lci.protobufExportConfig.enabled) {

      lci.protobufExportConfig.enabled = true;

      try {
        if (servers.type() == typeid(std::string)) {
          auto server = boost::get<const std::string>(servers);

          lci.protobufExportConfig.servers.emplace_back(server);
        }
        else {
          auto serversMap = boost::get<const std::unordered_map<int, std::string>>(servers);
          for (const auto& serverPair : serversMap) {
            lci.protobufExportConfig.servers.emplace_back(serverPair.second);
          }
        }

        parseProtobufOptions(vars, lci.protobufExportConfig);
      }
      catch (std::exception& e) {
        SLOG(g_log << Logger::Error << "Error while adding protobuf logger: " << e.what() << endl,
             lci.d_slog->error(Logr::Error, e.what(), "Exception  while adding protobuf logger", "exception", Logging::Loggable("std::exception")));
      }
      catch (PDNSException& e) {
        SLOG(g_log << Logger::Error << "Error while adding protobuf logger: " << e.reason << endl,
             lci.d_slog->error(Logr::Error, e.reason, "Exception  while adding protobuf logger", "exception", Logging::Loggable("PDNSException")));
      }
    }
    else {
      SLOG(g_log << Logger::Error << "Only one protobufServer() directive can be configured, we already have " << lci.protobufExportConfig.servers.at(0).toString() << endl,
           lci.d_slog->info(Logr::Error, "Only one protobufServer() directive can be configured", "existing", Logging::Loggable(lci.protobufExportConfig.servers.at(0).toString())));
    }
  });

  Lua->writeFunction("outgoingProtobufServer", [&lci](boost::variant<const std::string, const std::unordered_map<int, std::string>> servers, boost::optional<protobufOptions_t> vars) {
    if (!lci.outgoingProtobufExportConfig.enabled) {

      lci.outgoingProtobufExportConfig.enabled = true;

      try {
        if (servers.type() == typeid(std::string)) {
          auto server = boost::get<const std::string>(servers);

          lci.outgoingProtobufExportConfig.servers.emplace_back(server);
        }
        else {
          auto serversMap = boost::get<const std::unordered_map<int, std::string>>(servers);
          for (const auto& serverPair : serversMap) {
            lci.outgoingProtobufExportConfig.servers.emplace_back(serverPair.second);
          }
        }

        parseProtobufOptions(vars, lci.outgoingProtobufExportConfig);
      }
      catch (std::exception& e) {
        SLOG(g_log << Logger::Error << "Error while starting outgoing protobuf logger: " << e.what() << endl,
             lci.d_slog->error(Logr::Error, "Exception while starting outgoing protobuf logger", "exception", Logging::Loggable("std::exception")));
      }
      catch (PDNSException& e) {
        SLOG(g_log << Logger::Error << "Error while starting outgoing protobuf logger: " << e.reason << endl,
             lci.d_slog->error(Logr::Error, "Exception while starting outgoing protobuf logger", "exception", Logging::Loggable("PDNSException")));
      }
    }
    else {
      SLOG(g_log << Logger::Error << "Only one outgoingProtobufServer() directive can be configured, we already have " << lci.outgoingProtobufExportConfig.servers.at(0).toString() << endl,
           lci.d_slog->info(Logr::Error, "Only one outgoingProtobufServer() directive can be configured", "existing", Logging::Loggable(lci.outgoingProtobufExportConfig.servers.at(0).toString())));
    }
  });

#ifdef HAVE_FSTRM
  Lua->writeFunction("dnstapFrameStreamServer", [&lci](boost::variant<const std::string, const std::unordered_map<int, std::string>> servers, boost::optional<frameStreamOptions_t> vars) {
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
          auto serversMap = boost::get<const std::unordered_map<int, std::string>>(servers);
          for (const auto& serverPair : serversMap) {
            lci.frameStreamExportConfig.servers.emplace_back(serverPair.second);
          }
        }

        parseFrameStreamOptions(vars, lci.frameStreamExportConfig);
      }
      catch (std::exception& e) {
        SLOG(g_log << Logger::Error << "Error reading config for dnstap framestream logger: " << e.what() << endl,
              lci.d_slog->error(Logr::Error, "Exception reading config for dnstap framestream logger", "exception", Logging::Loggable("std::exception")));
      }
      catch (PDNSException& e) {
        SLOG(g_log << Logger::Error << "Error reading config for dnstap framestream logger: " << e.reason << endl,
             lci.d_slog->error(Logr::Error, "Exception reading config for dnstap framestream logger", "exception", Logging::Loggable("PDNSException")));
      }
    }
    else {
      SLOG(g_log << Logger::Error << "Only one dnstapFrameStreamServer() directive can be configured, we already have " << lci.frameStreamExportConfig.servers.at(0) << endl,
           lci.d_slog->info(Logr::Error,  "Only one dnstapFrameStreamServer() directive can be configured",  "existing", Logging::Loggable(lci.frameStreamExportConfig.servers.at(0))));
    }
  });
  Lua->writeFunction("dnstapNODFrameStreamServer", [&lci](boost::variant<const std::string, const std::unordered_map<int, std::string>> servers, boost::optional<frameStreamOptions_t> vars) {
    if (!lci.nodFrameStreamExportConfig.enabled) {
      lci.nodFrameStreamExportConfig.enabled = true;

      try {
        if (servers.type() == typeid(std::string)) {
          auto server = boost::get<const std::string>(servers);
          if (!boost::starts_with(server, "/")) {
            ComboAddress parsecheck(server);
          }
          lci.nodFrameStreamExportConfig.servers.emplace_back(server);
        }
        else {
          auto serversMap = boost::get<const std::unordered_map<int, std::string>>(servers);
          for (const auto& serverPair : serversMap) {
            lci.nodFrameStreamExportConfig.servers.emplace_back(serverPair.second);
          }
        }

        parseFrameStreamOptions(vars, lci.nodFrameStreamExportConfig);
      }
      catch (std::exception& e) {
        SLOG(g_log << Logger::Error << "Error reading config for dnstap NOD framestream logger: " << e.what() << endl,
              lci.d_slog->error(Logr::Error, "Exception reading config for dnstap NOD framestream logger", "exception", Logging::Loggable("std::exception")));
      }
      catch (PDNSException& e) {
        SLOG(g_log << Logger::Error << "Error reading config for dnstap NOD framestream logger: " << e.reason << endl,
             lci.d_slog->error(Logr::Error, "Exception reading config for dnstap NOD framestream logger", "exception", Logging::Loggable("PDNSException")));
      }
    }
    else {
      SLOG(g_log << Logger::Error << "Only one dnstapNODFrameStreamServer() directive can be configured, we already have " << lci.nodFrameStreamExportConfig.servers.at(0) << endl,
           lci.d_slog->info(Logr::Error,  "Only one dnstapNODFrameStreamServer() directive can be configured",  "existing", Logging::Loggable(lci.nodFrameStreamExportConfig.servers.at(0))));
    }
  });
#endif /* HAVE_FSTRM */

  Lua->writeFunction("addAllowedAdditionalQType", [&lci](int qtype, std::unordered_map<int, int> targetqtypes, boost::optional<std::map<std::string, int>> options) {
    switch (qtype) {
    case QType::MX:
    case QType::SRV:
    case QType::SVCB:
    case QType::HTTPS:
    case QType::NAPTR:
      break;
    default:
      SLOG(g_log << Logger::Error << "addAllowedAdditionalQType does not support " << QType(qtype).toString() << endl,
           lci.d_slog->info(Logr::Error, "addAllowedAdditionalQType does not support this qtype", "qtype", Logging::Loggable(QType(qtype).toString())));
      return;
    }

    std::set<QType> targets;
    for (const auto& t : targetqtypes) {
      targets.emplace(QType(t.second));
    }

    AdditionalMode mode = AdditionalMode::CacheOnlyRequireAuth; // Always cheap and should be safe

    if (options) {
      if (const auto it = options->find("mode"); it != options->end()) {
        mode = static_cast<AdditionalMode>(it->second);
        if (mode > AdditionalMode::ResolveDeferred) {
          SLOG(g_log << Logger::Error << "addAllowedAdditionalQType: unknown mode " << it->second << endl,
               lci.d_slog->info(Logr::Error, "addAllowedAdditionalQType: unknown mode", "mode", Logging::Loggable( it->second)));
        }
      }
    }
    lci.allowAdditionalQTypes.insert_or_assign(qtype, pair(targets, mode));
  });

  Lua->writeFunction("addProxyMapping", [&proxyMapping,&lci](const string& netmaskArg, const string& addressArg, boost::optional<std::vector<pair<int,std::string>>> smnStrings) {
    try {
      Netmask netmask(netmaskArg);
      ComboAddress address(addressArg);
      boost::optional<SuffixMatchNode> smn;
      if (smnStrings) {
        smn = boost::make_optional(SuffixMatchNode{});
        for (const auto& el : *smnStrings) {
          smn->add(el.second);
        }
      }
      proxyMapping.insert_or_assign(netmask, {address, smn});
    }
    catch (std::exception& e) {
      SLOG(g_log << Logger::Error << "Error processing addProxyMapping: " << e.what() << endl,
           lci.d_slog->error(Logr::Error, e.what(), "Exception processing addProxyMapping", "exception", Logging::Loggable("std::exception")));
    }
    catch (PDNSException& e) {
      SLOG(g_log << Logger::Error << "Error processing addProxyMapping: " << e.reason << endl,
           lci.d_slog->error(Logr::Error, e.reason, "Exception processing addProxyMapping", "exception", Logging::Loggable("PDNSException")));
    }
  });

  try {
    Lua->executeCode(ifs);
    g_luaconfs.setState(std::move(lci));
  }
  catch (const LuaContext::ExecutionErrorException& e) {
    SLOG(g_log << Logger::Error << "Unable to load Lua script from '" + fname + "': ",
         lci.d_slog->error(Logr::Error, e.what(),  "Unable to load Lua script", "file", Logging::Loggable(fname)));
    try {
      std::rethrow_if_nested(e);
    }
    catch (const std::exception& exp) {
      // exp is the exception that was thrown from inside the lambda
      SLOG(g_log << exp.what() << std::endl,
           lci.d_slog->error(Logr::Error, exp.what(), "Exception loading Lua", "exception", Logging::Loggable("std::exception")));
    }
    catch (const PDNSException& exp) {
      // exp is the exception that was thrown from inside the lambda
      SLOG(g_log << exp.reason << std::endl,
           lci.d_slog->error(Logr::Error, exp.reason, "Exception loading Lua", "exception", Logging::Loggable("PDNSException")))    }
    throw;
  }
  catch (std::exception& err) {
    SLOG(g_log << Logger::Error << "Unable to load Lua script from '" + fname + "': " << err.what() << endl,
         lci.d_slog->error(Logr::Error, err.what(),  "Unable to load Lua script", "file", Logging::Loggable(fname), "exception", Logging::Loggable("std::exception")));
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
    catch (const std::exception& e) {
      SLOG(g_log << Logger::Error << "Problem starting RPZIXFRTracker thread: " << e.what() << endl,
           g_slog->withName("rpz")->error(Logr::Error, e.what(), "Exception startng RPZIXFRTracker thread", "exception", Logging::Loggable("std::exception")));
      exit(1);
    }
    catch (const PDNSException& e) {
      SLOG(g_log << Logger::Error << "Problem starting RPZIXFRTracker thread: " << e.reason << endl,
           g_slog->withName("rpz")->error(Logr::Error, e.reason, "Exception startng RPZIXFRTracker thread", "exception", Logging::Loggable("PDNSException")));
      exit(1);
    }
  }
}
