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


static void parseRPZParameters(const std::unordered_map<string,boost::variant<uint32_t, string> >& have, std::string& polName, boost::optional<DNSFilterEngine::Policy>& defpol, uint32_t& maxTTL, size_t& zoneSizeHint)
{
  if(have.count("policyName")) {
    polName = boost::get<std::string>(constGet(have, "policyName"));
  }
  if(have.count("defpol")) {
    defpol=DNSFilterEngine::Policy();
    defpol->d_kind = (DNSFilterEngine::PolicyKind)boost::get<uint32_t>(constGet(have, "defpol"));
    defpol->d_name = std::make_shared<std::string>(polName);
    if(defpol->d_kind == DNSFilterEngine::PolicyKind::Custom) {
      defpol->d_custom=
          DNSRecordContent::mastermake(QType::CNAME, 1,
                                       boost::get<string>(constGet(have,"defcontent"))
            );

      if(have.count("defttl"))
        defpol->d_ttl = static_cast<int32_t>(boost::get<uint32_t>(constGet(have, "defttl")));
      else
        defpol->d_ttl = -1; // get it from the zone
    }
  }
  if(have.count("maxTTL")) {
    maxTTL = boost::get<uint32_t>(constGet(have, "maxTTL"));
  }
  if(have.count("zoneSizeHint")) {
    zoneSizeHint = static_cast<size_t>(boost::get<uint32_t>(constGet(have, "zoneSizeHint")));
  }
}

void loadRecursorLuaConfig(const std::string& fname, bool checkOnly)
{
  LuaConfigItems lci;

  LuaContext Lua;
  if(fname.empty())
    return;
  ifstream ifs(fname);
  if(!ifs)
    throw PDNSException("Cannot open file '"+fname+"': "+strerror(errno));

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

  Lua.writeFunction("rpzFile", [&lci](const string& filename, const boost::optional<std::unordered_map<string,boost::variant<uint32_t, string>>>& options) {
      try {
        boost::optional<DNSFilterEngine::Policy> defpol;
        std::string polName("rpzFile");
        std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
        uint32_t maxTTL = std::numeric_limits<uint32_t>::max();
        if(options) {
          auto& have = *options;
          size_t zoneSizeHint = 0;
          parseRPZParameters(have, polName, defpol, maxTTL, zoneSizeHint);
          if (zoneSizeHint > 0) {
            zone->reserve(zoneSizeHint);
          }
        }
        theL()<<Logger::Warning<<"Loading RPZ from file '"<<filename<<"'"<<endl;
        zone->setName(polName);
        loadRPZFromFile(filename, zone, defpol, maxTTL);
        lci.dfe.addZone(zone);
        theL()<<Logger::Warning<<"Done loading RPZ from file '"<<filename<<"'"<<endl;
      }
      catch(const std::exception& e) {
        theL()<<Logger::Error<<"Unable to load RPZ zone from '"<<filename<<"': "<<e.what()<<endl;
      }
    });

  Lua.writeFunction("rpzMaster", [&lci, checkOnly](const string& master_, const string& zoneName, const boost::optional<std::unordered_map<string,boost::variant<uint32_t, string>>>& options) {
      try {
        boost::optional<DNSFilterEngine::Policy> defpol;
        std::shared_ptr<DNSFilterEngine::Zone> zone = std::make_shared<DNSFilterEngine::Zone>();
        TSIGTriplet tt;
        uint32_t refresh=0;
        std::string polName(zoneName);
        size_t maxReceivedXFRMBytes = 0;
        uint32_t maxTTL = std::numeric_limits<uint32_t>::max();
        ComboAddress localAddress;
        if(options) {
          auto& have = *options;
          size_t zoneSizeHint = 0;
          parseRPZParameters(have, polName, defpol, maxTTL, zoneSizeHint);
          if (zoneSizeHint > 0) {
            zone->reserve(zoneSizeHint);
          }
          if(have.count("tsigname")) {
            tt.name=DNSName(toLower(boost::get<string>(constGet(have, "tsigname"))));
            tt.algo=DNSName(toLower(boost::get<string>(constGet(have, "tsigalgo"))));
            if(B64Decode(boost::get<string>(constGet(have, "tsigsecret")), tt.secret))
              throw std::runtime_error("TSIG secret is not valid Base-64 encoded");
          }
          if(have.count("refresh")) {
            refresh = boost::get<uint32_t>(constGet(have,"refresh"));
          }
          if(have.count("maxReceivedMBytes")) {
            maxReceivedXFRMBytes = static_cast<size_t>(boost::get<uint32_t>(constGet(have,"maxReceivedMBytes")));
          }
          if(have.count("localAddress")) {
            localAddress = ComboAddress(boost::get<string>(constGet(have,"localAddress")));
          }
        }
        ComboAddress master(master_, 53);
        if (localAddress != ComboAddress() && localAddress.sin4.sin_family != master.sin4.sin_family) {
          // We were passed a localAddress, check if its AF matches the master's
          throw PDNSException("Master address("+master.toString()+") is not of the same Address Family as the local address ("+localAddress.toString()+").");
        }

        DNSName domain(zoneName);
        zone->setDomain(domain);
        zone->setName(polName);
        zone->setRefresh(refresh);
        size_t zoneIdx = lci.dfe.addZone(zone);

        if (!checkOnly) {
          auto sr=loadRPZFromServer(master, domain, zone, defpol, maxTTL, tt, maxReceivedXFRMBytes * 1024 * 1024, localAddress);
          if(refresh)
            sr->d_st.refresh=refresh;
          zone->setSerial(sr->d_st.serial);

          std::thread t(RPZIXFRTracker, master, DNSName(zoneName), defpol, maxTTL, zoneIdx, tt, sr, maxReceivedXFRMBytes * 1024 * 1024, localAddress);
          t.detach();
        }
      }
      catch(const std::exception& e) {
        theL()<<Logger::Error<<"Unable to load RPZ zone '"<<zoneName<<"' from '"<<master_<<"': "<<e.what()<<endl;
      }
      catch(const PDNSException& e) {
        theL()<<Logger::Error<<"Unable to load RPZ zone '"<<zoneName<<"' from '"<<master_<<"': "<<e.reason<<endl;
      }

    });

  typedef vector<pair<int,boost::variant<string, vector<pair<int, string> > > > > argvec_t;
  Lua.writeFunction("addSortList", 
		    [&lci](const std::string& formask_, 
		       const boost::variant<string, argvec_t>& masks,
		       boost::optional<int> order_) 
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
			theL()<<Logger::Error<<"Error in addSortList: "<<e.what()<<endl;
		      }
		    });

  Lua.writeFunction("addDS", [&lci](const std::string& who, const std::string& what) {
      warnIfDNSSECDisabled("Warning: adding Trust Anchor for DNSSEC (addDS), but dnssec is set to 'off'!");
      DNSName zone(who);
      auto ds=std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(what));
      lci.dsAnchors[zone].insert(*ds);
  });

  Lua.writeFunction("clearDS", [&lci](boost::optional<string> who) {
      warnIfDNSSECDisabled("Warning: removing Trust Anchor for DNSSEC (clearDS), but dnssec is set to 'off'!");
      if(who)
        lci.dsAnchors.erase(DNSName(*who));
      else
        lci.dsAnchors.clear();
    });

  Lua.writeFunction("addNTA", [&lci](const std::string& who, const boost::optional<std::string> why) {
      warnIfDNSSECDisabled("Warning: adding Negative Trust Anchor for DNSSEC (addNTA), but dnssec is set to 'off'!");
      if(why)
        lci.negAnchors[DNSName(who)] = static_cast<string>(*why);
      else
        lci.negAnchors[DNSName(who)] = "";
    });

  Lua.writeFunction("clearNTA", [&lci](boost::optional<string> who) {
      warnIfDNSSECDisabled("Warning: removing Negative Trust Anchor for DNSSEC (clearNTA), but dnssec is set to 'off'!");
      if(who)
        lci.negAnchors.erase(DNSName(*who));
      else
        lci.negAnchors.clear();
    });

#if HAVE_PROTOBUF
  Lua.writeFunction("protobufServer", [&lci, checkOnly](const string& server_, const boost::optional<uint16_t> timeout, const boost::optional<uint64_t> maxQueuedEntries, const boost::optional<uint8_t> reconnectWaitTime, const boost::optional<uint8_t> maskV4, boost::optional<uint8_t> maskV6, boost::optional<bool> asyncConnect, boost::optional<bool> taggedOnly) {
      try {
	ComboAddress server(server_);
        if (!lci.protobufServer) {
          if (!checkOnly) {
            lci.protobufServer = std::make_shared<RemoteLogger>(server, timeout ? *timeout : 2, maxQueuedEntries ? *maxQueuedEntries : 100, reconnectWaitTime ? *reconnectWaitTime : 1, asyncConnect ? *asyncConnect : false);
          }

          if (maskV4) {
            lci.protobufMaskV4 = *maskV4;
          }
          if (maskV6) {
            lci.protobufMaskV6 = *maskV6;
          }
          if (taggedOnly) {
            lci.protobufTaggedOnly = *taggedOnly;
          }
        }
        else {
          theL()<<Logger::Error<<"Only one protobuf server can be configured, we already have "<<lci.protobufServer->toString()<<endl;
        }
      }
      catch(std::exception& e) {
	theL()<<Logger::Error<<"Error while starting protobuf logger to '"<<server_<<": "<<e.what()<<endl;
      }
      catch(PDNSException& e) {
        theL()<<Logger::Error<<"Error while starting protobuf logger to '"<<server_<<": "<<e.reason<<endl;
      }
    });

  Lua.writeFunction("outgoingProtobufServer", [&lci, checkOnly](const string& server_, const boost::optional<uint16_t> timeout, const boost::optional<uint64_t> maxQueuedEntries, const boost::optional<uint8_t> reconnectWaitTime, boost::optional<bool> asyncConnect) {
      try {
	ComboAddress server(server_);
        if (!lci.outgoingProtobufServer) {
          if (!checkOnly) {
            lci.outgoingProtobufServer = std::make_shared<RemoteLogger>(server, timeout ? *timeout : 2, maxQueuedEntries ? *maxQueuedEntries : 100, reconnectWaitTime ? *reconnectWaitTime : 1, asyncConnect ? *asyncConnect : false);
          }
        }
        else {
          theL()<<Logger::Error<<"Only one protobuf server can be configured, we already have "<<lci.protobufServer->toString()<<endl;
        }
      }
      catch(std::exception& e) {
	theL()<<Logger::Error<<"Error while starting protobuf logger to '"<<server_<<": "<<e.what()<<endl;
      }
      catch(PDNSException& e) {
        theL()<<Logger::Error<<"Error while starting protobuf logger to '"<<server_<<": "<<e.reason<<endl;
      }
    });
#endif

  try {
    Lua.executeCode(ifs);
    g_luaconfs.setState(lci);
  }
  catch(const LuaContext::ExecutionErrorException& e) {
    theL()<<Logger::Error<<"Unable to load Lua script from '"+fname+"': ";
    try {
      std::rethrow_if_nested(e);
    } catch(const std::exception& exp) {
      // exp is the exception that was thrown from inside the lambda
      theL() << exp.what() << std::endl;
    }
    catch(const PDNSException& exp) {
      // exp is the exception that was thrown from inside the lambda
      theL() << exp.reason << std::endl;
    }
    throw;

  }
  catch(std::exception& err) {
    theL()<<Logger::Error<<"Unable to load Lua script from '"+fname+"': "<<err.what()<<endl;
    throw;
  }

}

