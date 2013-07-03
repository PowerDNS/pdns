#include "remotebackend.hh"
#include <boost/foreach.hpp>

static const char *kBackendId = "[RemoteBackend]";

/**
 * Forwarder for value. This is just in case
 * we need to do some treatment to the value before
 * sending it downwards.
 */
bool Connector::send(rapidjson::Document &value) {
    return send_message(value);
}

/** 
 * Helper for handling receiving of data.
 * Basically what happens here is that we check 
 * that the receiving happened ok, and extract
 * result. Logging is performed here, too. 
 */
bool Connector::recv(rapidjson::Document &value) {
    if (recv_message(value)>0) {
       bool rv = true;
       // check for error
       if (!value.HasMember("result")) {
          return false;
       }
       if (!value["result"].IsObject() && getBool(value["result"]) == false) {
           rv = false;
        }
        if (value.HasMember("log")) {
           rapidjson::Value& messages = value["log"];
           if (messages.IsArray()) {
              // log em all
              for (rapidjson::Value::ValueIterator iter = messages.Begin(); iter != messages.End(); ++iter)
                 L<<Logger::Info<<"[remotebackend]:"<< getString(*iter) <<std::endl;
           } else if (messages.IsNull() == false) { // could be just a value
               L<<Logger::Info<<"[remotebackend]:"<< getString(messages) <<std::endl;
           }
        }
        return rv;
    }
    return false;
}

/** 
 * Standard ctor and dtor
 */
RemoteBackend::RemoteBackend(const std::string &suffix)
{
      setArgPrefix("remote"+suffix);
      build(getArg("connection-string"));
      this->d_result = NULL;
      this->d_dnssec = mustDo("dnssec");
      this->d_index = -1;
      this->d_trxid = 0;
}

RemoteBackend::~RemoteBackend() {
     if (connector != NULL) {
 	delete connector;
     }
}

/** 
 * Builds connector based on options
 * Currently supports unix,pipe and http
 */
int RemoteBackend::build(const std::string &connstr) {
      std::vector<std::string> parts;
      std::string type;
      std::string opts;
      std::map<std::string, std::string> options;

      // connstr is of format "type:options"
      size_t pos;
      pos = connstr.find_first_of(":");
      if (pos == std::string::npos)
         throw AhuException("Invalid connection string: malformed");

      type = connstr.substr(0, pos);
      opts = connstr.substr(pos+1);

      // tokenize the string on comma
      stringtok(parts, opts, ",");

      // find out some options and parse them while we're at it
      BOOST_FOREACH(std::string opt, parts) {
          std::string key,val;
          // make sure there is something else than air in the option...
          if (opt.find_first_not_of(" ") == std::string::npos) continue;

          // split it on '='. if not found, we treat it as "yes"
          pos = opt.find_first_of("=");

          if (pos == std::string::npos) {
             key = opt;
             val = "yes";
          } else {
             key = opt.substr(0,pos);
             val = opt.substr(pos+1);
          }
          options[key] = val;
      }

      // connectors know what they are doing
      if (type == "unix") {
        this->connector = new UnixsocketConnector(options);
      } else if (type == "http") {
#ifdef REMOTEBACKEND_HTTP
        this->connector = new HTTPConnector(options);
#else
	throw AhuException("Invalid connection string: http connector support not enabled. Recompile with --enable-remotebackend-http");
#endif
      } else if (type == "pipe") {
        this->connector = new PipeConnector(options);
      } else {
        throw AhuException("Invalid connection string: unknown connector");
      }

      return -1;
}

/** 
 * The functions here are just remote json stubs that send and receive the method call
 * data is mainly left alone, some defaults are assumed. 
 */
void RemoteBackend::lookup(const QType &qtype, const std::string &qdomain, DNSPacket *pkt_p, int zoneId) {
   rapidjson::Document query;
   rapidjson::Value parameters;

   if (d_index != -1) 
      throw AhuException("Attempt to lookup while one running");

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "lookup", query.GetAllocator())
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "qtype", qtype.getName().c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "qname", qdomain.c_str(), query.GetAllocator());

   string localIP="0.0.0.0";
   string remoteIP="0.0.0.0";
   string realRemote="0.0.0.0/0";
   if (pkt_p) {
     localIP=pkt_p->getLocal();
     realRemote = pkt_p->getRealRemote().toString();
     remoteIP = pkt_p->getRemote();
   }

   JSON_ADD_MEMBER(parameters, "remote", remoteIP.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "local", localIP.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "real-remote", realRemote.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "zone-id", zoneId, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   d_result = new rapidjson::Document();

   if (connector->send(query) == false || connector->recv(*d_result) == false) { 
      delete d_result;
      return;
   }

   // OK. we have result parameters in result
   if ((*d_result)["result"].IsArray() == false) {
      delete d_result;
      return;
   }

   d_index = 0;
}

bool RemoteBackend::list(const std::string &target, int domain_id) {
   rapidjson::Document query;
   rapidjson::Value parameters;

   if (d_index != -1)
      throw AhuException("Attempt to lookup while one running");

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "list", query.GetAllocator());
   query["method"] = "list";
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "zonename", target.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "domain-id", domain_id, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   d_result = new rapidjson::Document();

   if (connector->send(query) == false || connector->recv(*d_result) == false) {
     delete d_result;
     return false;
   }
   if ((*d_result)["result"].IsArray() == false) {
      delete d_result;
      return false;
   }

   d_index = 0;
   return true;
}

bool RemoteBackend::get(DNSResourceRecord &rr) {
   if (d_index == -1) return false;
   rapidjson::Value value;

   value = "";
   rr.qtype = getString(JSON_GET((*d_result)["result"][d_index], "qtype", value));
   rr.qname = getString(JSON_GET((*d_result)["result"][d_index], "qname", value));
   rr.qclass = QClass::IN;
   rr.content = getString(JSON_GET((*d_result)["result"][d_index], "content",value));
   value = -1;
   rr.ttl = getInt(JSON_GET((*d_result)["result"][d_index], "ttl",value));
   rr.domain_id = getInt(JSON_GET((*d_result)["result"][d_index],"domain_id",value));
   rr.priority = getInt(JSON_GET((*d_result)["result"][d_index],"priority",value));
   value = 1;
   if (d_dnssec) 
     rr.auth = getInt(JSON_GET((*d_result)["result"][d_index],"auth", value));
   else
     rr.auth = 1;
   value = 0;
   rr.scopeMask = getInt(JSON_GET((*d_result)["result"][d_index],"scopeMask", value));

   d_index++;
   
   // id index is out of bounds, we know the results end here. 
   if (d_index == static_cast<int>((*d_result)["result"].Size())) {
     delete d_result;
     d_result = NULL;
     d_index = -1;
   }
   return true;
}

bool RemoteBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;
   // no point doing dnssec if it's not supported
   if (d_dnssec == false) return false;

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "getBeforeAndAfterNamesAbsolute", query.GetAllocator());
   
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "id", id, query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "qname", qname.c_str(), query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   unhashed = getString(answer["result"]["unhashed"]);
   before = getString(answer["result"]["before"]);
   after = getString(answer["result"]["after"]);
  
   return true;
}

bool RemoteBackend::getDomainMetadata(const std::string& name, const std::string& kind, std::vector<std::string>& meta) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "getDomainMetadata", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "name", name.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "kind", kind.c_str(), query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false)
     return false;

   meta.clear();

   // not mandatory to implement
   if (connector->recv(answer) == false)
     return true;

   if (answer["result"].IsArray()) {
      for(rapidjson::Value::ValueIterator iter = answer["result"].Begin(); iter != answer["result"].End(); iter++) {
         meta.push_back(getString(*iter));
      }
   } else if (answer["result"].IsString()) {
      meta.push_back(answer["result"].GetString());
   }

   return true;
}

bool RemoteBackend::setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters,val;
   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "setDomainMetadata", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "name", name.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "kind", kind.c_str(), query.GetAllocator());
   val.SetArray();
   BOOST_FOREACH(std::string value, meta) {
     val.PushBack(value.c_str(), query.GetAllocator());
   }
   parameters.AddMember("value", val, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   return getBool(answer["result"]);
}


bool RemoteBackend::getDomainKeys(const std::string& name, unsigned int kind, std::vector<DNSBackend::KeyData>& keys) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;
   // no point doing dnssec if it's not supported
   if (d_dnssec == false) return false;

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "getDomainKeys", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "name", name.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "kind", kind, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   keys.clear();

   for(rapidjson::Value::ValueIterator iter = answer["result"].Begin(); iter != answer["result"].End(); iter++) {
      DNSBackend::KeyData key;
      key.id = getUInt((*iter)["id"]);
      key.flags = getUInt((*iter)["flags"]);
      key.active = getBool((*iter)["active"]);
      key.content = getString((*iter)["content"]);
      keys.push_back(key);
   }

   return true;
}

bool RemoteBackend::removeDomainKey(const string& name, unsigned int id) { 
   rapidjson::Document query,answer;
   rapidjson::Value parameters;
   // no point doing dnssec if it's not supported
   if (d_dnssec == false) return false;

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "removeDomainKey", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "name", name.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "id", id, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   return true;
}

int RemoteBackend::addDomainKey(const string& name, const KeyData& key) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters,jkey;

   // no point doing dnssec if it's not supported
   if (d_dnssec == false) return false;
   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "addDomainKey", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "name", name.c_str(), query.GetAllocator());
   jkey.SetObject();
   JSON_ADD_MEMBER(jkey, "flags", key.flags, query.GetAllocator());
   JSON_ADD_MEMBER(jkey, "active", key.active, query.GetAllocator());
   JSON_ADD_MEMBER(jkey, "content", key.content.c_str(), query.GetAllocator());
   parameters.AddMember("key", jkey, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   return getInt(answer["result"]);
}

bool RemoteBackend::activateDomainKey(const string& name, unsigned int id) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;

   // no point doing dnssec if it's not supported
   if (d_dnssec == false) return false;

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "activateDomainKey", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "name", name.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "id", id, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   return true;
}

bool RemoteBackend::deactivateDomainKey(const string& name, unsigned int id) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;

   // no point doing dnssec if it's not supported
   if (d_dnssec == false) return false;

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "deactivateDomainKey", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "name", name.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "id", id, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   return true;
}

bool RemoteBackend::doesDNSSEC() {
   return d_dnssec;
}

bool RemoteBackend::getTSIGKey(const std::string& name, std::string* algorithm, std::string* content) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;

   // no point doing dnssec if it's not supported
   if (d_dnssec == false) return false;
   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "getTSIGKey", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "name", name.c_str(), query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   if (algorithm != NULL)
     algorithm->assign(getString(answer["result"]["algorithm"]));
   if (content != NULL)
     content->assign(getString(answer["result"]["content"]));
   
   return true;
}

bool RemoteBackend::getDomainInfo(const string &domain, DomainInfo &di) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;
   rapidjson::Value value;
   std::string kind;

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "getDomainInfo", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "name", domain.c_str(), query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   // make sure we got zone & kind
   if (!answer["result"].HasMember("zone")) {
      L<<Logger::Error<<kBackendId<<"Missing zone in getDomainInfo return value"<<endl;
      throw AhuException();
   }
   value = -1;
   // parse return value. we need at least zone,serial,kind
   di.id = getInt(JSON_GET(answer["result"],"id",value));
   di.zone = getString(answer["result"]["zone"]);

   if (answer["result"].HasMember("masters") && answer["result"]["masters"].IsArray()) {
     rapidjson::Value& value = answer["result"]["masters"];
     for(rapidjson::Value::ValueIterator i = value.Begin(); i != value.End(); i++) {
        di.masters.push_back(getString(*i));
     }
   }
   di.notified_serial = getInt(JSON_GET(answer["result"], "notified_serial", value));
   value = 0;
   di.serial = getInt(JSON_GET(answer["result"],"serial", value));
   di.last_check = getInt(JSON_GET(answer["result"],"last_check", value));
   value = "native";
   kind = getString(JSON_GET(answer["result"], "kind", value));
   if (kind == "master") {
      di.kind = DomainInfo::Master;
   } else if (kind == "slave") {
      di.kind = DomainInfo::Slave;
   } else {
      di.kind = DomainInfo::Native;
   }
   di.backend = this;
   return true;
}

void RemoteBackend::setNotified(uint32_t id, uint32_t serial) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;
  
   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "setNotified", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "id", id, query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "serial", serial, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());
 
   if (connector->send(query) == false || connector->recv(answer) == false) {
      L<<Logger::Error<<kBackendId<<"Failed to execute RPC for RemoteBackend::setNotified("<<id<<","<<serial<<")"<<endl;
   }
}

bool RemoteBackend::superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *account, DNSBackend **ddb) 
{
   rapidjson::Document query,answer;
   rapidjson::Value parameters;
   rapidjson::Value rrset;

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "superMasterBackend", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "ip", ip.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "domain", domain.c_str(), query.GetAllocator());
   rrset.SetArray();
   rrset.Reserve(nsset.size(), query.GetAllocator());
   for(rapidjson::SizeType i = 0; i < nsset.size(); i++) {
      rapidjson::Value rr;
      rr.SetObject();
      JSON_ADD_MEMBER(rr, "qtype", nsset[i].qtype.getName().c_str(), query.GetAllocator());
      JSON_ADD_MEMBER(rr, "qname", nsset[i].qname.c_str(), query.GetAllocator());
      JSON_ADD_MEMBER(rr, "qclass", QClass::IN, query.GetAllocator());
      JSON_ADD_MEMBER(rr, "content", nsset[i].content.c_str(), query.GetAllocator());
      JSON_ADD_MEMBER(rr, "ttl", nsset[i].ttl, query.GetAllocator());
      JSON_ADD_MEMBER(rr, "priority", nsset[i].priority, query.GetAllocator());
      JSON_ADD_MEMBER(rr, "auth", nsset[i].auth, query.GetAllocator());
      rrset.PushBack(rr, query.GetAllocator());
   }
   parameters.AddMember("nsset", rrset, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   *ddb = 0;

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   // we are the backend
   *ddb = this;
   
   // we allow simple true as well...
   if (answer["result"].IsObject() && answer["result"].HasMember("account")) 
     *account = getString(answer["result"]["account"]);

   return true;
}

bool RemoteBackend::createSlaveDomain(const string &ip, const string &domain, const string &account) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;
   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "createSlaveDomain", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "ip", ip.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "domain", domain.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "account", account.c_str(), query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;
   return true;
}

bool RemoteBackend::replaceRRSet(uint32_t domain_id, const string& qname, const QType& qtype, const vector<DNSResourceRecord>& rrset) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;
   rapidjson::Value rj_rrset;
   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "replaceRRSet", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "domain_id", domain_id, query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "qname", qname.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "qtype", qtype.getName().c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "trxid", d_trxid, query.GetAllocator());

   rj_rrset.SetArray();
   rj_rrset.Reserve(rrset.size(), query.GetAllocator());

   for(rapidjson::SizeType i = 0; i < rrset.size(); i++) {
      rapidjson::Value rr;
      rr.SetObject();
      JSON_ADD_MEMBER(rr, "qtype", rrset[i].qtype.getName().c_str(), query.GetAllocator());
      JSON_ADD_MEMBER(rr, "qname", rrset[i].qname.c_str(), query.GetAllocator());
      JSON_ADD_MEMBER(rr, "qclass", QClass::IN, query.GetAllocator());
      JSON_ADD_MEMBER(rr, "content", rrset[i].content.c_str(), query.GetAllocator());
      JSON_ADD_MEMBER(rr, "ttl", rrset[i].ttl, query.GetAllocator());
      JSON_ADD_MEMBER(rr, "priority", rrset[i].priority, query.GetAllocator());
      JSON_ADD_MEMBER(rr, "auth", rrset[i].auth, query.GetAllocator());
      rj_rrset.PushBack(rr, query.GetAllocator());
   }
   parameters.AddMember("rrset", rj_rrset, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   return true;
}

bool RemoteBackend::feedRecord(const DNSResourceRecord &rr, string *ordername) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters,rj_rr;
   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "feedRecord", query.GetAllocator());
   parameters.SetObject();
   rj_rr.SetObject();
   JSON_ADD_MEMBER(rj_rr, "qtype", rr.qtype.getName().c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(rj_rr, "qname", rr.qname.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(rj_rr, "qclass", QClass::IN, query.GetAllocator());
   JSON_ADD_MEMBER(rj_rr, "content", rr.content.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(rj_rr, "ttl", rr.ttl, query.GetAllocator());
   JSON_ADD_MEMBER(rj_rr, "priority", rr.priority, query.GetAllocator());
   JSON_ADD_MEMBER(rj_rr, "auth", rr.auth, query.GetAllocator());
   parameters.AddMember("rr", rj_rr, query.GetAllocator());

   JSON_ADD_MEMBER(parameters, "trxid", d_trxid, query.GetAllocator());

   if (ordername) {
     JSON_ADD_MEMBER(parameters, "ordername", ordername->c_str(), query.GetAllocator());
   }

   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;
   return true; // XXX FIXME this API should not return 'true' I think -ahu
}

bool RemoteBackend::feedEnts(int domain_id, set<string>& nonterm) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;
   rapidjson::Value nts;
   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "feedEnts", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "domain_id", domain_id, query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "trxid", d_trxid, query.GetAllocator());
   nts.SetArray();
   BOOST_FOREACH(const string &t, nonterm) {
      nts.PushBack(t.c_str(), query.GetAllocator());
   }
   parameters.AddMember("nonterm", nts, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;
   return true; 
}

bool RemoteBackend::feedEnts3(int domain_id, const string &domain, set<string> &nonterm, unsigned int times, const string &salt, bool narrow) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;
   rapidjson::Value nts;
   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "feedEnts3", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "domain_id", domain_id, query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "domain", domain.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "times", times, query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "salt", salt.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "narrow", narrow, query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "trxid", d_trxid, query.GetAllocator());

   nts.SetArray();
   BOOST_FOREACH(const string &t, nonterm) {
      nts.PushBack(t.c_str(), query.GetAllocator());
   }
   parameters.AddMember("nonterm", nts, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;
   return true;
}

bool RemoteBackend::startTransaction(const string &domain, int domain_id) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;
   this->d_trxid = time((time_t*)NULL);

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "startTransaction", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "domain", domain.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "domain_id", domain_id, query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "trxid", d_trxid, query.GetAllocator());

   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false) {
     d_trxid = -1;
     return false;
   }
   return true;

}
bool RemoteBackend::commitTransaction() { 
   rapidjson::Document query,answer;
   rapidjson::Value parameters;

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "abortTransaction", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "trxid", d_trxid, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   d_trxid = -1;
   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;
   return true;
}

bool RemoteBackend::abortTransaction() { 
   rapidjson::Document query,answer;
   rapidjson::Value parameters;

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "commitTransaction", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "trxid", d_trxid, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   d_trxid = -1;
   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;
   return true;
}

bool RemoteBackend::calculateSOASerial(const string& domain, const SOAData& sd, time_t& serial) {
   rapidjson::Document query,answer;
   rapidjson::Value parameters;
   rapidjson::Value soadata;

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "calculateSOASerial", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "domain", domain.c_str(), query.GetAllocator());
   soadata.SetObject();
   JSON_ADD_MEMBER(soadata, "qname", sd.qname.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(soadata, "nameserver", sd.nameserver.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(soadata, "hostmaster", sd.hostmaster.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(soadata, "ttl", sd.ttl, query.GetAllocator());
   JSON_ADD_MEMBER(soadata, "serial", sd.serial, query.GetAllocator());
   JSON_ADD_MEMBER(soadata, "refresh", sd.refresh, query.GetAllocator());
   JSON_ADD_MEMBER(soadata, "retry", sd.retry, query.GetAllocator());
   JSON_ADD_MEMBER(soadata, "expire", sd.expire, query.GetAllocator());
   JSON_ADD_MEMBER(soadata, "default_ttl", sd.default_ttl, query.GetAllocator());
   JSON_ADD_MEMBER(soadata, "domain_id", sd.domain_id, query.GetAllocator());
   JSON_ADD_MEMBER(soadata, "scopeMask", sd.scopeMask, query.GetAllocator());
   parameters.AddMember("sd", soadata, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   serial = getInt64(answer["result"]);
   return true;
}

// some rapidjson helpers 
bool RemoteBackend::getBool(rapidjson::Value &value) {
   if (value.IsNull()) return false;
   if (value.IsBool()) return value.GetBool();
   if (value.IsInt()) return value.GetInt() != 0; // 0 = false, non-zero true
   if (value.IsDouble()) return value.GetDouble() != 0; // 0 = false, non-zero true
   if (value.IsString()) {  // accepts 0, 1, false, true
     std::string tmp = value.GetString();
     if (boost::iequals(tmp, "1") || boost::iequals(tmp, "true")) return true;
     if (boost::iequals(tmp, "0") || boost::iequals(tmp, "false")) return false;
   }
   std::cerr << value.GetType() << endl;
   throw new AhuException("Cannot convert rapidjson value into boolean");
}

bool Connector::getBool(rapidjson::Value &value) {
   if (value.IsNull()) return false;
   if (value.IsBool()) return value.GetBool();
   if (value.IsInt()) return value.GetInt() != 0; // 0 = false, non-zero true
   if (value.IsDouble()) return value.GetDouble() != 0; // 0 = false, non-zero true
   if (value.IsString()) {  // accepts 0, 1, false, true
     std::string tmp = value.GetString();
     if (boost::iequals(tmp, "1") || boost::iequals(tmp, "true")) return true;
     if (boost::iequals(tmp, "0") || boost::iequals(tmp, "false")) return false;
   }

   // this is specific for Connector!
   return true;
}

std::string Connector::getString(rapidjson::Value &value) {
   if (value.IsString()) return value.GetString();
   if (value.IsBool()) return (value.GetBool() ? "true" : "false");
   if (value.IsInt64()) return boost::lexical_cast<std::string>(value.GetInt64());
   if (value.IsInt()) return boost::lexical_cast<std::string>(value.GetInt());
   if (value.IsDouble()) return boost::lexical_cast<std::string>(value.GetDouble());
   return "(unpresentable value)"; // cannot convert into presentation format
}

int RemoteBackend::getInt(rapidjson::Value &value) {
   if (value.IsInt()) return value.GetInt();
   if (value.IsBool()) return (value.GetBool() ? 1 : 0);
   if (value.IsUint()) return static_cast<int>(value.GetUint());
   if (value.IsDouble()) return static_cast<int>(value.GetDouble());
   if (value.IsString()) {  // accepts 0, 1, false, true
     std::string tmp = value.GetString();
     return boost::lexical_cast<int>(tmp);
   }
   throw new AhuException("Cannot convert rapidjson value into integer");
}

unsigned int RemoteBackend::getUInt(rapidjson::Value &value) {
   if (value.IsUint()) return value.GetUint();
   if (value.IsBool()) return (value.GetBool() ? 1 : 0);
   if (value.IsInt()) return static_cast<unsigned int>(value.GetInt());
   if (value.IsDouble()) return static_cast<unsigned int>(value.GetDouble());
   if (value.IsString()) {  // accepts 0, 1, false, true
     std::string tmp = value.GetString();
     return boost::lexical_cast<unsigned int>(tmp);
   }
   throw new AhuException("Cannot convert rapidjson value into integer");
}

int64_t RemoteBackend::getInt64(rapidjson::Value &value) {
   if (value.IsInt64()) return value.GetInt64();
   if (value.IsBool()) return (value.GetBool() ? 1 : 0);
   if (value.IsInt()) return value.GetInt();
   if (value.IsDouble()) return static_cast<int64_t>(value.GetDouble());
   if (value.IsString()) {  // accepts 0, 1, false, true
     std::string tmp = value.GetString();
     return boost::lexical_cast<int64_t>(tmp);
   }
   throw new AhuException("Cannot convert rapidjson value into integer");
}

std::string RemoteBackend::getString(rapidjson::Value &value) {
   if (value.IsString()) return value.GetString();
   if (value.IsBool()) return (value.GetBool() ? "true" : "false");
   if (value.IsInt64()) return boost::lexical_cast<std::string>(value.GetInt64());
   if (value.IsInt()) return boost::lexical_cast<std::string>(value.GetInt());
   if (value.IsDouble()) return boost::lexical_cast<std::string>(value.GetDouble());
   throw new AhuException("Cannot convert rapidjson value into std::string");
}

double RemoteBackend::getDouble(rapidjson::Value &value) {
   if (value.IsDouble()) return value.GetDouble();
   if (value.IsBool()) return (value.GetBool() ? 1.0L : 0.0L);
   if (value.IsInt64()) return static_cast<double>(value.GetInt64());
   if (value.IsInt()) return static_cast<double>(value.GetInt());
   if (value.IsString()) {  // accepts 0, 1, false, true
     std::string tmp = value.GetString();
     return boost::lexical_cast<double>(tmp);
   }
   throw new AhuException("Cannot convert rapidjson value into double");
}

DNSBackend *RemoteBackend::maker()
{
   try {
      return new RemoteBackend();
   }
   catch(...) {
      L<<Logger::Error<<kBackendId<<" Unable to instantiate a remotebackend!"<<endl;
      return 0;
   };
}

RemoteLoader remoteloader __attribute__((visibility("default")));
