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
bool Connector::recv(rapidjson::Value &value) {
    rapidjson::Document input;
    if (recv_message(input)>0) {
       bool rv = true;
       // check for error
       if (input.HasMember("result")) {
          value = input["result"];
       } else {
          value = false;
          return false;
       }
       if (!value.IsObject() && (value.IsBool() && value.GetBool() == false)) {
           rv = false;
	   value = false;
        }
        if (input.HasMember("log")) {
           const rapidjson::Value& messages = input["log"];
           if (messages.IsArray()) {
              // log em all
              for (rapidjson::Value::ConstValueIterator iter = messages.Begin(); iter != messages.End(); ++iter)
                 L<<Logger::Info<<"[remotebackend]:"<< iter->GetString() <<std::endl;
           } else if (messages.IsString()) { // could be just a string, too
               L<<Logger::Info<<"[remotebackend]:"<< messages.GetString() <<std::endl;
           }
        }
        return rv;
    }
    return false;
}

RemoteBackend::RemoteBackend(const std::string &suffix)
{
      setArgPrefix("remote"+suffix);
      build(getArg("connection-string"));
      this->d_dnssec = mustDo("dnssec");
      this->d_index = -1;
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
         throw new AhuException("Invalid connection string: malformed");

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
#ifdef REMOTEBACKEND_HTTP
      } else if (type == "http") {
        this->connector = new HTTPConnector(options);
#endif
      } else if (type == "pipe") {
        this->connector = new PipeConnector(options);
      } else {
        throw new AhuException("Invalid connection string: unknown connector");
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

   if (pkt_p != NULL) {
     JSON_ADD_MEMBER(parameters, "remote", pkt_p->getRemote().c_str(), query.GetAllocator());
     JSON_ADD_MEMBER(parameters, "local", pkt_p->getRemote().c_str(), query.GetAllocator());
     JSON_ADD_MEMBER(parameters, "real-remote", pkt_p->getRealRemote().toString().c_str(), query.GetAllocator());
   }
   JSON_ADD_MEMBER(parameters, "zone-id", zoneId, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(d_result) == false)  return;

   // OK. we have result parametersues in result
   if (d_result.IsArray() == false) return;
   d_index = 0;
}

bool RemoteBackend::get(DNSResourceRecord &rr) {
   if (d_index == -1) return false;
   rapidjson::Value value;

   value = "";
   rr.qtype = JSON_GET(d_result[d_index], "qtype", value).GetString();
   rr.qname = JSON_GET(d_result[d_index], "qname", value).GetString();
   rr.qclass = QClass::IN;
   rr.content = JSON_GET(d_result[d_index], "content",value).GetString();
   value = -1;
   rr.ttl = JSON_GET(d_result[d_index], "ttl",value).GetInt();
   rr.domain_id = JSON_GET(d_result[d_index],"domain_id",value).GetInt();
   rr.priority = JSON_GET(d_result[d_index],"priority",value).GetInt();
   value = 1;
   if (d_dnssec) 
     rr.auth = JSON_GET(d_result[d_index],"auth", value).GetInt();
   else
     rr.auth = 1;
   value = 0;
   rr.scopeMask = JSON_GET(d_result[d_index],"scopeMask", value).GetInt();

   d_index++;
   
   // id index is out of bounds, we know the results end here. 
   if (d_index == static_cast<int>(d_result.Size())) {
     d_result.SetNull();
     d_index = -1;
   }
   return true;
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

   if (connector->send(query) == false || connector->recv(d_result) == false) 
     return false;
   if (d_result.IsArray() == false) 
     return false;

   d_index = 0;
   return true;
}

bool RemoteBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after) {
   rapidjson::Document query;
   rapidjson::Value answer,parameters;
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

   unhashed = answer["unhashed"].GetString();
   before = answer["before"].GetString();
   after = answer["after"].GetString();
  
   return true;
}

bool RemoteBackend::getDomainMetadata(const std::string& name, const std::string& kind, std::vector<std::string>& meta) {
   rapidjson::Document query;
   rapidjson::Value answer,parameters;

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

   for(rapidjson::Value::ValueIterator iter = answer.Begin(); iter != answer.End(); iter++) {
          meta.push_back(iter->GetString());
   }

   return true;
}

bool RemoteBackend::setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta) {
   rapidjson::Document query;
   rapidjson::Value answer,parameters,val;
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

   if (answer.IsBool())
      return answer.GetBool();
   return false;
}


bool RemoteBackend::getDomainKeys(const std::string& name, unsigned int kind, std::vector<DNSBackend::KeyData>& keys) {
   rapidjson::Document query;
   rapidjson::Value answer,parameters;
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

   for(rapidjson::Value::ValueIterator iter = answer.Begin(); iter != answer.End(); iter++) {
      DNSBackend::KeyData key;
      key.id = (*iter)["id"].GetUint();
      key.flags = (*iter)["flags"].GetUint();
      key.active = (*iter)["active"].GetBool();
      key.content = (*iter)["content"].GetString();
      keys.push_back(key);
   }

   return true;
}

bool RemoteBackend::removeDomainKey(const string& name, unsigned int id) { 
   rapidjson::Document query;
   rapidjson::Value answer,parameters;
   // no point doing dnssec if it's not supported
   if (d_dnssec == false) return false;

   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "getDomainKeys", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "name", name.c_str(), query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "id", id, query.GetAllocator());
   query.AddMember("parameters", parameters, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false)
     return false;

   return answer.GetBool();
}

int RemoteBackend::addDomainKey(const string& name, const KeyData& key) {
   rapidjson::Document query;
   rapidjson::Value answer,parameters,jkey;

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

   return answer.GetInt();
}

bool RemoteBackend::activateDomainKey(const string& name, unsigned int id) {
   rapidjson::Document query;
   rapidjson::Value answer, parameters;

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

   return answer.GetBool();
}

bool RemoteBackend::deactivateDomainKey(const string& name, unsigned int id) {
   rapidjson::Document query;
   rapidjson::Value answer, parameters;

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

   return answer.GetBool();
}

bool RemoteBackend::doesDNSSEC() {
   return d_dnssec;
}

bool RemoteBackend::getTSIGKey(const std::string& name, std::string* algorithm, std::string* content) {
   rapidjson::Document query;
   rapidjson::Value answer, parameters;

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
     algorithm->assign(answer["algorithm"].GetString());
   if (content != NULL)
     content->assign(answer["content"].GetString());
   
   return true;
}

bool RemoteBackend::getDomainInfo(const string &domain, DomainInfo &di) {
   rapidjson::Document query;
   rapidjson::Value answer, parameters;
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
   if (!answer.HasMember("zone")) {
      L<<Logger::Error<<kBackendId<<"Missing zone in getDomainInfo return value"<<endl;
      throw new AhuException();
   }
   value = -1;
   // parse return value. we need at least zone,serial,kind
   di.id = JSON_GET(answer,"id",value).GetInt();
   di.zone = answer["zone"].GetString();
   if (answer.HasMember("masters") && answer["masters"].IsArray()) {
     rapidjson::Value& value = answer["masters"];
     for(rapidjson::Value::ValueIterator i = value.Begin(); i != value.End(); i++) {
        di.masters.push_back(i->GetString());
     }
   }
   di.notified_serial = JSON_GET(answer, "notified_serial", value).GetInt();
   value = 0;
   di.serial = JSON_GET(answer,"serial", value).GetInt();
   di.last_check = JSON_GET(answer,"last_check", value).GetInt();
   value = "native";
   kind = JSON_GET(answer, "kind", value).GetString();
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
   rapidjson::Document query;
   rapidjson::Value answer, parameters;
  
   query.SetObject();
   JSON_ADD_MEMBER(query, "method", "setNotified", query.GetAllocator());
   parameters.SetObject();
   JSON_ADD_MEMBER(parameters, "id", id, query.GetAllocator());
   JSON_ADD_MEMBER(parameters, "serial", id, query.GetAllocator());

   if (connector->send(query) == false || connector->recv(answer) == false) {
      L<<Logger::Error<<kBackendId<<"Failed to execute RPC for RemoteBackend::setNotified("<<id<<","<<serial<<")"<<endl;
   }
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

class RemoteBackendFactory : public BackendFactory
{
  public:
      RemoteBackendFactory() : BackendFactory("remote") {}

      void declareArguments(const std::string &suffix="")
      {
          declare(suffix,"dnssec","Enable dnssec support","no");
          declare(suffix,"connection-string","Connection string","");
          declare(suffix,"timeout","Timeout in milliseconds to wait for reply","2000");
      }

      DNSBackend *make(const std::string &suffix="")
      {
         return new RemoteBackend(suffix);
      }
};

class RemoteLoader
{
   public:
      RemoteLoader()
      {
#ifdef REMOTEBACKEND_HTTP
         curl_global_init(CURL_GLOBAL_ALL);
#endif
         BackendMakers().report(new RemoteBackendFactory);
         L<<Logger::Notice<<kBackendId<<" This is the remotebackend version "VERSION" ("__DATE__", "__TIME__") reporting"<<endl;
      }
};

static RemoteLoader remoteloader;
