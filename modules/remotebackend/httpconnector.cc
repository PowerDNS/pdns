#include "remotebackend.hh"
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <boost/foreach.hpp>
#include <sstream>
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "polarssl/ssl.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

HTTPConnector::HTTPConnector(std::map<std::string,std::string> options) {
    this->d_url = options.find("url")->second;
    if (options.find("url-suffix") != options.end()) {
      this->d_url_suffix = options.find("url-suffix")->second;
    } else {
      this->d_url_suffix = "";
    }
    this->timeout = 2;
    this->d_post = false;
    this->d_post_json = false;

    if (options.find("timeout") != options.end()) {
      this->timeout = boost::lexical_cast<int>(options.find("timeout")->second)/1000;
    }
    if (options.find("post") != options.end()) {
      std::string val = options.find("post")->second;
      if (val == "yes" || val == "true" || val == "on" || val == "1") {
        this->d_post = true;
      }
    }
    if (options.find("post_json") != options.end()) {
      std::string val = options.find("post_json")->second;
      if (val == "yes" || val == "true" || val == "on" || val == "1") {
        this->d_post_json = true;
      }
    }
    if (options.find("capath") != options.end()) this->d_capath = options.find("capath")->second;
    if (options.find("cafile") != options.end()) this->d_cafile = options.find("cafile")->second;
}

HTTPConnector::~HTTPConnector() {
}

// converts json value into string
bool HTTPConnector::json2string(const rapidjson::Value &input, std::string &output) {
   if (input.IsString()) output = input.GetString();
   else if (input.IsNull()) output = "";
   else if (input.IsUint64()) output = lexical_cast<std::string>(input.GetUint64());
   else if (input.IsInt64()) output = lexical_cast<std::string>(input.GetInt64());
   else if (input.IsUint()) output = lexical_cast<std::string>(input.GetUint());
   else if (input.IsInt()) output = lexical_cast<std::string>(input.GetInt());
   else return false;
   return true;
}

void HTTPConnector::addUrlComponent(const rapidjson::Value &parameters, const char *element, std::stringstream& ss) {
    rapidjson::Value nullval;
    std::string sparam;
    nullval.SetNull();
    const rapidjson::Value& param = (parameters.HasMember(element)?parameters[element]:nullval);
    if (param.IsNull() == false) {
       json2string(param, sparam);
       ss << "/" << sparam;
    }
}

template <class T> std::string buildMemberListArgs(std::string prefix, const T* value) {
    std::stringstream stream;

    for (rapidjson::Value::ConstMemberIterator itr = value->MemberBegin(); itr != value->MemberEnd(); itr++) {
        stream << prefix << "[" << itr->name.GetString() << "]=";

        if (itr->value.IsUint64()) {
            stream << itr->value.GetUint64();
        } else if (itr->value.IsInt64()) {
            stream << itr->value.GetInt64();
        } else if (itr->value.IsUint()) {
            stream << itr->value.GetUint();
        } else if (itr->value.IsInt()) {
            stream << itr->value.GetInt();
        } else if (itr->value.IsBool()) {
            stream << (itr->value.GetBool() ? 1 : 0);
        } else if (itr->value.IsString()) {
            stream << YaHTTP::Utility::encodeURL(itr->value.GetString(), false);
        }

        stream << "&";
    }

    return stream.str().substr(0, stream.str().size()-1); // snip the trailing & 
}

// builds our request (near-restful)
void HTTPConnector::restful_requestbuilder(const std::string &method, const rapidjson::Value &parameters, YaHTTP::Request& req)
{
    std::stringstream ss;
    std::string sparam;
    std::string verb;

    // special names are qname, name, zonename, kind, others go to headers

    ss << d_url;

    ss << "/" << method;

    // add the url components, if found, in following order.
    // id must be first due to the fact that the qname/name can be empty

    addUrlComponent(parameters, "id", ss);
    addUrlComponent(parameters, "domain_id", ss);
    addUrlComponent(parameters, "zonename", ss);
    addUrlComponent(parameters, "qname", ss);
    addUrlComponent(parameters, "name", ss);
    addUrlComponent(parameters, "kind", ss);
    addUrlComponent(parameters, "qtype", ss);

    // set the correct type of request based on method
    if (method == "activateDomainKey" || method == "deactivateDomainKey") {
        // create an empty post
        verb = "POST";
    } else if (method == "setTSIGKey") {
        req.POST()["algorithm"] = parameters["algorithm"].GetString();
        req.POST()["content"] = parameters["content"].GetString();
        req.preparePost();
        verb = "PATCH";
    } else if (method == "deleteTSIGKey") {
        verb = "DELETE";
    } else if (method == "addDomainKey") {
        const rapidjson::Value& param = parameters["key"];
        json2string(param["flags"],sparam);
        req.POST()["flags"] = sparam;
        req.POST()["active"] = (param["active"].GetBool() ? "1" : "0");
        req.POST()["content"] = param["content"].GetString();
        req.preparePost();
        verb = "PUT";
    } else if (method == "isMaster") {
        addUrlComponent(parameters, "ip", ss);
        verb = "GET";
    } else if (method == "superMasterBackend") {
        std::stringstream ss2;
        addUrlComponent(parameters, "ip", ss);
        addUrlComponent(parameters, "domain", ss);
        // then we need to serialize rrset payload into POST
        size_t index = 0;
        for(rapidjson::Value::ConstValueIterator itr = parameters["nsset"].Begin(); itr != parameters["nsset"].End(); itr++) {
            index++;
            ss2 << buildMemberListArgs("nsset[" + boost::lexical_cast<std::string>(index) + "]", itr) << "&";
        }
        req.body = ss2.str().substr(0, ss2.str().size()-1);
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = boost::lexical_cast<std::string>(req.body.size());
        verb = "POST";
    } else if (method == "createSlaveDomain") {
        addUrlComponent(parameters, "ip", ss);
        addUrlComponent(parameters, "domain", ss);
        if (parameters.HasMember("account")) {
           req.POST()["account"] = parameters["account"].GetString();
        }
        req.preparePost();
        verb = "PUT";
    } else if (method == "replaceRRSet") {
        std::stringstream ss2;
        size_t index = 0;
        for(rapidjson::Value::ConstValueIterator itr = parameters["rrset"].Begin(); itr != parameters["rrset"].End(); itr++) {
            index++;
            ss2 << buildMemberListArgs("rrset[" + boost::lexical_cast<std::string>(index) + "]", itr);
        }
        req.body = ss2.str();
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = boost::lexical_cast<std::string>(req.body.size());
        verb = "PATCH";
    } else if (method == "feedRecord") {
        addUrlComponent(parameters, "trxid", ss);
        req.body = buildMemberListArgs("rr", &parameters["rr"]);
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = boost::lexical_cast<std::string>(req.body.size());
        verb = "PATCH";
    } else if (method == "feedEnts") {
        std::stringstream ss2;
        addUrlComponent(parameters, "trxid", ss);
        for(rapidjson::Value::ConstValueIterator itr = parameters["nonterm"].Begin(); itr != parameters["nonterm"].End(); itr++) {
          ss2 << "nonterm[]=" << YaHTTP::Utility::encodeURL(itr->GetString(), false) << "&";
        }
        req.body = ss2.str().substr(0, ss2.str().size()-1);
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = boost::lexical_cast<std::string>(req.body.size());
        verb = "PATCH";
    } else if (method == "feedEnts3") {
        std::stringstream ss2;
        addUrlComponent(parameters, "domain", ss);
        addUrlComponent(parameters, "trxid", ss);
        ss2 << "times=" << parameters["times"].GetInt() << "&salt=" << YaHTTP::Utility::encodeURL(parameters["salt"].GetString(), false) << "&narrow=" << (parameters["narrow"].GetBool() ? 1 : 0) << "&";
        for(rapidjson::Value::ConstValueIterator itr = parameters["nonterm"].Begin(); itr != parameters["nonterm"].End(); itr++) {
          ss2 << "nonterm[]=" << YaHTTP::Utility::encodeURL(itr->GetString(), false) << "&";
        }
        req.body = ss2.str().substr(0, ss2.str().size()-1);
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = boost::lexical_cast<std::string>(req.body.size());
        verb = "PATCH";
    } else if (method == "startTransaction") {
        addUrlComponent(parameters, "domain", ss);
        addUrlComponent(parameters, "trxid", ss);
        verb = "POST";
    } else if (method == "commitTransaction" || method == "abortTransaction") {
        addUrlComponent(parameters, "trxid", ss);
        verb = "POST";
    } else if (method == "calculateSOASerial") {
        addUrlComponent(parameters, "domain", ss);
        req.body = buildMemberListArgs("sd", &parameters["sd"]);
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = boost::lexical_cast<std::string>(req.body.size());
        verb = "POST";
    } else if (method == "setDomainMetadata") {
        // copy all metadata values into post
        std::stringstream ss2;
        const rapidjson::Value& param = parameters["value"];
        // this one has values too
        if (param.IsArray()) {
           for(rapidjson::Value::ConstValueIterator i = param.Begin(); i != param.End(); i++) {
              ss2 << "value[]=" << YaHTTP::Utility::encodeURL(i->GetString(), false) << "&";
           }
        }
        req.body = ss2.str().substr(0, ss2.str().size()-1);
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = boost::lexical_cast<std::string>(req.body.size());
        verb = "PATCH";
    } else if (method == "removeDomainKey") {
        // this one is delete
        verb = "DELETE";
    } else if (method == "setNotified") {
        json2string(parameters["serial"],sparam);
        req.POST()["serial"] = sparam;
        req.preparePost();
        verb = "PATCH";
    } else {
        // perform normal get
        verb = "GET";
    }

    // put everything else into headers
    for (rapidjson::Value::ConstMemberIterator iter = parameters.MemberBegin(); iter != parameters.MemberEnd(); ++iter) {
      std::string member = iter->name.GetString();
      // whitelist header parameters
      if ((member == "trxid" ||
           member == "local" || 
           member == "remote" ||
           member == "real-remote" ||
           member == "zone-id") && 
          json2string(parameters[member.c_str()], sparam)) {
        std::string hdr = "x-remotebackend-" + member;
        req.headers[hdr] = sparam;
      }
    };

    // finally add suffix and store url
    ss << d_url_suffix;

    req.setup(verb, ss.str());
    req.headers["accept"] = "application/json";
}


void HTTPConnector::post_requestbuilder(const rapidjson::Document &input, YaHTTP::Request& req) {
    if (this->d_post_json) {
        req.setup("POST", d_url);
        // simple case, POST JSON into url. nothing fancy.
        std::string out = makeStringFromDocument(input);
        req.headers["Content-Type"] = "text/javascript; charset=utf-8";
        req.headers["Content-Length"] = boost::lexical_cast<std::string>(out.size());
        req.headers["accept"] = "application/json";
        req.body = out;
    } else {
        std::stringstream url,content;
        // call url/method.suffix
        rapidjson::StringBuffer output;
        rapidjson::Writer<rapidjson::StringBuffer> w(output);
        input["parameters"].Accept(w);
        url << d_url << "/" << input["method"].GetString() << d_url_suffix;
        req.setup("POST", url.str());
        // then build content
        req.POST()["parameters"] = output.GetString();
        req.preparePost();
        req.headers["accept"] = "application/json";
    }
}

int HTTPConnector::send_message(const rapidjson::Document &input) {
    int rv,ec;
    
    std::vector<std::string> members;
    std::string method;
    std::ostringstream out;

    // perform request
    YaHTTP::Request req;

    if (d_post)
      post_requestbuilder(input, req);
    else
      restful_requestbuilder(input["method"].GetString(), input["parameters"], req);

    rv = -1;
    req.headers["connection"] = "close"; // make sure the other ends knows we are not going to hang around

    out << req;

    if (req.url.protocol == "unix") {
      // connect using unix socket
    } else {
      // connect using tcp
      struct addrinfo *gAddr, *gAddrPtr;
      std::string sPort = boost::lexical_cast<std::string>(req.url.port);
      if ((ec = getaddrinfo(req.url.host.c_str(), sPort.c_str(), NULL, &gAddr)) == 0) {
        // try to connect to each address. 
        gAddrPtr = gAddr;
        while(gAddrPtr) {
          d_socket = new Socket(gAddrPtr->ai_family, gAddrPtr->ai_socktype, gAddrPtr->ai_protocol);
          try {
            ComboAddress addr = *reinterpret_cast<ComboAddress*>(gAddrPtr->ai_addr);
            d_socket->connect(addr);
            d_socket->setNonBlocking();
            d_socket->writenWithTimeout(out.str().c_str(), out.str().size(), timeout);
            rv = 1;
          } catch (NetworkError& ne) {
            L<<Logger::Error<<"While writing to HTTP endpoint: "<<ne.what()<<std::endl;
          }
          if (rv > -1) break;
          delete d_socket;
          d_socket = NULL;
          gAddrPtr = gAddrPtr->ai_next;
        }
        freeaddrinfo(gAddr);
      } else {
        L<<Logger::Error<<"Unable to resolve " << req.url.host << ": " << gai_strerror(ec) << std::endl;
      }
    }

    return rv;
}

int HTTPConnector::recv_message(rapidjson::Document &output) {
    YaHTTP::AsyncResponseLoader arl;
    YaHTTP::Response resp;

    if (d_socket == NULL ) return -1; // cannot receive :(
    char buffer[4096];
    int rd = -1;

    arl.initialize(&resp);

    while(arl.ready() == false) {
       rd = d_socket->readWithTimeout(buffer, sizeof(buffer), timeout);
       if (rd<0) {
         delete d_socket;
         d_socket = NULL;
         return -1;
       }
       buffer[rd] = 0;
       arl.feed(std::string(buffer, rd));
    }

    arl.finalize();

    if (resp.status < 200 || resp.status >= 400) {
      // bad. 
      return -1;
    }

    rapidjson::StringStream ss(resp.body.c_str());
    int rv = -1;
    output.ParseStream<0>(ss);

    // offer whatever we read in send_message
    if (output.HasParseError() == false)
       rv = rd;
    else
       rv = -1;

    delete d_socket;
    d_socket = NULL;
 
    return rv;
}
