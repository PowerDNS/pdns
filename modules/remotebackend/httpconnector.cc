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

    return stream.str();
}

void HTTPConnector::post_requestbuilder(const rapidjson::Document &input, YaHTTP::Request& req) {
    if (this->d_post_json) {
        req.setup("POST", d_url);
        // simple case, POST JSON into url. nothing fancy.
        std::string out = makeStringFromDocument(input);
        req.headers["Content-Type"] = "text/javascript; charset=utf-8";
        req.headers["Content-Length"] = boost::lexical_cast<std::string>(out.size());
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
    }
}

void HTTPConnector::restful_requestbuilder(const std::string &method, const rapidjson::Value &parameters, YaHTTP::Request& req) {
};

int HTTPConnector::send_message(const rapidjson::Document &input) {
    int rv,ec;
    long rcode;
    
    std::vector<std::string> members;
    std::string method;
    std::ostringstream out;

    // initialize curl
    d_data = "";

    // perform request
    YaHTTP::Request req;

    if (d_post)
      post_requestbuilder(input, req);
    else
      restful_requestbuilder(input["method"].GetString(), input["parameters"], req);

    rv = -1;
    req.headers["connection"] = "close";

    out << req;

    if (req.url.protocol == "unix") {
      // connect using unix d_socketet
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
    int rd;

    arl.initialize(&resp);
    while(arl.ready() == false) {
       rd = d_socket->readWithTimeout(buffer, sizeof(buffer), timeout);
       if (rd>0)
         buffer[rd] = 0;
       arl.feed(std::string(buffer, rd));
    }
    arl.finalize();
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
