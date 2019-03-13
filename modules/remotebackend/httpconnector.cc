/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "remotebackend.hh"
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include <sstream>
#include "pdns/lock.hh"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

HTTPConnector::HTTPConnector(std::map<std::string,std::string> options): d_socket(nullptr) {

    if (options.find("url") == options.end()) {
      throw PDNSException("Cannot find 'url' option in the remote backend HTTP connector's parameters");
    }

    this->d_url = options.find("url")->second;

    try {
      YaHTTP::URL url(d_url);
      d_host = url.host;
      d_port = url.port;
    }
    catch(const std::exception& e) {
      throw PDNSException("Error parsing the 'url' option provided to the remote backend HTTP connector: " + std::string(e.what()));
    }

    if (options.find("url-suffix") != options.end()) {
      this->d_url_suffix = options.find("url-suffix")->second;
    } else {
      this->d_url_suffix = "";
    }
    this->timeout = 2;
    this->d_post = false;
    this->d_post_json = false;

    if (options.find("timeout") != options.end()) {
      this->timeout = std::stoi(options.find("timeout")->second)/1000;
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
}

HTTPConnector::~HTTPConnector() { }

void HTTPConnector::addUrlComponent(const Json &parameters, const string& element, std::stringstream& ss) {
    std::string sparam;
    if (parameters[element] != Json())
       ss << "/" << YaHTTP::Utility::encodeURL(asString(parameters[element]), false);
}

std::string HTTPConnector::buildMemberListArgs(std::string prefix, const Json& args) {
    std::stringstream stream;

    for(const auto& pair: args.object_items()) {
        if (pair.second.is_bool()) {
          stream << (pair.second.bool_value()?"1":"0");
        } else if (pair.second.is_null()) {
          stream << prefix << "[" << YaHTTP::Utility::encodeURL(pair.first, false) << "]=";
        } else {
          stream << prefix << "[" << YaHTTP::Utility::encodeURL(pair.first, false) << "]=" << YaHTTP::Utility::encodeURL(this->asString(pair.second), false);
        }
        stream << "&";
    }

    return stream.str().substr(0, stream.str().size()-1); // snip the trailing & 
}

// builds our request (near-restful)
void HTTPConnector::restful_requestbuilder(const std::string &method, const Json& parameters, YaHTTP::Request& req)
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
        req.preparePost();
        verb = "POST";
    } else if (method == "setTSIGKey") {
        req.POST()["algorithm"] = parameters["algorithm"].string_value();
        req.POST()["content"] = parameters["content"].string_value();
        req.preparePost();
        verb = "PATCH";
    } else if (method == "deleteTSIGKey") {
        verb = "DELETE";
    } else if (method == "addDomainKey") {
        const Json& param = parameters["key"];
        req.POST()["flags"] = asString(param["flags"]);
        req.POST()["active"] = (param["active"].bool_value() ? "1" : "0");
        req.POST()["content"] = param["content"].string_value();
        req.preparePost();
        verb = "PUT";
    } else if (method == "superMasterBackend") {
        std::stringstream ss2;
        addUrlComponent(parameters, "ip", ss);
        addUrlComponent(parameters, "domain", ss);
        // then we need to serialize rrset payload into POST
        for(size_t index = 0; index < parameters["nsset"].array_items().size(); index++) {
            ss2 << buildMemberListArgs("nsset[" + std::to_string(index) + "]", parameters["nsset"][index]) << "&";
        }
        req.body = ss2.str().substr(0, ss2.str().size()-1);
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = std::to_string(req.body.size());
        verb = "POST";
    } else if (method == "createSlaveDomain") {
        addUrlComponent(parameters, "ip", ss);
        addUrlComponent(parameters, "domain", ss);
        if (parameters["account"].is_null() == false && parameters["account"].is_string()) {
           req.POST()["account"] = parameters["account"].string_value();
        }
        req.preparePost();
        verb = "PUT";
    } else if (method == "replaceRRSet") {
        std::stringstream ss2;
        for(size_t index = 0; index < parameters["rrset"].array_items().size(); index++) {
            ss2 << buildMemberListArgs("rrset[" + std::to_string(index) + "]", parameters["rrset"][index]);
        }
        req.body = ss2.str();
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = std::to_string(req.body.size());
        verb = "PATCH";
    } else if (method == "feedRecord") {
        addUrlComponent(parameters, "trxid", ss);
        req.body = buildMemberListArgs("rr", parameters["rr"]);
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = std::to_string(req.body.size());
        verb = "PATCH";
    } else if (method == "feedEnts") {
        std::stringstream ss2;
        addUrlComponent(parameters, "trxid", ss);
        for(const auto& param: parameters["nonterm"].array_items()) {
          ss2 << "nonterm[]=" << YaHTTP::Utility::encodeURL(param.string_value(), false) << "&";
        }
        for(const auto& param: parameters["auth"].array_items()) {
          ss2 << "auth[]=" << (param["auth"].bool_value()?"1":"0") << "&";
        }
        req.body = ss2.str().substr(0, ss2.str().size()-1);
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = std::to_string(req.body.size());
        verb = "PATCH";
    } else if (method == "feedEnts3") {
        std::stringstream ss2;
        addUrlComponent(parameters, "domain", ss);
        addUrlComponent(parameters, "trxid", ss);
        ss2 << "times=" << parameters["times"].int_value() << "&salt=" << YaHTTP::Utility::encodeURL(parameters["salt"].string_value(), false) << "&narrow=" << (parameters["narrow"].bool_value() ? 1 : 0) << "&";
        for(const auto& param: parameters["nonterm"].array_items()) {
          ss2 << "nonterm[]=" << YaHTTP::Utility::encodeURL(param.string_value(), false) << "&";
        }
        for(const auto& param: parameters["auth"].array_items()) {
          ss2 << "auth[]=" << (param["auth"].bool_value()?"1":"0") << "&";
        }
        req.body = ss2.str().substr(0, ss2.str().size()-1);
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = std::to_string(req.body.size());
        verb = "PATCH";
    } else if (method == "startTransaction") {
        addUrlComponent(parameters, "domain", ss);
        addUrlComponent(parameters, "trxid", ss);
        req.preparePost();
        verb = "POST";
    } else if (method == "commitTransaction" || method == "abortTransaction") {
        addUrlComponent(parameters, "trxid", ss);
        req.preparePost();
        verb = "POST";
    } else if (method == "setDomainMetadata") {
        // copy all metadata values into post
        std::stringstream ss2;
        // this one has values too
        if (parameters["value"].is_array()) {
           for(const auto& val: parameters["value"].array_items()) {
              ss2 << "value[]=" << YaHTTP::Utility::encodeURL(val.string_value(), false) << "&";
           }
        }
        req.body = ss2.str().substr(0, ss2.str().size()-1);
        req.headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
        req.headers["content-length"] = std::to_string(req.body.size());
        verb = "PATCH";
    } else if (method == "removeDomainKey") {
        // this one is delete
        verb = "DELETE";
    } else if (method == "setNotified") {
        req.POST()["serial"] = std::to_string(parameters["serial"].number_value());
        req.preparePost();
        verb = "PATCH";
    } else if (method == "directBackendCmd") {
        req.POST()["query"] = parameters["query"].string_value();
        req.preparePost();
        verb = "POST";
    } else if (method == "searchRecords" || method == "searchComments") {
        req.GET()["pattern"] = parameters["pattern"].string_value();
        req.GET()["maxResults"] = std::to_string(parameters["maxResults"].int_value());
        verb = "GET";
   } else if (method == "getAllDomains") {
        req.GET()["includeDisabled"] = (parameters["include_disabled"].bool_value()?"true":"false");
        verb = "GET";
    } else {
        // perform normal get
        verb = "GET";
    }

    // put everything else into headers
    for(const auto& pair: parameters.object_items()) {
      std::string member = pair.first;
      // whitelist header parameters
      if ((member == "trxid" ||
           member == "local" || 
           member == "remote" ||
           member == "real-remote" ||
           member == "zone-id")) {
        std::string hdr = "x-remotebackend-" + member;
        req.headers[hdr] = asString(pair.second);
      }
    };

    // finally add suffix and store url
    ss << d_url_suffix;

    req.setup(verb, ss.str());
    req.headers["accept"] = "application/json";
}

void HTTPConnector::post_requestbuilder(const Json& input, YaHTTP::Request& req) {
    if (this->d_post_json) {
        std::string out = input.dump();
        req.setup("POST", d_url);
        // simple case, POST JSON into url. nothing fancy.
        req.headers["Content-Type"] = "text/javascript; charset=utf-8";
        req.headers["Content-Length"] = std::to_string(out.size());
        req.headers["accept"] = "application/json";
        req.body = out;
    } else {
        std::stringstream url,content;
        // call url/method.suffix
        url << d_url << "/" << input["method"].string_value() << d_url_suffix;
        req.setup("POST", url.str());
        // then build content
        req.POST()["parameters"] = input["parameters"].dump();
        req.preparePost();
        req.headers["accept"] = "application/json";
    }
}

int HTTPConnector::send_message(const Json& input) {
    int rv,ec,fd;
    
    std::vector<std::string> members;
    std::string method;
    std::ostringstream out;

    // perform request
    YaHTTP::Request req;

    if (d_post)
      post_requestbuilder(input, req);
    else
      restful_requestbuilder(input["method"].string_value(), input["parameters"], req);

    rv = -1;
    req.headers["connection"] = "Keep-Alive"; // see if we can streamline requests (not needed, strictly speaking)

    out << req;

    // try sending with current socket, if it fails retry with new socket
    if (this->d_socket != nullptr) {
      fd = this->d_socket->getHandle();
      // there should be no data waiting
      if (waitForRWData(fd, true, 0, 1000) < 1) {
        try {
          d_socket->writenWithTimeout(out.str().c_str(), out.str().size(), timeout);
          rv = 1;
        } catch (NetworkError& ne) {
          g_log<<Logger::Error<<"While writing to HTTP endpoint "<<d_addr.toStringWithPort()<<": "<<ne.what()<<std::endl;
        } catch (...) {
          g_log<<Logger::Error<<"While writing to HTTP endpoint "<<d_addr.toStringWithPort()<<": exception caught"<<std::endl;
        }
      }
    }

    if (rv == 1) return rv;

    this->d_socket.reset();

    // connect using tcp
    struct addrinfo *gAddr, *gAddrPtr, hints;
    std::string sPort = std::to_string(d_port);
    memset(&hints,0,sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if ((ec = getaddrinfo(d_host.c_str(), sPort.c_str(), &hints, &gAddr)) == 0) {
      // try to connect to each address.
      gAddrPtr = gAddr;

      while(gAddrPtr) {
        try {
          d_socket = std::unique_ptr<Socket>(new Socket(gAddrPtr->ai_family, gAddrPtr->ai_socktype, gAddrPtr->ai_protocol));
          d_addr.setSockaddr(gAddrPtr->ai_addr, gAddrPtr->ai_addrlen);
          d_socket->connect(d_addr);
          d_socket->setNonBlocking();
          d_socket->writenWithTimeout(out.str().c_str(), out.str().size(), timeout);
          rv = 1;
        } catch (NetworkError& ne) {
          g_log<<Logger::Error<<"While writing to HTTP endpoint "<<d_addr.toStringWithPort()<<": "<<ne.what()<<std::endl;
        } catch (...) {
          g_log<<Logger::Error<<"While writing to HTTP endpoint "<<d_addr.toStringWithPort()<<": exception caught"<<std::endl;
        }

        if (rv > -1) break;
        d_socket.reset();
        gAddrPtr = gAddrPtr->ai_next;
      }
      freeaddrinfo(gAddr);
    } else {
      g_log<<Logger::Error<<"Unable to resolve " << d_host << ": " << gai_strerror(ec) << std::endl;
    }

    return rv;
}

int HTTPConnector::recv_message(Json& output) {
    YaHTTP::AsyncResponseLoader arl;
    YaHTTP::Response resp;

    if (d_socket == nullptr ) return -1; // cannot receive :(
    char buffer[4096];
    int rd = -1;
    bool fail = false;
    time_t t0;

    arl.initialize(&resp);

    try {
      t0 = time((time_t*)NULL);
      while(arl.ready() == false && (labs(time((time_t*)NULL) - t0) <= timeout)) {
        rd = d_socket->readWithTimeout(buffer, sizeof(buffer), timeout);
        if (rd==0) 
          throw NetworkError("EOF while reading");
        if (rd<0)
          throw NetworkError(std::string(strerror(rd)));
        arl.feed(std::string(buffer, rd));
      }
      // timeout occured.
      if (arl.ready() == false)
        throw NetworkError("timeout");
    } catch (NetworkError &ne) {
      g_log<<Logger::Error<<"While reading from HTTP endpoint "<<d_addr.toStringWithPort()<<": "<<ne.what()<<std::endl; 
      d_socket.reset();
      fail = true;
    } catch (...) {
      g_log<<Logger::Error<<"While reading from HTTP endpoint "<<d_addr.toStringWithPort()<<": exception caught"<<std::endl;
      d_socket.reset();
      fail = true;
    }

    if (fail) {
      return -1;
    }

    arl.finalize();

    if (resp.status < 200 || resp.status >= 400) {
      // bad. 
      return -1;
    }

    int rv = -1;
    std::string err;
    output = Json::parse(resp.body, err);
    if (output != nullptr) return resp.body.size();
    g_log<<Logger::Error<<"Cannot parse JSON reply: "<<err<<endl;

    return rv;
}
