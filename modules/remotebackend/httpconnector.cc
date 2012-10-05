#include "remotebackend.hh"
#include <sys/socket.h>
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>
#include <curl/curl.h>
#include <boost/foreach.hpp>
#include <sstream>
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
}

HTTPConnector::~HTTPConnector() {
    this->d_c = NULL;
}

// friend method for writing data into our buffer
size_t httpconnector_write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
    HTTPConnector *tc = reinterpret_cast<HTTPConnector*>(userp);
    std::string tmp(reinterpret_cast<char *>(buffer), size*nmemb);
    tc->d_data += tmp;
    return nmemb;
}

// converts json value into string
void HTTPConnector::json2string(const Json::Value &input, std::string &output) {
   if (input.isString()) output = input.asString();
   else if (input.isNull()) output = "";
   else if (input.isUInt()) output = lexical_cast<std::string>(input.asUInt());
   else if (input.isInt()) output = lexical_cast<std::string>(input.asInt());
   else output = "inconvertible value";
}

// builds our request
void HTTPConnector::requestbuilder(const std::string &method, const Json::Value &parameters, struct curl_slist **slist)
{
    std::stringstream ss;
    Json::Value param;
    std::string sparam;
    char *tmpstr;

    // check for certain elements
    std::vector<std::string> members = parameters.getMemberNames();

    // special names are qname, name, zonename, kind, others go to headers

    ss << d_url;

    ss << "/" << method;

    // add the url components, if found, in following order 

    if ((param = parameters.get("zonename", Json::Value())).isNull() == false) {
       json2string(param, sparam);
       ss << "/" << sparam;
    }

    if ((param = parameters.get("qname", Json::Value())).isNull() == false) {
       json2string(param, sparam);
       ss << "/" << sparam;
    }
    
    if ((param = parameters.get("name", Json::Value())).isNull() == false) {
       json2string(param, sparam);
       ss << "/" << sparam;
    }

    if ((param = parameters.get("kind", Json::Value())).isNull() == false) {
       json2string(param, sparam);
       ss << "/" << sparam;
    }
    if ((param = parameters.get("qtype", Json::Value())).isNull() == false) {
       json2string(param, sparam);
       ss << "/" << sparam;
    }

    if ((param = parameters.get("id", Json::Value())).isNull() == false) {
       json2string(param, sparam);
       ss << "/" << sparam;
    }

    // finally add suffix
    ss << d_url_suffix;
    curl_easy_setopt(d_c, CURLOPT_URL, ss.str().c_str());

    (*slist) = NULL;
    // set the correct type of request based on method
    if (method == "activateDomainKey" || method == "deactivateDomainKey") { 
        // create an empty post
        curl_easy_setopt(d_c, CURLOPT_POST, 1);
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, 0);
    } else if (method == "addDomainKey") {
        // create post with keydata
        std::stringstream ss2;
        param = parameters["key"]; 
        ss2 << "flags" << param["flags"].asUInt() << "&active" << (param["active"].asBool() ? 1 : 0) << "&content=";
        tmpstr = curl_easy_escape(d_c, param["content"].asCString(), 0);
        ss2 << tmpstr;
        sparam = ss2.str();
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, sparam.size());
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, sparam.c_str());
        curl_free(tmpstr);
    } else if (method == "setDomainMetadata") {
        // copy all metadata values into post
        std::stringstream ss2;
        param = parameters["value"];
        curl_easy_setopt(d_c, CURLOPT_POST, 1);
        // this one has values too
        if (param.isArray()) {
           for(Json::ValueIterator i = param.begin(); i != param.end(); i++) {
              ss2 << "value[]=" << (*i).asString() << "&";
           }
        }
        sparam = ss2.str();
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, sparam.size());
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, sparam.c_str());
    } else if (method == "removeDomainKey") {
        // this one is delete
        curl_easy_setopt(d_c, CURLOPT_CUSTOMREQUEST, "DELETE");
    } else {
        // perform normal get
        curl_easy_setopt(d_c, CURLOPT_HTTPGET, 1);
    }

    // put everything else into headers
    BOOST_FOREACH(std::string member, members) {
      char header[1024];
      // these are not put into headers for obvious reasons
      if (member == "zonename" || member == "qname" ||
          member == "name" || member == "kind" ||
          member == "qtype" || member == "id" ||
          member == "key" ) continue;
      json2string(parameters[member], sparam);
      snprintf(header, sizeof header, "X-RemoteBackend-%s: %s", member.c_str(), sparam.c_str());
      (*slist) = curl_slist_append((*slist), header);
    };

    // store headers into request
    curl_easy_setopt(d_c, CURLOPT_HTTPHEADER, *slist); 
}

int HTTPConnector::send_message(const Json::Value &input) {
    int rv;
    long rcode;
    struct curl_slist *slist;

    std::vector<std::string> members;
    std::string method;

    // initialize curl
    d_c = curl_easy_init();
    d_data = "";
    curl_easy_setopt(d_c, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(d_c, CURLOPT_TIMEOUT, 2);
    slist = NULL;

    // build request
    requestbuilder(input["method"].asString(), input["parameters"], &slist);

    // setup write function helper
    curl_easy_setopt(d_c, CURLOPT_WRITEFUNCTION, &(httpconnector_write_data));
    curl_easy_setopt(d_c, CURLOPT_WRITEDATA, this);

    // then we actually do it
    if (curl_easy_perform(d_c) != CURLE_OK) {
      // boo, it failed
      rv = -1;
    } else {
      // ensure the result was OK
      if (curl_easy_getinfo(d_c, CURLINFO_RESPONSE_CODE, &rcode) != CURLE_OK || rcode < 200 || rcode > 299) {
         rv = -1;
      } else {
         // ok. if d_data == 0 but rcode is 2xx then result:true
         if (this->d_data.size() == 0) 
            this->d_data = "{\"result\": true}";
         rv = this->d_data.size();
      }
    }

    // clean up resources
    curl_slist_free_all(slist);
    curl_easy_cleanup(d_c);

    return rv;
}

int HTTPConnector::recv_message(Json::Value &output) {
    Json::Reader r;
    int rv = -1;

    // offer whatever we read in send_message
    if (r.parse(d_data, output) == true)
       rv = d_data.size();

    d_data = ""; // cleanup here
    return rv;
}
