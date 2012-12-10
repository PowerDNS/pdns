#include "remotebackend.hh"
#include <sys/socket.h>
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>
#include <boost/foreach.hpp>
#include <sstream>

#ifdef REMOTEBACKEND_HTTP
#include <curl/curl.h>
#endif

#ifndef UNIX_PATH_MAX 
#define UNIX_PATH_MAX 108
#endif

#ifdef REMOTEBACKEND_HTTP
HTTPConnector::HTTPConnector(std::map<std::string,std::string> options) {
    this->d_url = options.find("url")->second;
    if (options.find("url-suffix") != options.end()) {
      this->d_url_suffix = options.find("url-suffix")->second;
    } else {
      this->d_url_suffix = "";
    }
    this->timeout = 2;
    if (options.find("timeout") != options.end()) { 
      this->timeout = boost::lexical_cast<int>(options.find("timeout")->second)/1000;
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
void HTTPConnector::json2string(const rapidjson::Value &input, std::string &output) {
   if (input.IsString()) output = input.GetString();
   else if (input.IsNull()) output = "";
   else if (input.IsUint()) output = lexical_cast<std::string>(input.GetUint());
   else if (input.IsInt()) output = lexical_cast<std::string>(input.GetInt());
   else output = "inconvertible value";
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


// builds our request
void HTTPConnector::requestbuilder(const std::string &method, const rapidjson::Value &parameters, struct curl_slist **slist)
{
    std::stringstream ss;
    std::string sparam;
    char *tmpstr;

    // special names are qname, name, zonename, kind, others go to headers

    ss << d_url;

    ss << "/" << method;

    // add the url components, if found, in following order.
    // id must be first due to the fact that the qname/name can be empty

    addUrlComponent(parameters, "id", ss);
    addUrlComponent(parameters, "zonename", ss);
    addUrlComponent(parameters, "qname", ss);
    addUrlComponent(parameters, "name", ss);
    addUrlComponent(parameters, "kind", ss);
    addUrlComponent(parameters, "qtype", ss);

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
        const rapidjson::Value& param = parameters["key"]; 
        ss2 << "flags=" << param["flags"].GetUint() << "&active=" << (param["active"].GetBool() ? 1 : 0) << "&content=";
        tmpstr = curl_easy_escape(d_c, param["content"].GetString(), 0);
        ss2 << tmpstr;
        sparam = ss2.str();
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, sparam.size());
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, sparam.c_str());
        curl_free(tmpstr);
    } else if (method == "setDomainMetadata") {
        int n=0;
        // copy all metadata values into post
        std::stringstream ss2;
        const rapidjson::Value& param = parameters["value"];
        curl_easy_setopt(d_c, CURLOPT_POST, 1);
        // this one has values too
        if (param.IsArray()) {
           for(rapidjson::Value::ConstValueIterator i = param.Begin(); i != param.End(); i++) {
              ss2 << "value" << (++n) << "=" << i->GetString() << "&";
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
    for (rapidjson::Value::ConstMemberIterator iter = parameters.MemberBegin(); iter != parameters.MemberEnd(); ++iter) {
      char header[1024];
      const char *member = iter->name.GetString();
      // these are not put into headers for obvious reasons
      if (!strncmp(member,"zonename",8) || !strncmp(member,"qname",5) ||
          !strncmp(member,"name",4) || !strncmp(member,"kind",4) ||
          !strncmp(member,"qtype",5) || !strncmp(member,"id",2) ||
          !strncmp(member,"key",3)) continue;
      json2string(parameters[member], sparam);
      snprintf(header, sizeof header, "X-RemoteBackend-%s: %s", iter->name.GetString(), sparam.c_str());
      (*slist) = curl_slist_append((*slist), header);
    };

    // store headers into request
    curl_easy_setopt(d_c, CURLOPT_HTTPHEADER, *slist); 
}

int HTTPConnector::send_message(const rapidjson::Document &input) {
    int rv;
    long rcode;
    struct curl_slist *slist;

    std::vector<std::string> members;
    std::string method;

    // initialize curl
    d_c = curl_easy_init();
    d_data = "";
    curl_easy_setopt(d_c, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(d_c, CURLOPT_TIMEOUT, this->timeout);

    slist = NULL;

    // build request
    requestbuilder(input["method"].GetString(), input["parameters"], &slist);

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

int HTTPConnector::recv_message(rapidjson::Document &output) {
    rapidjson::StringStream ss(d_data.c_str());
    int rv = -1;
    output.ParseStream<0>(ss);

    // offer whatever we read in send_message
    if (output.HasParseError() == false)
       rv = d_data.size();

    d_data = ""; // cleanup here
    return rv;
}

#endif
