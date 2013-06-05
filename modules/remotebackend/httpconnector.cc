#include "remotebackend.hh"
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <boost/foreach.hpp>
#include <sstream>
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

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
bool HTTPConnector::json2string(const rapidjson::Value &input, std::string &output) {
   if (input.IsString()) output = input.GetString();
   else if (input.IsNull()) output = "";
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

template <class T> std::string buildMemberListArgs(std::string prefix, const T* value, CURL* curlContext) {
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
            char *tmpstr = curl_easy_escape(curlContext, itr->value.GetString(), 0);
            stream << tmpstr;
            curl_free(tmpstr);
        }

        stream << "&";
    }

    return stream.str();
}

// builds our request (near-restful)
void HTTPConnector::restful_requestbuilder(const std::string &method, const rapidjson::Value &parameters, struct curl_slist **slist)
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
    addUrlComponent(parameters, "domain_id", ss);
    addUrlComponent(parameters, "zonename", ss);
    addUrlComponent(parameters, "qname", ss);
    addUrlComponent(parameters, "name", ss);
    addUrlComponent(parameters, "kind", ss);
    addUrlComponent(parameters, "qtype", ss);

    (*slist) = NULL;
    // set the correct type of request based on method
    if (method == "activateDomainKey" || method == "deactivateDomainKey") { 
        // create an empty post
        curl_easy_setopt(d_c, CURLOPT_POST, 1);
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, 0);
    } else if (method == "addDomainKey") {
        // create post with keydata
        char *postfields;
        int nsize;
        const rapidjson::Value& param = parameters["key"];
        tmpstr = curl_easy_escape(d_c, param["content"].GetString(), 0);
        nsize = 35 + strlen(tmpstr);
        postfields = new char[nsize];
        nsize = snprintf(postfields, nsize, "flags=%u&active=%d&content=%s", param["flags"].GetUint(), (param["active"].GetBool() ? 1 : 0), tmpstr);
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, nsize);
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, postfields);
        curl_free(tmpstr);
        delete postfields;
    } else if (method == "superMasterBackend") {
        std::stringstream ss2;
        addUrlComponent(parameters, "ip", ss);
        addUrlComponent(parameters, "domain", ss);
        // then we need to serialize rrset payload into POST
        size_t index = 0;
        for(rapidjson::Value::ConstValueIterator itr = parameters["nsset"].Begin(); itr != parameters["nsset"].End(); itr++) {
            index++;
            ss2 << buildMemberListArgs("nsset[" + boost::lexical_cast<std::string>(index) + "]", itr, d_c);
        }
        // then give it to curl
        std::string out = ss2.str();
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, out.size());
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, out.c_str());
    } else if (method == "createSlaveDomain") {
        addUrlComponent(parameters, "ip", ss);
        addUrlComponent(parameters, "domain", ss);
        if (parameters.HasMember("account")) {
           std::string out = parameters["account"].GetString();
           curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, out.size());
           curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, out.c_str()); 
        } else {
           curl_easy_setopt(d_c, CURLOPT_POST, 1);
           curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, 0); 
        }
    } else if (method == "replaceRRSet") {
        std::stringstream ss2;
        size_t index = 0;
        for(rapidjson::Value::ConstValueIterator itr = parameters["rrset"].Begin(); itr != parameters["rrset"].End(); itr++) {
            index++;
            ss2 << buildMemberListArgs("rrset[" + boost::lexical_cast<std::string>(index) + "]", itr, d_c);
        }
        // then give it to curl
        std::string out = ss2.str();
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, out.size());
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, out.c_str());
    } else if (method == "feedRecord") {
        std::string out = buildMemberListArgs("rr", &parameters["rr"], d_c);
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, out.size());
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, out.c_str());
    } else if (method == "feedEnts") {
        std::stringstream ss2;
        for(rapidjson::Value::ConstValueIterator itr = parameters["nonterm"].Begin(); itr != parameters["nonterm"].End(); itr++) {
          tmpstr = curl_easy_escape(d_c, itr->GetString(), 0);
          ss2 << "nonterm[]=" << tmpstr << "&";
          curl_free(tmpstr);
        }
        std::string out = ss2.str();
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, out.size());
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, out.c_str());
    } else if (method == "feedEnts3") {
        std::stringstream ss2;
        addUrlComponent(parameters, "domain", ss);
        ss2 << "times=" << parameters["times"].GetInt() << "&salt=" << parameters["salt"].GetString() << "&narrow=" << (parameters["narrow"].GetBool() ? 1 : 0) << "&";
        for(rapidjson::Value::ConstValueIterator itr = parameters["nonterm"].Begin(); itr != parameters["nonterm"].End(); itr++) {
          tmpstr = curl_easy_escape(d_c, itr->GetString(), 0);
          ss2 << "nonterm[]=" << tmpstr << "&";
          curl_free(tmpstr);
        }
        std::string out = ss2.str();
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, out.size());
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, out.c_str());
    } else if (method == "startTransaction") {
        addUrlComponent(parameters, "domain", ss);
        addUrlComponent(parameters, "trxid", ss);
        curl_easy_setopt(d_c, CURLOPT_POST, 1);
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, 0);
    } else if (method == "commitTransaction" || method == "abortTransaction") {
        addUrlComponent(parameters, "trxid", ss);
        curl_easy_setopt(d_c, CURLOPT_POST, 1);
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, 0);
    } else if (method == "calculateSOASerial") {
        addUrlComponent(parameters, "domain", ss);
        std::string out = buildMemberListArgs("sd", &parameters["sd"], d_c);
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, out.size());
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, out.c_str());
    } else if (method == "setDomainMetadata") {
        // copy all metadata values into post
        std::stringstream ss2;
        const rapidjson::Value& param = parameters["value"];
        curl_easy_setopt(d_c, CURLOPT_POST, 1);
        // this one has values too
        if (param.IsArray()) {
           for(rapidjson::Value::ConstValueIterator i = param.Begin(); i != param.End(); i++) {
              ss2 << "value[]=" << i->GetString() << "&";
           }
        }
        sparam = ss2.str();
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, sparam.size());
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, sparam.c_str());
    } else if (method == "removeDomainKey") {
        // this one is delete
        curl_easy_setopt(d_c, CURLOPT_CUSTOMREQUEST, "DELETE");
    } else if (method == "setNotified") {
        tmpstr = (char*)malloc(128);
        snprintf(tmpstr, 128, "serial=%u", parameters["serial"].GetInt());
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, strlen(tmpstr));
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, tmpstr);
        free(tmpstr);
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
      if (json2string(parameters[member], sparam)) {
         snprintf(header, sizeof header, "X-RemoteBackend-%s: %s", iter->name.GetString(), sparam.c_str());
         (*slist) = curl_slist_append((*slist), header);
      }
    };

    // finally add suffix and store url
    ss << d_url_suffix;
    curl_easy_setopt(d_c, CURLOPT_URL, ss.str().c_str());

    // store headers into request
    curl_easy_setopt(d_c, CURLOPT_HTTPHEADER, *slist); 
}

void HTTPConnector::post_requestbuilder(const rapidjson::Document &input, struct curl_slist **slist) {
    if (this->d_post_json) {
        // simple case, POST JSON into url. nothing fancy. 
        std::string out = makeStringFromDocument(input);
        (*slist) = curl_slist_append((*slist), "Content-Type: text/javascript; charset=utf-8");
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, out.size());
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, out.c_str());
        curl_easy_setopt(d_c, CURLOPT_URL, d_url.c_str());
        curl_easy_setopt(d_c, CURLOPT_HTTPHEADER, *slist);
    } else {
        std::stringstream url,content;
        char *tmpstr;
        // call url/method.suffix
        rapidjson::StringBuffer output;
        rapidjson::Writer<rapidjson::StringBuffer> w(output);
        input["parameters"].Accept(w);
        url << d_url << "/" << input["method"].GetString() << d_url_suffix;
        // then build content
        tmpstr = curl_easy_escape(d_c, output.GetString(), 0);
        content << "parameters=" << tmpstr;
        // convert into parameters=urlencoded
        curl_easy_setopt(d_c, CURLOPT_POSTFIELDSIZE, content.str().size());
        curl_easy_setopt(d_c, CURLOPT_COPYPOSTFIELDS, content.str().c_str());
        free(tmpstr);
        curl_easy_setopt(d_c, CURLOPT_URL, d_url.c_str());
        curl_easy_setopt(d_c, CURLOPT_URL, url.str().c_str());
    }
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

    // build request based on mode
    
    if (d_post) 
      post_requestbuilder(input, &slist);
    else
      restful_requestbuilder(input["method"].GetString(), input["parameters"], &slist);

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
