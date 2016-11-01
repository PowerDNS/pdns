#include "minicurl.hh"
#include <curl/curl.h>
#include <stdexcept>

MiniCurl::MiniCurl()
{
  d_curl = curl_easy_init();
}

MiniCurl::~MiniCurl()
{
  curl_easy_cleanup(d_curl);
}

size_t MiniCurl::write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  MiniCurl* us = (MiniCurl*)userdata;
  us->d_data.append(ptr, size*nmemb);
  return size*nmemb;
}

static string extractHostFromURL(const std::string& url)
{
  auto pos = url.find("://");
  if(pos == string::npos)
    throw runtime_error("Can't find host part of '"+url+"'");
  pos += 3;
  auto endpos = url.find('/', pos);
  if(endpos == string::npos)
    return url.substr(pos);

  return url.substr(pos, endpos-pos);
}

void MiniCurl::setupURL(const std::string& str, const ComboAddress* rem)
{
  if(rem) {
    struct curl_slist *hostlist = NULL;

    // url = http://hostname.enzo/url 

    string host4=extractHostFromURL(str);
    cout<<"Host name: '"<<host4<<"'"<<endl;
    string hcode=(host4+":80:"+rem->toString());
    //cout<<"Setting hardcoded IP: "<<hcode<<endl;
    hostlist = curl_slist_append(NULL, hcode.c_str());
    hcode=(host4+":443:"+rem->toString());
    //    cout<<"Setting hardcoded IP: "<<hcode<<endl;;
    hostlist = curl_slist_append(hostlist, hcode.c_str());

    curl_easy_setopt(d_curl, CURLOPT_RESOLVE, hostlist);
  }
  curl_easy_setopt(d_curl, CURLOPT_FOLLOWLOCATION, true);
  /* only allow HTTP, TFTP and SFTP */
  curl_easy_setopt(d_curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
  curl_easy_setopt(d_curl, CURLOPT_SSL_VERIFYPEER, false);
  curl_easy_setopt(d_curl, CURLOPT_SSL_VERIFYHOST, false);
  curl_easy_setopt(d_curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(d_curl, CURLOPT_URL, str.c_str());
  curl_easy_setopt(d_curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(d_curl, CURLOPT_WRITEDATA, this);

  
  d_data.clear();
}
std::string MiniCurl::getURL(const std::string& str, const ComboAddress* rem)
{
  setupURL(str, rem);
  auto res = curl_easy_perform(d_curl);
  long http_code = 0;
  curl_easy_getinfo(d_curl, CURLINFO_RESPONSE_CODE, &http_code);

  if(res != CURLE_OK || http_code != 200)  {
    throw std::runtime_error("Unable to retrieve URL ("+std::to_string(http_code)+"): "+string(curl_easy_strerror(res)));
  }
  std::string ret=d_data;
  d_data.clear();
  return ret;
}

std::string MiniCurl::postURL(const std::string& str, const std::string& postdata)
{
  setupURL(str);
  curl_easy_setopt(d_curl, CURLOPT_POSTFIELDS, postdata.c_str());

  auto res = curl_easy_perform(d_curl);
  if(res != CURLE_OK) 
    throw std::runtime_error("Unable to post URL");

  std::string ret=d_data;

  d_data.clear();
  return ret;
}
