/*
 * MIT License
 *
 * Copyright (c) 2018-2019 powerdns.com bv
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "minicurl.hh"
#include <curl/curl.h>
#include <stdexcept>

void MiniCurl::init()
{
  static std::atomic_flag s_init = ATOMIC_FLAG_INIT;

  if (s_init.test_and_set())
    return;

  CURLcode code = curl_global_init(CURL_GLOBAL_ALL);
  if (code != 0) {
    throw std::runtime_error("Error initializing libcurl");
  }
}

MiniCurl::MiniCurl(const string& useragent)
{
  d_curl = curl_easy_init();
  if (d_curl == nullptr) {
    throw std::runtime_error("Error creating a MiniCurl session");
  }
  curl_easy_setopt(d_curl, CURLOPT_USERAGENT, useragent.c_str());
}

MiniCurl::~MiniCurl()
{
  // NEEDS TO CLEAN HOSTLIST
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

void MiniCurl::setupURL(const std::string& str, const ComboAddress* rem, const ComboAddress* src)
{
  if(rem) {
    struct curl_slist *hostlist = nullptr; // THIS SHOULD BE FREED

    // url = http://hostname.enzo/url
    string host4=extractHostFromURL(str);
    // doest the host contain port indication
    std::size_t found = host4.find(':');
    vector<uint16_t> ports{80, 443};
    if (found != std::string::npos) {
      int port = std::stoi(host4.substr(found + 1));
      if (port <= 0 || port > 65535)
        throw std::overflow_error("Invalid port number");
      ports = {(uint16_t)port};
      host4 = host4.substr(0, found);
    }

    for (const auto& port : ports) {
      string hcode = boost::str(boost::format("%s:%u:%s") % host4 % port % rem->toString());
      hostlist = curl_slist_append(hostlist, hcode.c_str());
    }

    curl_easy_setopt(d_curl, CURLOPT_RESOLVE, hostlist);
  }
  if(src) {
    curl_easy_setopt(d_curl, CURLOPT_INTERFACE, src->toString().c_str());
  }
  curl_easy_setopt(d_curl, CURLOPT_FOLLOWLOCATION, true);
  /* only allow HTTP and HTTPS */
  curl_easy_setopt(d_curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
  curl_easy_setopt(d_curl, CURLOPT_SSL_VERIFYPEER, false);
  curl_easy_setopt(d_curl, CURLOPT_SSL_VERIFYHOST, false);
  curl_easy_setopt(d_curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(d_curl, CURLOPT_URL, str.c_str());
  curl_easy_setopt(d_curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(d_curl, CURLOPT_WRITEDATA, this);
  curl_easy_setopt(d_curl, CURLOPT_TIMEOUT, 2L);

  clearHeaders();
  d_data.clear();
}

std::string MiniCurl::getURL(const std::string& str, const ComboAddress* rem, const ComboAddress* src)
{
  setupURL(str, rem, src);
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

std::string MiniCurl::postURL(const std::string& str, const std::string& postdata, MiniCurlHeaders& headers)
{
  setupURL(str);
  setHeaders(headers);
  curl_easy_setopt(d_curl, CURLOPT_POSTFIELDSIZE, postdata.size());
  curl_easy_setopt(d_curl, CURLOPT_POSTFIELDS, postdata.c_str());

  auto res = curl_easy_perform(d_curl);

  long http_code = 0;
  curl_easy_getinfo(d_curl, CURLINFO_RESPONSE_CODE, &http_code);

  if(res != CURLE_OK)
    throw std::runtime_error("Unable to post URL ("+std::to_string(http_code)+"): "+string(curl_easy_strerror(res)));

  std::string ret=d_data;

  d_data.clear();
  return ret;
}

void MiniCurl::clearHeaders()
{
  if (d_curl) {
    curl_easy_setopt(d_curl, CURLOPT_HTTPHEADER, NULL);
    if (d_header_list != nullptr) {
      curl_slist_free_all(d_header_list);
      d_header_list = nullptr;
    }
  }
}

void MiniCurl::setHeaders(const MiniCurlHeaders& headers)
{
  if (d_curl) {
    for (auto& header : headers) {
      std::stringstream header_ss;
      header_ss << header.first << ": " << header.second;
      d_header_list = curl_slist_append(d_header_list, header_ss.str().c_str());
    }
    curl_easy_setopt(d_curl, CURLOPT_HTTPHEADER, d_header_list);
  }
}
