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
#include <stdexcept>
#include <boost/format.hpp>

#ifdef CURL_STRICTER
#define getCURLPtr(x) \
  x.get()
#else
#define getCURLPtr(x) \
  x
#endif

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

MiniCurl::MiniCurl(const string& useragent, bool failonerror) : d_failonerror(failonerror)
{
#ifdef CURL_STRICTER
  d_curl = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>(curl_easy_init(), curl_easy_cleanup);
#else
  d_curl = curl_easy_init();
#endif
  if (d_curl == nullptr) {
    throw std::runtime_error("Error creating a MiniCurl session");
  }
  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_USERAGENT, useragent.c_str());
}

MiniCurl::~MiniCurl()
{
  clearHeaders();
  clearHostsList();
#ifndef CURL_STRICTER
  curl_easy_cleanup(d_curl);
#endif
}

size_t MiniCurl::write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  if (userdata != nullptr) {
    MiniCurl* us = static_cast<MiniCurl*>(userdata);
    us->d_data.append(ptr, size * nmemb);
    return size * nmemb;
  }
  return 0;
}

#if defined(LIBCURL_VERSION_NUM) && LIBCURL_VERSION_NUM >= 0x072000 // 7.32.0
size_t MiniCurl::progress_callback(void *clientp, curl_off_t /* dltotal */, curl_off_t dlnow, curl_off_t /* ultotal */, curl_off_t /* ulnow */)
{
  if (clientp != nullptr) {
    MiniCurl* us = static_cast<MiniCurl*>(clientp);
    if (us->d_byteslimit > 0 && static_cast<size_t>(dlnow) > us->d_byteslimit) {
      return static_cast<size_t>(dlnow);
    }
  }
  return 0;
}
#else
size_t MiniCurl::progress_callback(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow)
{
  if (clientp != nullptr) {
    MiniCurl* us = static_cast<MiniCurl*>(clientp);
    if (us->d_byteslimit > 0 && dlnow > static_cast<double>(us->d_byteslimit)) {
      return static_cast<size_t>(dlnow);
    }
  }
  return 0;
}
#endif

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

void MiniCurl::setupURL(const std::string& str, const ComboAddress* rem, const ComboAddress* src, int timeout, size_t byteslimit, [[maybe_unused]] bool fastopen, bool verify)
{
  if (!d_fresh) {
    curl_easy_reset(getCURLPtr(d_curl));
  }
  else {
    d_fresh = false;
  }

  clearHostsList();

  if (rem) {
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

#ifdef CURL_STRICTER
    d_host_list = std::unique_ptr<struct curl_slist, decltype(&curl_slist_free_all)>(hostlist, curl_slist_free_all);
#else
    d_host_list = hostlist;
#endif

    curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_RESOLVE, getCURLPtr(d_host_list));
  }
  if(src) {
    curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_INTERFACE, src->toString().c_str());
  }
  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_FOLLOWLOCATION, true);

  /* only allow HTTP and HTTPS */
#if defined(LIBCURL_VERSION_NUM) && LIBCURL_VERSION_NUM >= 0x075500 // 7.85.0
  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_PROTOCOLS_STR, "http,https");
#else
  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif

  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_SSL_VERIFYPEER, verify);
  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_SSL_VERIFYHOST, verify ? 2 : 0);
  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_FAILONERROR, d_failonerror);
  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_URL, str.c_str());
  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_WRITEDATA, this);

  d_byteslimit = byteslimit;
  if (d_byteslimit > 0) {
    /* enable progress meter */
    curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_NOPROGRESS, 0L);
#if defined(LIBCURL_VERSION_NUM) && LIBCURL_VERSION_NUM >= 0x072000 // 7.32.0
    curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_XFERINFOFUNCTION, progress_callback);
    curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_XFERINFODATA, this);
#else
    curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_PROGRESSFUNCTION, progress_callback);
    curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_PROGRESSDATA, this);
#endif
  }

  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_TIMEOUT, static_cast<long>(timeout));
#if defined(CURL_AT_LEAST_VERSION)
#if CURL_AT_LEAST_VERSION(7, 49, 0) && defined(__linux__)
  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_TCP_FASTOPEN, fastopen);
#endif
#endif
  clearHeaders();
  d_data.clear();
}

std::string MiniCurl::getURL(const std::string& str, const ComboAddress* rem, const ComboAddress* src, int timeout, [[maybe_unused]] bool fastopen, bool verify, size_t byteslimit, int http_status)
{
  setupURL(str, rem, src, timeout, byteslimit, fastopen, verify);
  auto res = curl_easy_perform(getCURLPtr(d_curl));
  long http_code = 0;
  curl_easy_getinfo(getCURLPtr(d_curl), CURLINFO_RESPONSE_CODE, &http_code);

  if ((res != CURLE_OK && res != CURLE_ABORTED_BY_CALLBACK) || http_code != http_status)  {
    throw std::runtime_error("Unable to retrieve URL ("+std::to_string(http_code)+"): "+string(curl_easy_strerror(res)));
  }
  std::string ret = d_data;
  d_data.clear();
  return ret;
}

std::string MiniCurl::postURL(const std::string& str, const std::string& postdata, MiniCurlHeaders& headers, int timeout, bool fastopen, bool verify)
{
  setupURL(str, nullptr, nullptr, timeout, 0, fastopen, verify);
  setHeaders(headers);
  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_POSTFIELDSIZE, postdata.size());
  curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_POSTFIELDS, postdata.c_str());

  auto res = curl_easy_perform(getCURLPtr(d_curl));

  long http_code = 0;
  curl_easy_getinfo(getCURLPtr(d_curl), CURLINFO_RESPONSE_CODE, &http_code);

  if(res != CURLE_OK)
    throw std::runtime_error("Unable to post URL ("+std::to_string(http_code)+"): "+string(curl_easy_strerror(res)));

  std::string ret=d_data;

  d_data.clear();
  return ret;
}

void MiniCurl::clearHeaders()
{
  if (d_curl) {
    curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_HTTPHEADER, nullptr);
#ifdef CURL_STRICTER
    d_header_list.reset();
#else
    curl_slist_free_all(d_header_list);
    d_header_list = nullptr;
#endif
  }
}

void MiniCurl::clearHostsList()
{
  if (d_curl) {
    curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_RESOLVE, nullptr);
#ifdef CURL_STRICTER
    d_host_list.reset();
#else
    curl_slist_free_all(d_host_list);
    d_host_list = nullptr;
#endif
  }
}

void MiniCurl::setHeaders(const MiniCurlHeaders& headers)
{
  if (d_curl) {
    for (auto& header : headers) {
      std::stringstream header_ss;
      header_ss << header.first << ": " << header.second;
#ifdef CURL_STRICTER
      struct curl_slist * list = nullptr;
      if (d_header_list) {
        list = d_header_list.release();
      }
      d_header_list = std::unique_ptr<struct curl_slist, decltype(&curl_slist_free_all)>(curl_slist_append(list, header_ss.str().c_str()), curl_slist_free_all);
#else
      d_header_list = curl_slist_append(d_header_list, header_ss.str().c_str());
#endif
    }
    curl_easy_setopt(getCURLPtr(d_curl), CURLOPT_HTTPHEADER, getCURLPtr(d_header_list));
  }
}
