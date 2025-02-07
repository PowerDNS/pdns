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

#pragma once
#include <string>

#include <curl/curlver.h>
#if defined(LIBCURL_VERSION_NUM) && LIBCURL_VERSION_NUM >= 0x073200
/* we need this so that 'CURL' is not typedef'd to void,
   which prevents us from wrapping it in a unique_ptr.
   Wrapping in a shared_ptr is fine because of type erasure,
   but it is a bit wasteful. */
#define CURL_STRICTER 1
#endif
#include <curl/curl.h>
#include "iputils.hh"

class MiniCurl
{
public:
  using MiniCurlHeaders = std::map<std::string, std::string>;

  static void init();

  MiniCurl(const string& useragent="MiniCurl/0.0", bool failonerror=true);
  ~MiniCurl();
  MiniCurl& operator=(const MiniCurl&) = delete;

  std::string getURL(const std::string& str, const ComboAddress* rem=nullptr, const ComboAddress* src=nullptr, int timeout = 2, bool fastopen = false, bool verify = false, size_t byteslimit = 0, int http_status = 200);
  std::string postURL(const std::string& str, const std::string& postdata, MiniCurlHeaders& headers, int timeout = 2, bool fastopen = false, bool verify = false);

private:
  static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata);
#if defined(LIBCURL_VERSION_NUM) && LIBCURL_VERSION_NUM >= 0x072000 // 7.32.0
  static size_t progress_callback(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow);
#else
  static size_t progress_callback(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow);
#endif

#ifdef CURL_STRICTER
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> d_curl{nullptr, curl_easy_cleanup};
  std::unique_ptr<struct curl_slist, decltype(&curl_slist_free_all)> d_header_list{nullptr, curl_slist_free_all};
  std::unique_ptr<struct curl_slist, decltype(&curl_slist_free_all)> d_host_list{nullptr, curl_slist_free_all};
#else
  CURL* d_curl{};
  struct curl_slist* d_header_list{};
  struct curl_slist* d_host_list{};
#endif
  std::string d_data;
  size_t d_byteslimit{};
  bool d_fresh{true};
  bool d_failonerror;

  void setupURL(const std::string& str, const ComboAddress* rem, const ComboAddress* src, int timeout, size_t byteslimit, bool fastopen, bool verify);
  void setHeaders(const MiniCurlHeaders& headers);
  void clearHeaders();
  void clearHostsList();
};
