/* @file
 * @brief Concrete implementation of Router 
 */
#include "yahttp.hpp"
#include "router.hpp"

namespace YaHTTP {
  // router is defined here.
  YaHTTP::Router Router::router;

  void Router::map(const std::string& method, const std::string& url, THandlerFunction handler, const std::string& name) {
    std::string method2 = method;
    bool isopen=false;
    // add into vector
    for(std::string::const_iterator i = url.begin(); i != url.end(); i++) {
       if (*i == '<' && isopen) throw Error("Invalid URL mask, cannot have < after <");
       if (*i == '<') isopen = true;
       if (*i == '>' && !isopen) throw Error("Invalid URL mask, cannot have > without < first");
       if (*i == '>') isopen = false;
    }
    std::transform(method2.begin(), method2.end(), method2.begin(), ::toupper); 
    routes.push_back(funcptr::make_tuple(method2, url, handler, name));
  };

  bool Router::match(const std::string& route, const URL& requrl, std::map<std::string, TDelim> &params) {
     size_t rpos = 0;
     size_t upos = 0;
     size_t npos = 0;
     size_t nstart = 0;
     size_t nend = 0;
     std::string pname;
     for(; rpos < route.size() && upos < requrl.path.size(); ) {
        if (route[rpos] == '<') {
          nstart = upos;
          npos = rpos+1;
          // start of parameter
          while(rpos < route.size() && route[rpos] != '>') {
            rpos++;
          }
          pname = std::string(route.begin()+static_cast<long>(npos), route.begin()+static_cast<long>(rpos));
          // then we also look it on the url
          if (pname[0] == '*') {
            pname = pname.substr(1);
            // this matches whatever comes after it, basically end of string
            nend = requrl.path.size();
            if (!pname.empty()) {
              params[pname] = funcptr::tie(nstart,nend);
            }
            rpos = route.size();
            upos = requrl.path.size();
            break;
          }
          // match until url[upos] or next / if pattern is at end
          while (upos < requrl.path.size()) {
            if (route[rpos+1] == '\0' && requrl.path[upos] == '/') {
              break;
            }
            if (requrl.path[upos] == route[rpos+1]) {
              break;
            }
            upos++;
          }
          nend = upos;
          params[pname] = funcptr::tie(nstart, nend);
          if (upos > 0) {
            upos--;
          }
          else {
            // If upos is zero, do not decrement it and then increment at bottom of loop, this disturbs Coverity.
            // Only increment rpos and continue loop
            rpos++;
            continue;
          }
        }
        else if (route[rpos] != requrl.path[upos]) {
          break;
        }

        rpos++; upos++;
      }
      return route[rpos] == requrl.path[upos];
  }

  RoutingResult Router::route(Request *req, THandlerFunction& handler) {
    std::map<std::string, TDelim> params;
    bool matched = false;
    bool seen = false;
    std::string rname;

    // iterate routes
    for (auto& route: routes) {
      std::string method;
      std::string url;
      funcptr::tie(method, url, handler, rname) = route;

      // see if we can't match the url
      params.clear();
      // simple matcher func
      matched = match(url, req->url, params);

      if (matched && !method.empty() && req->method != method) {
         // method did not match, record it though so we can return correct result
         matched = false;
         // The OPTIONS handler registered in pdns/webserver.cc matches every
         // url, and would cause "not found" errors to always be superseded
         // with "found, but wrong method" errors, so don't pretend there has
         // been a match in this case.
         if (method != "OPTIONS") {
           seen = true;
         }
         continue;
      }
      if (matched) {
        break;
      }
    }

    if (!matched) {
      if (seen) {
        return RouteNoMethod;
      }
      // no route
      return RouteNotFound;
    }

    req->parameters.clear();

    for (const auto& param: params) {
      int nstart = 0;
      int nend = 0;
      funcptr::tie(nstart, nend) = param.second;
      std::string value(req->url.path.begin() + nstart, req->url.path.begin() + nend);
      value = Utility::decodeURL(value);
      req->parameters[param.first] = std::move(value);
    }

    req->routeName = std::move(rname);

    return RouteFound;
  };

};
