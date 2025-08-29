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

  void Router::printRoutes(std::ostream &os) {
    for(TRouteList::iterator i = routes.begin(); i != routes.end(); i++) {
#if __cplusplus >= 201103L
      std::streamsize ss = os.width();
      std::ios::fmtflags ff = os.setf(std::ios::left);
      os.width(10);
      os << std::get<0>(*i);
      os.width(50);
      os << std::get<1>(*i);
      os.width(ss);
      os.setf(ff);
      os << "    " << std::get<3>(*i);
      os << std::endl;
#else
      os << i->get<0>() << "    " << i->get<1>() << "    " << i->get<3>() << std::endl;
#endif
    } 
  };

  std::pair<std::string,std::string> Router::urlFor(const std::string &name, const strstr_map_t& arguments) {
    std::ostringstream path;
    std::string mask,method,result;
    int k1,k2,k3;

    bool found = false;
    for(TRouteList::iterator i = routes.begin(); !found && i != routes.end(); i++) {
#if __cplusplus >= 201103L
      if (std::get<3>(*i) == name) { mask = std::get<1>(*i); method = std::get<0>(*i); found = true; }
#else
      if (i->get<3>() == name) { mask = i->get<1>(); method = i->get<0>(); found = true; }
#endif
    }

    if (!found)
      throw Error("Route not found");

    for(k1=0,k3=0;k1<static_cast<int>(mask.size());k1++) {
      if (mask[k1] == '<') {
        std::string pname;
        strstr_map_t::const_iterator pptr;
        k2=k1;
        while(k1<static_cast<int>(mask.size()) && mask[k1]!='>') k1++;
        path << mask.substr(k3,k2-k3);
        if (mask[k2+1] == '*')
          pname = std::string(mask.begin() + k2 + 2, mask.begin() + k1);
        else 
          pname = std::string(mask.begin() + k2 + 1, mask.begin() + k1);
        if ((pptr = arguments.find(pname)) != arguments.end()) 
          path << Utility::encodeURL(pptr->second);
        k3 = k1+1;
      }
      else if (mask[k1] == '*') {
        // ready 
        k3++;
        continue;
      }
    }
    path << mask.substr(k3);
    result = path.str();
    return std::make_pair(method, result);
  }
};
