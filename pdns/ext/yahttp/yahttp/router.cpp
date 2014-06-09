/* @file
 * @brief Concrete implementation of Router 
 */
#include "yahttp.hpp"
#include "router.hpp"

namespace YaHTTP {
  typedef funcptr::tuple<int,int> TDelim;

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

  bool Router::route(Request *req, THandlerFunction& handler) {
    std::map<std::string, TDelim> params;
    int pos1,pos2;
    std::string pname;
    bool matched = false;
    std::string rname;

    // iterate routes
    for(TRouteList::iterator i = routes.begin(); !matched && i != routes.end(); i++) {
      int k1,k2,k3;
      std::string pname;
      std::string method, url;
      funcptr::tie(method, url, handler, rname) = *i;
    
      if (method.empty() == false && req->method != method) continue; // no match on method
      // see if we can't match the url
      params.clear();
      // simple matcher func
      for(k1=0, k2=0; k1 < static_cast<int>(url.size()) && k2 < static_cast<int>(req->url.path.size()); ) {
        if (url[k1] == '<') {
          pos1 = k2;
          k3 = k1+1;
          // start of parameter
          while(k1 < static_cast<int>(url.size()) && url[k1] != '>') k1++;
          pname = std::string(url.begin()+k3, url.begin()+k1);
          // then we also look it on the url
          if (pname[0]=='*') {
            pname = pname.substr(1);
            // this matches whatever comes after it, basically end of string
            pos2 = req->url.path.size();
            matched = true;
            if (pname != "") 
              params[pname] = funcptr::tie(pos1,pos2);
            k1 = url.size();
            k2 = req->url.path.size();
            break;
          } else { 
            // match until url[k1]
            while(k2 < static_cast<int>(req->url.path.size()) && req->url.path[k2] != url[k1+1]) k2++;
            pos2 = k2;
            params[pname] = funcptr::tie(pos1,pos2);
          }
          k2--;
        }
        else if (url[k1] != req->url.path[k2]) {
          break;
        }

        k1++; k2++;
      }

      // ensure.
      if (url[k1] != req->url.path[k2]) 
        matched = false;
      else
        matched = true;
    }

    if (!matched) { return false; } // no route
    req->parameters.clear();    

    for(std::map<std::string, TDelim>::iterator i = params.begin(); i != params.end(); i++) {
      int p1,p2;
      funcptr::tie(p1,p2) = i->second;
      std::string value(req->url.path.begin() + p1, req->url.path.begin() + p2);
      value = Utility::decodeURL(value);
      req->parameters[i->first] = value;
    }

    req->routeName = rname;

    return true;
  };

  void Router::printRoutes(std::ostream &os) {
    for(TRouteList::iterator i = routes.begin(); i != routes.end(); i++) {
#ifdef HAVE_CXX11
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
#ifdef HAVE_CXX11
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
    std::cout << mask.substr(k3) << std::endl;
    path << mask.substr(k3);
    result = path.str();
    return std::make_pair(method, result);
  }
};
