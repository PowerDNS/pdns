#pragma once
/* @file 
 * @brief Defines router class and support structures
 */
#if __cplusplus >= 201103L
#include <functional>
#include <tuple>
#define HAVE_CPP_FUNC_PTR
#define IGNORE std::ignore
namespace funcptr = std;
#else
#ifdef HAVE_BOOST
#include <boost/function.hpp>
#include <boost/tuple/tuple.hpp>
#define IGNORE boost::tuples::ignore
namespace funcptr = boost;
#define HAVE_CPP_FUNC_PTR
#else
#warning "You need to configure with boost or have C++11 capable compiler for router"
#endif
#endif

#ifdef HAVE_CPP_FUNC_PTR
#include <vector>
#include <utility>

namespace YaHTTP {
  enum RoutingResult {
    RouteFound = 1,
    RouteNotFound = 0,
    RouteNoMethod = -1,
  };

  typedef funcptr::function <void(Request* req, Response* resp)> THandlerFunction; //!< Handler function pointer 
  typedef funcptr::tuple<std::string, std::string, THandlerFunction, std::string> TRoute; //!< Route tuple (method, urlmask, handler, name)
  typedef std::vector<TRoute> TRouteList; //!< List of routes in order of evaluation
  typedef funcptr::tuple<int,int> TDelim;

  /*! Implements simple router.

This class implements a router for masked urls. The URL mask syntax is as of follows

/&lt;masked&gt;/url&lt;number&gt;/&lt;hi&gt;.&lt;format&gt;

You can use &lt;*param&gt; to denote that everything will be matched and consumed into the parameter, including slash (/). Use &lt;*&gt; to denote that URL 
is consumed but not stored. Note that only path is matched, scheme, host and url parameters are ignored. 
   */
  class Router {
  private:
    Router() {}; 
    static Router router; //<! Singleton instance of Router
  public:
    void map(const std::string& method, const std::string& url, THandlerFunction handler, const std::string& name); //<! Instance method for mapping urls
    RoutingResult route(Request *req, THandlerFunction& handler); //<! Instance method for performing routing
    void printRoutes(std::ostream &os); //<! Instance method for printing routes
    std::pair<std::string, std::string> urlFor(const std::string &name, const strstr_map_t& arguments); //<! Instance method for generating paths
    static bool match(const std::string& route, const URL& requrl, std::map<std::string, TDelim>& params); //<! Instance method for matching a route

/*! Map an URL.
If method is left empty, it will match any method. Name is also optional, but needed if you want to find it for making URLs
*/
    static void Map(const std::string& method, const std::string& url, THandlerFunction handler, const std::string& name = "") { router.map(method, url, std::move(handler), name); };
    static void Get(const std::string& url, THandlerFunction handler, const std::string& name = "") { router.map("GET", url, std::move(handler), name); }; //<! Helper for mapping GET
    static void Post(const std::string& url, THandlerFunction handler, const std::string& name = "") { router.map("POST", url, std::move(handler), name); }; //<! Helper for mapping POST
    static void Put(const std::string& url, THandlerFunction handler, const std::string& name = "") { router.map("PUT", url, std::move(handler), name); }; //<! Helper for mapping PUT
    static void Patch(const std::string& url, THandlerFunction handler, const std::string& name = "") { router.map("PATCH", url, std::move(handler), name); }; //<! Helper for mapping PATCH
    static void Delete(const std::string& url, THandlerFunction handler, const std::string& name = "") { router.map("DELETE", url, std::move(handler), name); }; //<! Helper for mapping DELETE
    static void Any(const std::string& url, THandlerFunction handler, const std::string& name = "") { router.map("", url, std::move(handler), name); }; //<! Helper for mapping any method

    static bool Match(const std::string& route, const URL& requrl, std::map<std::string, TDelim>& params) { return router.match(route, requrl, params); };
    static RoutingResult Route(Request *req, THandlerFunction& handler) { return router.route(req, handler); }; //<! Performs routing based on req->url.path, returns RouteFound if route is found and method matches, RouteNoMethod if route is seen but method did match, and RouteNotFound if not found.
    static void PrintRoutes(std::ostream &os) { router.printRoutes(os); }; //<! Prints all known routes to given output stream

    static std::pair<std::string, std::string> URLFor(const std::string &name, const strstr_map_t& arguments) { return router.urlFor(name,arguments); }; //<! Generates url from named route and arguments. Missing arguments are assumed empty
    static const TRouteList& GetRoutes() { return router.routes; } //<! Reference to route list
    static void Clear() { router.routes.clear(); } //<! Clear all routes

    TRouteList routes; //<! Instance variable for routes
  };
};
#endif
