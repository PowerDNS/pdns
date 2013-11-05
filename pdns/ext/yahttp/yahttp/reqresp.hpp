#include <map>
#include <iostream>
#include <locale>
#include <algorithm>

#include "url.hpp"
#include "utility.hpp"
#include "exception.hpp"

#ifndef YAHTTP_MAX_REQUEST_SIZE 
#define YAHTTP_MAX_REQUEST_SIZE 2097152
#endif

namespace YaHTTP {
  typedef std::map<std::string,std::string> strstr_map_t;

  class Response;
  class Request;
  class AsyncResponseLoader;
  class AsyncRequestLoader;

  class Request {
  public:
     Request();
     Request(const Response &resp);
     Request(const Request &req);
     ~Request();

     void build(const std::string &method, const std::string &url, const std::string &params);

     void load(std::istream &is);
     void write(std::ostream &os) const;

     strstr_map_t headers;
     strstr_map_t parameters;
     strstr_map_t cookies;

     URL url;
     std::string method;
     std::string body;

     friend std::istream& operator>>(std::istream& os, const Request &req);
     friend std::ostream& operator<<(std::ostream& os, const Request &req);
     friend class AsyncRequestLoader;
  };

  class Response {
  public:
     Response();
     Response(const Request &req);
     Response(const Response &resp);
     ~Response();
     void load(std::istream &is);
     void write(std::ostream &os) const;

     strstr_map_t headers;
     strstr_map_t parameters;
     strstr_map_t cookies;

     URL url;
     int status;
     std::string statusText;
     std::string method;
     std::string body;

     friend std::istream& operator>>(std::istream& is, Response &resp);
     friend std::ostream& operator<<(std::ostream& os, const Response &resp);
     friend class AsyncResponseLoader;
  };

  class AsyncResponseLoader {
  public:
    AsyncResponseLoader(Response *response) {
      state = 0;
      chunked = false;
      chunk_size = 0;
      this->response = response;
    };
    bool feed(const std::string &somedata);
  private:
    Response *response;
    int state;
    std::string buffer;
    bool chunked;
    int chunk_size;
    std::ostringstream bodybuf;
  };

  class AsyncRequestLoader {
  public:
    AsyncRequestLoader(Request *request) {
      state = 0;
      chunked = false;
      chunk_size = 0;
      maxbody = 0;
      this->request = request;
    };
    bool feed(const std::string &somedata);
  private:
    Request *request;
    int state;
    std::string buffer;
    bool chunked;
    int chunk_size;
    std::ostringstream bodybuf;
    long maxbody;
  };
};
