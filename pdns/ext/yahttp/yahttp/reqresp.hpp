#ifdef HAVE_CXX11
#include <functional>
#define HAVE_CPP_FUNC_PTR
namespace funcptr = std;
#else
#ifdef HAVE_BOOST
#include <boost/function.hpp>
namespace funcptr = boost;
#define HAVE_CPP_FUNC_PTR
#endif
#endif

#include <fstream>
#include <cctype>

#ifndef WIN32
#include <cstdio>
#include <unistd.h>
#endif

#ifndef YAHTTP_MAX_REQUEST_SIZE
#define YAHTTP_MAX_REQUEST_SIZE 2097152
#endif

#ifndef YAHTTP_MAX_RESPONSE_SIZE
#define YAHTTP_MAX_RESPONSE_SIZE 2097152
#endif

#define YAHTTP_TYPE_REQUEST 1
#define YAHTTP_TYPE_RESPONSE 2

namespace YaHTTP {
  typedef std::map<std::string,std::string> strstr_map_t;
  typedef std::map<std::string,Cookie> strcookie_map_t;

  typedef enum {
    urlencoded,
    multipart
  } postformat_t;

  class HTTPBase {
  public:
#ifdef HAVE_CPP_FUNC_PTR
    class SendBodyRender {
    public:
      SendBodyRender() {};

      size_t operator()(const HTTPBase *doc, std::ostream& os) const {
        os << doc->body;
        return doc->body.length();
      };
    };
    class SendFileRender {
    public:
      SendFileRender(const std::string& path) {
        this->path = path;
      };
  
      size_t operator()(const HTTPBase *doc, std::ostream& os) const {
        char buf[4096];
        size_t n,k;
#ifdef HAVE_CXX11
        std::ifstream ifs(path, std::ifstream::binary);
#else
        std::ifstream ifs(path.c_str(), std::ifstream::binary);
#endif
        n = 0;
        while(ifs && ifs.good()) {
          ifs.read(buf, sizeof buf);
          n += (k = ifs.gcount());
          if (k)
            os.write(buf, k);
        }

        return n;
      };

      std::string path;
    };
#endif
    HTTPBase() {
#ifdef HAVE_CPP_FUNC_PTR
      renderer = SendBodyRender();
#endif
    };
protected:
    HTTPBase(const HTTPBase& rhs) {
      this->url = rhs.url; this->kind = rhs.kind;
      this->status = rhs.status; this->statusText = rhs.statusText;
      this->method = rhs.method; this->headers = rhs.headers;
      this->jar = rhs.jar; this->postvars = rhs.postvars;
      this->parameters = rhs.parameters; this->getvars = rhs.getvars;
      this->body = rhs.body;
#ifdef HAVE_CPP_FUNC_PTR
      this->renderer = rhs.renderer;
#endif
    };
    HTTPBase& operator=(const HTTPBase& rhs) {
      this->url = rhs.url; this->kind = rhs.kind;
      this->status = rhs.status; this->statusText = rhs.statusText;
      this->method = rhs.method; this->headers = rhs.headers;
      this->jar = rhs.jar; this->postvars = rhs.postvars;
      this->parameters = rhs.parameters; this->getvars = rhs.getvars;
      this->body = rhs.body;
#ifdef HAVE_CPP_FUNC_PTR
      this->renderer = rhs.renderer;
#endif
      return *this;
    };
public:
    URL url;
    int kind;
    int status;
    std::string statusText;
    std::string method;
    strstr_map_t headers;
    CookieJar jar;
    strstr_map_t postvars;
    strstr_map_t getvars;
// these two are for Router
    strstr_map_t parameters;
    std::string routeName;

    std::string body;
 
#ifdef HAVE_CPP_FUNC_PTR
    funcptr::function<size_t(const HTTPBase*,std::ostream&)> renderer;
#endif
    void write(std::ostream& os) const;

    strstr_map_t& GET() { return getvars; };
    strstr_map_t& POST() { return postvars; };
    strcookie_map_t& COOKIES() { return jar.cookies; };
  };

  class Response: public HTTPBase { 
  public:
    Response() { this->kind = YAHTTP_TYPE_RESPONSE; };
    Response(const HTTPBase& rhs): HTTPBase(rhs) {
      this->kind = YAHTTP_TYPE_RESPONSE;
    };
    Response& operator=(const HTTPBase& rhs) {
      HTTPBase::operator=(rhs);
      this->kind = YAHTTP_TYPE_RESPONSE;
      return *this;
    }
    friend std::ostream& operator<<(std::ostream& os, const Response &resp);
    friend std::istream& operator>>(std::istream& is, Response &resp);
  };

  class Request: public HTTPBase {
  public:
    Request() { this->kind = YAHTTP_TYPE_REQUEST; };
    Request(const HTTPBase& rhs): HTTPBase(rhs) {
      this->kind = YAHTTP_TYPE_REQUEST;
    };
    Request& operator=(const HTTPBase& rhs) {
      HTTPBase::operator=(rhs);
      this->kind = YAHTTP_TYPE_REQUEST;
      return *this;
    }

    void setup(const std::string& method, const std::string& url) {
      this->url.parse(url);
      this->headers["host"] = this->url.host;
      this->method = method;
      std::transform(this->method.begin(), this->method.end(), this->method.begin(), ::toupper);
      this->headers["user-agent"] = "YaHTTP v1.0";
    }

    void preparePost(postformat_t format = urlencoded) {
      std::ostringstream postbuf;
      if (format == urlencoded) {
        for(strstr_map_t::const_iterator i = POST().begin(); i != POST().end(); i++) {
          postbuf << Utility::encodeURL(i->first) << "=" << Utility::encodeURL(i->second) << "&";
        }
        // remove last bit
        if (postbuf.str().length()>0) 
          body = std::string(postbuf.str().begin(), postbuf.str().end()-1);
        else
          body = "";
        headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
      } else if (format == multipart) {
        headers["content-type"] = "multipart/form-data; boundary=YaHTTP-12ca543";
        for(strstr_map_t::const_iterator i = POST().begin(); i != POST().end(); i++) {
          postbuf << "--YaHTTP-12ca543\r\nContent-Disposition: form-data; name=\"" << Utility::encodeURL(i->first) << "; charset=UTF-8\r\n\r\n"
            << Utility::encodeURL(i->second) << "\r\n";
        }
      }

      // set method and change headers
      method = "POST";
      headers["content-length"] = body.length();
    };

    friend std::ostream& operator<<(std::ostream& os, const Request &resp);
    friend std::istream& operator>>(std::istream& is, Request &resp);
  };

  template <class T>
  class AsyncLoader {
  public:
    T* target;
    int state;
    size_t pos;
    
    std::string buffer;
    bool chunked;
    int chunk_size;
    std::ostringstream bodybuf;
    size_t maxbody;
    size_t minbody;
    bool hasBody;

    void keyValuePair(const std::string &keyvalue, std::string &key, std::string &value);

    void initialize(T* target) {
      chunked = false; chunk_size = 0;
      bodybuf.str(""); maxbody = 0;
      pos = 0; state = 0; this->target = target; 
      hasBody = false;
    };
    int feed(const std::string& somedata);
    bool ready() {  return state > 1 && 
                      (!hasBody || 
                         (bodybuf.str().size() <= maxbody && 
                          bodybuf.str().size() >= minbody)
                      ); 
                 };
    void finalize() {
      bodybuf.flush();
      if (ready()) {
        strstr_map_t::iterator pos = target->headers.find("content-type");
        if (pos != target->headers.end() && Utility::iequals(pos->second, "application/x-www-form-urlencoded", 32)) {
          target->postvars = Utility::parseUrlParameters(bodybuf.str());
        }
        target->body = bodybuf.str();
      }
      bodybuf.str("");
      this->target = NULL;
    };
  };

  class AsyncResponseLoader: public AsyncLoader<Response> {
  };

  class AsyncRequestLoader: public AsyncLoader<Request> {
  };

};
