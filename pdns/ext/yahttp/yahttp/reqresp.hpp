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

#include <algorithm>

#ifndef YAHTTP_MAX_REQUEST_SIZE
#define YAHTTP_MAX_REQUEST_SIZE 2097152
#endif

#ifndef YAHTTP_MAX_RESPONSE_SIZE
#define YAHTTP_MAX_RESPONSE_SIZE 2097152
#endif

#define YAHTTP_TYPE_REQUEST 1
#define YAHTTP_TYPE_RESPONSE 2

namespace YaHTTP {
  typedef std::map<std::string,Cookie,ASCIICINullSafeComparator> strcookie_map_t; //<! String to Cookie map

  typedef enum {
    urlencoded,
    multipart
  } postformat_t; //<! Enumeration of possible post encodings, url encoding or multipart

  /*! Base class for request and response */
  class HTTPBase {
  public:
    /*! Default renderer for request/response, simply copies body to response */
    class SendBodyRender {
    public:
      SendBodyRender() {};

      size_t operator()(const HTTPBase *doc, std::ostream& os, bool chunked) const {
        if (chunked) {
          std::string::size_type i,cl;
          for(i=0;i<doc->body.length();i+=1024) {
            cl = std::min(static_cast<std::string::size_type>(1024), doc->body.length()-i); // for less than 1k blocks
            os << std::hex << cl << std::dec << "\r\n";
            os << doc->body.substr(i, cl) << "\r\n";
          }
          os << 0 << "\r\n\r\n"; // last chunk
        } else {
          os << doc->body;
        }
        return doc->body.length();
      }; //<! writes body to ostream and returns length 
    };
    /* Simple sendfile renderer which streams file to ostream */
    class SendFileRender {
    public:
      SendFileRender(const std::string& path) {
        this->path = path;
      };
  
      size_t operator()(const HTTPBase *doc __attribute__((unused)), std::ostream& os, bool chunked) const {
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
          if (k) {
            if (chunked) os << std::hex << k << std::dec << "\r\n";
            os.write(buf, k);
            if (chunked) os << "\r\n"; 
          }
        }
        if (chunked) os << 0 << "\r\n\r\n";
        return n;
      }; //<! writes file to ostream and returns length

      std::string path; //<! File to send
    };

    HTTPBase() {
      initialize();
    };

    virtual void initialize() {
      kind = 0;
      status = 0;
#ifdef HAVE_CPP_FUNC_PTR
      renderer = SendBodyRender();
#endif
      max_request_size = YAHTTP_MAX_REQUEST_SIZE;
      max_response_size = YAHTTP_MAX_RESPONSE_SIZE;
      url = "";
      method = "";
      statusText = "";
      jar.clear();
      headers.clear();
      parameters.clear();
      getvars.clear();
      postvars.clear();
      body = "";
      routeName = "";
      version = 11; // default to version 1.1
    }
protected:
    HTTPBase(const HTTPBase& rhs) {
      this->url = rhs.url; this->kind = rhs.kind;
      this->status = rhs.status; this->statusText = rhs.statusText;
      this->method = rhs.method; this->headers = rhs.headers;
      this->jar = rhs.jar; this->postvars = rhs.postvars;
      this->parameters = rhs.parameters; this->getvars = rhs.getvars;
      this->body = rhs.body; this->max_request_size = rhs.max_request_size;
      this->max_response_size = rhs.max_response_size; this->version = rhs.version;
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
      this->body = rhs.body; this->max_request_size = rhs.max_request_size;
      this->max_response_size = rhs.max_response_size; this->version = rhs.version;
#ifdef HAVE_CPP_FUNC_PTR
      this->renderer = rhs.renderer;
#endif
      return *this;
    };
public:
    URL url; //<! URL of this request/response
    int kind; //<! Type of object (1 = request, 2 = response)
    int status; //<! status code 
    int version; //<! http version 9 = 0.9, 10 = 1.0, 11 = 1.1
    std::string statusText; //<! textual representation of status code
    std::string method; //<! http verb
    strstr_map_t headers; //<! map of header(s)
    CookieJar jar; //<! cookies 
    strstr_map_t postvars; //<! map of POST variables (from POST body)
    strstr_map_t getvars; //<! map of GET variables (from URL)
// these two are for Router
    strstr_map_t parameters; //<! map of route parameters (only if you use YaHTTP::Router)
    std::string routeName; //<! name of the current route (only if you use YaHTTP::Router)

    std::string body; //<! the actual content

    ssize_t max_request_size; //<! maximum size of request
    ssize_t max_response_size;  //<! maximum size of response
 
#ifdef HAVE_CPP_FUNC_PTR
    funcptr::function<size_t(const HTTPBase*,std::ostream&,bool)> renderer; //<! rendering function
#endif
    void write(std::ostream& os) const; //<! writes request to the given output stream

    strstr_map_t& GET() { return getvars; }; //<! acccessor for getvars
    strstr_map_t& POST() { return postvars; }; //<! accessor for postvars
    strcookie_map_t& COOKIES() { return jar.cookies; }; //<! accessor for cookies

    std::string versionStr(int version) const {
      switch(version) {
      case  9: return "0.9";
      case 10: return "1.0";
      case 11: return "1.1";
      default: throw YaHTTP::Error("Unsupported version");
      }
    };

    std::string str() const {
       std::ostringstream oss;
       write(oss);
       return oss.str();
    }; //<! return string representation of this object
  };

  /*! Response class, represents a HTTP Response document */
  class Response: public HTTPBase { 
  public:
    Response() { initialize(); };
    Response(const HTTPBase& rhs): HTTPBase(rhs) {
      this->kind = YAHTTP_TYPE_RESPONSE;
    };
    Response& operator=(const HTTPBase& rhs) {
      HTTPBase::operator=(rhs);
      this->kind = YAHTTP_TYPE_RESPONSE;
      return *this;
    };
    void initialize() {
      HTTPBase::initialize();
      this->kind = YAHTTP_TYPE_RESPONSE;
    }
    void initialize(const HTTPBase& rhs) {
      HTTPBase::initialize();
      this->kind = YAHTTP_TYPE_RESPONSE;
      // copy SOME attributes
      this->url = rhs.url;
      this->method = rhs.method;
      this->jar = rhs.jar;
      this->version = rhs.version;
    }
    friend std::ostream& operator<<(std::ostream& os, const Response &resp);
    friend std::istream& operator>>(std::istream& is, Response &resp);
  };

  /* Request class, represents a HTTP Request document */
  class Request: public HTTPBase {
  public:
    Request() { initialize(); };
    Request(const HTTPBase& rhs): HTTPBase(rhs) {
      this->kind = YAHTTP_TYPE_REQUEST;
    };
    Request& operator=(const HTTPBase& rhs) {
      HTTPBase::operator=(rhs);
      this->kind = YAHTTP_TYPE_REQUEST;
      return *this;
    };
    void initialize() {
      HTTPBase::initialize();
      this->kind = YAHTTP_TYPE_REQUEST;
    }
    void initialize(const HTTPBase& rhs) {
      HTTPBase::initialize();
      this->kind = YAHTTP_TYPE_REQUEST;
      // copy SOME attributes
      this->url = rhs.url;
      this->method = rhs.method;
      this->jar = rhs.jar;
      this->version = rhs.version;
    }
    void setup(const std::string& method, const std::string& url) {
      this->url.parse(url);
      this->headers["host"] = this->url.host;
      this->method = method;
      std::transform(this->method.begin(), this->method.end(), this->method.begin(), ::toupper);
      this->headers["user-agent"] = "YaHTTP v1.0";
    }; //<! Set some initial things for a request

    void preparePost(postformat_t format = urlencoded) {
      std::ostringstream postbuf;
      if (format == urlencoded) {
        for(strstr_map_t::const_iterator i = POST().begin(); i != POST().end(); i++) {
          postbuf << Utility::encodeURL(i->first, false) << "=" << Utility::encodeURL(i->second, false) << "&";
        }
        // remove last bit
        if (postbuf.str().length()>0) 
          body = postbuf.str().substr(0, postbuf.str().length()-1);
        else
          body = "";
        headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8";
      } else if (format == multipart) {
        headers["content-type"] = "multipart/form-data; boundary=YaHTTP-12ca543";
        for(strstr_map_t::const_iterator i = POST().begin(); i != POST().end(); i++) {
          postbuf << "--YaHTTP-12ca543\r\nContent-Disposition: form-data; name=\"" << Utility::encodeURL(i->first, false) << "; charset=UTF-8\r\n\r\n"
            << Utility::encodeURL(i->second, false) << "\r\n";
        }
      }

      postbuf.str("");
      postbuf << body.length();
      // set method and change headers
      method = "POST";
      headers["content-length"] = postbuf.str();
    }; //<! convert all postvars into string and stuff it into body

    friend std::ostream& operator<<(std::ostream& os, const Request &resp);
    friend std::istream& operator>>(std::istream& is, Request &resp);
  };

  /*! Asynchronous HTTP document loader */
  template <class T>
  class AsyncLoader {
  public:
    T* target; //<! target to populate
    int state; //<! reader state
    size_t pos; //<! reader position
    
    std::string buffer; //<! read buffer 
    bool chunked; //<! whether we are parsing chunked data
    int chunk_size; //<! expected size of next chunk
    std::ostringstream bodybuf; //<! buffer for body
    size_t maxbody; //<! maximum size of body
    size_t minbody; //<! minimum size of body
    bool hasBody; //<! are we expecting body

    void keyValuePair(const std::string &keyvalue, std::string &key, std::string &value); //<! key value pair parser helper

    void initialize(T* target) {
      chunked = false; chunk_size = 0;
      bodybuf.str(""); minbody = 0; maxbody = 0;
      pos = 0; state = 0; this->target = target; 
      hasBody = false;
      buffer = "";
      this->target->initialize();
    }; //<! Initialize the parser for target and clear state
    int feed(const std::string& somedata); //<! Feed data to the parser
    bool ready() {
     return (chunked == true && state == 3) || // if it's chunked we get end of data indication
             (chunked == false && state > 1 &&  
               (!hasBody || 
                 (bodybuf.str().size() <= maxbody && 
                  bodybuf.str().size() >= minbody)
               )
             ); 
    }; //<! whether we have received enough data
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
    }; //<! finalize and release target
  };

  /*! Asynchronous HTTP response loader */
  class AsyncResponseLoader: public AsyncLoader<Response> {
  };

  /*! Asynchronous HTTP request loader */
  class AsyncRequestLoader: public AsyncLoader<Request> {
  };

};
