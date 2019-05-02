#include "yahttp.hpp"

namespace YaHTTP {

  bool isspace(char c) {
    return std::isspace(c) != 0;
  }

  bool isspace(char c, const std::locale& loc) {
    return std::isspace(c, loc);
  }

  bool isxdigit(char c) {
    return std::isxdigit(c) != 0;
  }

  bool isxdigit(char c, const std::locale& loc) {
    return std::isxdigit(c, loc);
  }

  bool isdigit(char c) {
    return std::isdigit(c) != 0;
  }

  bool isdigit(char c, const std::locale& loc) {
    return std::isdigit(c, loc);
  }

  bool isalnum(char c) {
    return std::isalnum(c) != 0;
  }

  bool isalnum(char c, const std::locale& loc) {
    return std::isalnum(c, loc);
  }

  template <class T>
  bool AsyncLoader<T>::feed(const std::string& somedata) {
    buffer.append(somedata);
    while(state < 2) {
      int cr=0;
      pos = buffer.find_first_of("\n");
      // need to find CRLF in buffer
      if (pos == std::string::npos) return false;
      if (pos>0 && buffer[pos-1]=='\r')
        cr=1;
      std::string line(buffer.begin(), buffer.begin()+pos-cr); // exclude CRLF
      buffer.erase(buffer.begin(), buffer.begin()+pos+1); // remove line from buffer including CRLF

      if (state == 0) { // startup line
        if (target->kind == YAHTTP_TYPE_REQUEST) {
          std::string ver;
          std::string tmpurl;
          std::istringstream iss(line);
          iss >> target->method >> tmpurl >> ver;
          if (ver.size() == 0)
            target->version = 9;
          else if (ver.find("HTTP/0.9") == 0)
            target->version = 9;
          else if (ver.find("HTTP/1.0") == 0)
            target->version = 10;
          else if (ver.find("HTTP/1.1") == 0)
            target->version = 11;
          else
            throw ParseError("HTTP version not supported");
          // uppercase the target method
          std::transform(target->method.begin(), target->method.end(), target->method.begin(), ::toupper);
          target->url.parse(tmpurl);
          target->getvars = Utility::parseUrlParameters(target->url.parameters);
          state = 1;
        } else if(target->kind == YAHTTP_TYPE_RESPONSE) {
          std::string ver;
          std::istringstream iss(line);
          std::string::size_type pos1;
          iss >> ver >> target->status;
          std::getline(iss, target->statusText);
          pos1=0;
          while(pos1 < target->statusText.size() && YaHTTP::isspace(target->statusText.at(pos1))) pos1++;
          target->statusText = target->statusText.substr(pos1); 
          if ((pos1 = target->statusText.find("\r")) != std::string::npos) {
            target->statusText = target->statusText.substr(0, pos1-1);
          }
          if (ver.size() == 0) {
            target->version = 9;
          } else if (ver.find("HTTP/0.9") == 0)
            target->version = 9;
          else if (ver.find("HTTP/1.0") == 0)
            target->version = 10;
          else if (ver.find("HTTP/1.1") == 0)
            target->version = 11;
          else
            throw ParseError("HTTP version not supported");
          state = 1;
        }
      } else if (state == 1) {
        std::string key,value;
        size_t pos1;
        if (line.empty()) {
          chunked = (target->headers.find("transfer-encoding") != target->headers.end() && target->headers["transfer-encoding"] == "chunked");
          state = 2;
          break;
        }
        // split headers
        if ((pos1 = line.find(": ")) == std::string::npos)
          throw ParseError("Malformed header line");
        key = line.substr(0, pos1);
        value = line.substr(pos1+2);
        for(std::string::iterator it=key.begin(); it != key.end(); it++)
          if (YaHTTP::isspace(*it))
            throw ParseError("Header key contains whitespace which is not allowed by RFC");

        Utility::trim(value);
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        // is it already defined

        if (key == "set-cookie" && target->kind == YAHTTP_TYPE_RESPONSE) {
          target->jar.parseSetCookieHeader(value);
        } else if (key == "cookie" && target->kind == YAHTTP_TYPE_REQUEST) {
          target->jar.parseCookieHeader(value);
        } else {
          if (key == "host" && target->kind == YAHTTP_TYPE_REQUEST) {
            // maybe it contains port?
            if ((pos1 = value.find(":")) == std::string::npos) {
              target->url.host = value;
            } else {
              target->url.host = value.substr(0, pos1);
              target->url.port = ::atoi(value.substr(pos1).c_str());
            }
          }
          if (target->headers.find(key) != target->headers.end()) {
            target->headers[key] = target->headers[key] + ";" + value;
          } else {
            target->headers[key] = value;
          }
        }
      }
    }

    minbody = 0;
    // check for expected body size
    if (target->kind == YAHTTP_TYPE_REQUEST) maxbody = target->max_request_size;
    else if (target->kind == YAHTTP_TYPE_RESPONSE) maxbody = target->max_response_size;
    else maxbody = 0;

    if (!chunked) {
      if (target->headers.find("content-length") != target->headers.end()) {
        std::istringstream maxbodyS(target->headers["content-length"]);
        maxbodyS >> minbody;
        maxbody = minbody;
      }
      if (minbody < 1) return true; // guess there isn't anything left.
      if (target->kind == YAHTTP_TYPE_REQUEST && static_cast<ssize_t>(minbody) > target->max_request_size) throw ParseError("Max request body size exceeded");
      else if (target->kind == YAHTTP_TYPE_RESPONSE && static_cast<ssize_t>(minbody) > target->max_response_size) throw ParseError("Max response body size exceeded");
    }

    if (maxbody == 0) hasBody = false;
    else hasBody = true;

    if (buffer.size() == 0) return ready();

    while(buffer.size() > 0) {
      if (chunked) {
        if (chunk_size == 0) {
          char buf[100];
          // read chunk length
          if ((pos = buffer.find('\n')) == std::string::npos) return false;
          if (pos > 99)
            throw ParseError("Impossible chunk_size");
          buffer.copy(buf, pos);
          buf[pos]=0; // just in case...
          buffer.erase(buffer.begin(), buffer.begin()+pos+1); // remove line from buffer
          sscanf(buf, "%x", &chunk_size);
          if (chunk_size == 0) { state = 3; break; } // last chunk
        } else {
          int crlf=1;
          if (buffer.size() < static_cast<size_t>(chunk_size+1)) return false; // expect newline
          if (buffer.at(chunk_size) == '\r') {
            if (buffer.size() < static_cast<size_t>(chunk_size+2) || buffer.at(chunk_size+1) != '\n') return false; // expect newline after carriage return
            crlf=2;
          } else if (buffer.at(chunk_size) != '\n') return false;
          std::string tmp = buffer.substr(0, chunk_size);
          buffer.erase(buffer.begin(), buffer.begin()+chunk_size+crlf);
          bodybuf << tmp;
          chunk_size = 0;
          if (buffer.size() == 0) break; // just in case
        }
      } else {
        if (bodybuf.str().length() + buffer.length() > maxbody)
          bodybuf << buffer.substr(0, maxbody - bodybuf.str().length());
        else
          bodybuf << buffer;
        buffer = "";
      }
    }

    if (chunk_size!=0) return false; // need more data

    return ready();
  };

  void HTTPBase::write(std::ostream& os) const {
    if (kind == YAHTTP_TYPE_REQUEST) {
      std::ostringstream getparmbuf;
      std::string getparms;
      // prepare URL
      for(strstr_map_t::const_iterator i = getvars.begin(); i != getvars.end(); i++) {
        getparmbuf << Utility::encodeURL(i->first, false) << "=" << Utility::encodeURL(i->second, false) << "&";
      }
      if (getparmbuf.str().length() > 0) {
        std::string buf = getparmbuf.str();
        getparms = "?" + std::string(buf.begin(), buf.end() - 1);
      }
      else
        getparms = "";
      os << method << " " << url.path << getparms << " HTTP/" << versionStr(this->version);
    } else if (kind == YAHTTP_TYPE_RESPONSE) {
      os << "HTTP/" << versionStr(this->version) << " " << status << " ";
      if (statusText.empty())
        os << Utility::status2text(status);
      else
        os << statusText;
    }
    os << "\r\n";

    bool cookieSent = false;
    bool sendChunked = false;

    if (this->version > 10) { // 1.1 or better
      if (headers.find("content-length") == headers.end() && !this->is_multipart) {
        // must use chunked on response
        sendChunked = (kind == YAHTTP_TYPE_RESPONSE);
        if ((headers.find("transfer-encoding") != headers.end() && headers.find("transfer-encoding")->second != "chunked")) {
          throw YaHTTP::Error("Transfer-encoding must be chunked, or Content-Length defined");
        }
        if ((headers.find("transfer-encoding") == headers.end() && kind == YAHTTP_TYPE_RESPONSE)) {
          sendChunked = true;
          os << "Transfer-Encoding: chunked\r\n";
        }
      } else {
	sendChunked = false;
      }
    }

    // write headers
    strstr_map_t::const_iterator iter = headers.begin();
    while(iter != headers.end()) {
      if (iter->first == "host" && (kind != YAHTTP_TYPE_REQUEST || version < 10)) { iter++; continue; }
      if (iter->first == "transfer-encoding" && sendChunked) { iter++; continue; }
      std::string header = Utility::camelizeHeader(iter->first);
      if (header == "Cookie" || header == "Set-Cookie") cookieSent = true;
      os << Utility::camelizeHeader(iter->first) << ": " << iter->second << "\r\n";
      iter++;
    }
    if (version > 9 && !cookieSent && jar.cookies.size() > 0) { // write cookies
     if (kind == YAHTTP_TYPE_REQUEST) {
        bool first = true;
        os << "Cookie: ";
        for(strcookie_map_t::const_iterator i = jar.cookies.begin(); i != jar.cookies.end(); i++) {
          if (first)
            first = false;
          else
            os << "; ";
          os << Utility::encodeURL(i->second.name) << "=" << Utility::encodeURL(i->second.value);
        }
     } else if (kind == YAHTTP_TYPE_RESPONSE) {
        for(strcookie_map_t::const_iterator i = jar.cookies.begin(); i != jar.cookies.end(); i++) {
          os << "Set-Cookie: ";
          os << i->second.str() << "\r\n";
        }
      }
    }
    os << "\r\n";
#ifdef HAVE_CPP_FUNC_PTR
    this->renderer(this, os, sendChunked);
#else
    SendbodyRenderer r;
    r(this, os, chunked)
#endif
  };

  std::ostream& operator<<(std::ostream& os, const Response &resp) {
    resp.write(os);
    return os;
  };

  std::istream& operator>>(std::istream& is, Response &resp) {
    YaHTTP::AsyncResponseLoader arl;
    arl.initialize(&resp);
    while(is.good()) {
      char buf[1024];
      is.read(buf, 1024);
      if (is.gcount()>0) { // did we actually read anything
        is.clear();
        if (arl.feed(std::string(buf, is.gcount())) == true) break; // completed
      }
    }
    // throw unless ready
    if (arl.ready() == false)
      throw ParseError("Was not able to extract a valid Response from stream");
    arl.finalize();
    return is;
  };

  std::ostream& operator<<(std::ostream& os, const Request &req) {
    req.write(os);
    return os;
  };

  std::istream& operator>>(std::istream& is, Request &req) {
    YaHTTP::AsyncRequestLoader arl;
    arl.initialize(&req);
    while(is.good()) {
      char buf[1024];
      is.read(buf, 1024);
      if (is.gcount() > 0) { // did we actually read anything
        is.clear();
        if (arl.feed(std::string(buf, is.gcount())) == true) break; // completed
      }
    }
    if (arl.ready() == false)
      throw ParseError("Was not able to extract a valid Request from stream");
    arl.finalize();
    return is;
  };
};
