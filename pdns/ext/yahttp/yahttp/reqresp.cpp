#include "yahttp.hpp"

namespace YaHTTP {
  template <class T>
  int AsyncLoader<T>::feed(const std::string& somedata) {
    buffer.append(somedata);
    while(state < 2) {
      int cr=0;
      // need to find CRLF in buffer
      if ((pos = buffer.find_first_of("\n")) == std::string::npos) return false;
      if (buffer[pos-1]=='\r')
        cr=1;
      std::string line(buffer.begin(), buffer.begin()+pos-cr); // exclude CRLF
      buffer.erase(buffer.begin(), buffer.begin()+pos+1); // remove line from buffer including CRLF

      if (state == 0) { // startup line
        if (target->kind == YAHTTP_TYPE_REQUEST) {
          std::string ver;
          std::string tmpurl;
          std::istringstream iss(line);
          iss >> target->method >> tmpurl >> ver;
          if (ver.find("HTTP/1.") != 0)
            throw ParseError("Not a HTTP 1.x request");
          // uppercase the target method
          std::transform(target->method.begin(), target->method.end(), target->method.begin(), ::toupper);
          target->url.parse(tmpurl);
          target->getvars = Utility::parseUrlParameters(target->url.parameters);
          state = 1;
        } else if(target->kind == YAHTTP_TYPE_RESPONSE) {
          std::string ver;
          std::istringstream iss(line);
          iss >> ver >> target->status >> target->statusText;
          if (ver.find("HTTP/1.") != 0)
            throw ParseError("Not a HTTP 1.x response");
          state = 1;
        }
      } else if (state == 1) {
        std::string key,value;
        size_t pos;
        if (line.empty()) {
          chunked = (target->headers.find("transfer-encoding") != target->headers.end() && target->headers["transfer-encoding"] == "chunked");
          state = 2;
          break;
        }
        // split headers
        if ((pos = line.find_first_of(": ")) == std::string::npos)
          throw ParseError("Malformed header line");
        key = line.substr(0, pos);
        value = line.substr(pos+2);
        Utility::trimRight(value);
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        // is it already defined

        if ((key == "set-cookie" && target->kind == YAHTTP_TYPE_RESPONSE) ||
            (key == "cookie" && target->kind == YAHTTP_TYPE_REQUEST)) {
          target->jar.parseCookieHeader(value);
        } else {
          if (key == "host" && target->kind == YAHTTP_TYPE_REQUEST) {
            // maybe it contains port? 
            if ((pos = value.find(":")) == std::string::npos) {
              target->url.host = value;
            } else {
              target->url.host = value.substr(0, pos);
              target->url.port = ::atoi(value.substr(pos).c_str());
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
    if (target->kind == YAHTTP_TYPE_REQUEST) maxbody = YAHTTP_MAX_REQUEST_SIZE;
    else if (target->kind == YAHTTP_TYPE_RESPONSE) maxbody = YAHTTP_MAX_RESPONSE_SIZE; 
    else maxbody = 0;
   
    if (!chunked) {
      if (target->headers.find("content-length") != target->headers.end()) {
        std::istringstream maxbodyS(target->headers["content-length"]);
        maxbodyS >> minbody;
        maxbody = minbody;
      }
      if (minbody < 1) return true; // guess there isn't anything left.
      if (target->kind == YAHTTP_TYPE_REQUEST && minbody > YAHTTP_MAX_REQUEST_SIZE) throw ParseError("Max request body size exceeded");
      else if (target->kind == YAHTTP_TYPE_RESPONSE && minbody > YAHTTP_MAX_RESPONSE_SIZE) throw ParseError("Max response body size exceeded");
    }

    if (maxbody == 0) hasBody = false;
    else hasBody = true;

    if (buffer.size() == 0) return ready();

    while(buffer.size() > 0) {
      char buf[1024] = {0};

      if (chunked) {
        if (chunk_size == 0) {
          // read chunk length
          if ((pos = buffer.find('\n')) == std::string::npos) return false;
          if (pos > 1023)
            throw ParseError("Impossible chunk_size");
          buffer.copy(buf, pos);
          buf[pos]=0; // just in case...
          buffer.erase(buffer.begin(), buffer.begin()+pos+1); // remove line from buffer
          sscanf(buf, "%x", &chunk_size);
          if (!chunk_size) break; // last chunk
        } else {
          if (buffer.size() < static_cast<size_t>(chunk_size+1)) return false; // expect newline
          if (buffer.at(chunk_size) != '\n') return false; // there should be newline.
          buffer.copy(buf, chunk_size);
          buffer.erase(buffer.begin(), buffer.begin()+chunk_size+1);
          bodybuf << buf;
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
        getparmbuf << Utility::encodeURL(i->first) << "=" << Utility::encodeURL(i->second) << "&";
      }
      if (getparmbuf.str().length() > 0)  
        getparms = "?" + std::string(getparmbuf.str().begin(), getparmbuf.str().end() - 1);
      else
        getparms = "";
      os << method << " " << url.path << getparms << " HTTP/1.1";
    } else if (kind == YAHTTP_TYPE_RESPONSE) {
      os << "HTTP/1.1 " << status << " ";
      if (statusText.empty())
        os << Utility::status2text(status);
      else
        os << statusText;
    }
    os << "\r\n";
  
    // write headers
    strstr_map_t::const_iterator iter = headers.begin();
    while(iter != headers.end()) {
      if (iter->first == "host" && kind != YAHTTP_TYPE_REQUEST) { iter++; continue; }
      os << Utility::camelizeHeader(iter->first) << ": " << iter->second << "\r\n";
      iter++;
    }
    if (jar.cookies.size() > 0) { // write cookies
      for(strcookie_map_t::const_iterator i = jar.cookies.begin(); i != jar.cookies.end(); i++) {
        if (kind == YAHTTP_TYPE_REQUEST) {
          os << "Cookie: ";
        } else {
          os << "Set-Cookie: ";
        }
        os << i->second.str() << "\r\n";
      }
    }
    os << "\r\n";
#ifdef HAVE_CPP_FUNC_PTR
    this->renderer(this, os);
#else
    os << body;
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
      if (is.gcount()) { // did we actually read anything
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
      if (is.gcount()) { // did we actually read anything
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
