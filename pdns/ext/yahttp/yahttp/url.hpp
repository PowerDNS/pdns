#ifndef _YAHTTP_URL_HPP
#define _YAHTTP_URL_HPP 1
#include <sstream>
#include <string>

#include "utility.hpp"

#ifndef YAHTTP_MAX_URL_LENGTH
#define YAHTTP_MAX_URL_LENGTH 2048
#endif 

namespace YaHTTP {
  class URL {
   private: 
      bool parseSchema(const std::string& url, size_t &pos) {
          size_t pos1;
          if (pos >= url.size()) return false; // no data
          if ( (pos1 = url.find_first_of(":",pos)) == std::string::npos ) return false; // schema is mandatory
          protocol = url.substr(pos, pos1-pos);
          if (protocol == "http") port = 80;
          if (protocol == "https") port = 443;
          pos = pos1+1; // after :
          if (url.compare(pos, 2, "//") == 0) {
             pathless = false; // if this is true we put rest into parameters
             pos += 2;
          }
          return true;
      }

      bool parseHost(const std::string& url, size_t &pos) {
          size_t pos1;
          if (pos >= url.size()) return true; // no data
          if ( (pos1 = url.find_first_of("/", pos)) == std::string::npos ) {
             host = url.substr(pos);
             path = "/";
             pos = url.size();
          } else {
             host = url.substr(pos, pos1-pos);
             pos = pos1;
          }
          return true;
      }

      bool parseUserPass(const std::string& url, size_t &pos) {
          size_t pos1,pos2;
          if (pos >= url.size()) return true; // no data

          if ( (pos1 = url.find_first_of("@",pos)) == std::string::npos ) return true; // no userinfo
          pos2 = url.find_first_of(":",pos);

          if (pos2 != std::string::npos) { // comes with password
             username = url.substr(pos, pos2 - pos);
             password = url.substr(pos2+1, pos1 - pos2 - 1);
             password = Utility::decodeURL(password);
          } else {
             username = url.substr(pos+1, pos1 - pos);
          }
          pos = pos1+1;
          username = Utility::decodeURL(username);
          return true;
      };

      bool parsePath(const std::string& url, size_t &pos) {
          size_t pos1;
          if (pos >= url.size()) return true; // no data
          if (url[pos] != '/') return false; // not an url
          if ( (pos1 = url.find_first_of("?", pos)) == std::string::npos ) {
             path = url.substr(pos);
             pos = url.size();
          } else {
             path = url.substr(pos, pos1-pos);
             pos = pos1;
          }
          return true;
      }

      bool parseParameters(const std::string& url, size_t &pos) {
          size_t pos1;
          if (pos >= url.size()) return true; // no data
          if (url[pos] == '#') return true; // anchor starts here
          if (url[pos] != '?') return false; // not a parameter
          if ( (pos1 = url.find_first_of("#", pos)) == std::string::npos ) {
             parameters = url.substr(pos+1);;
             pos = url.size();
          } else {
             parameters = url.substr(pos+1, pos1-pos-1);
             pos = pos1;
          }
          if (parameters.size()>0 && *(parameters.end()-1) == '&') parameters.resize(parameters.size()-1);
          return true;
      }

      bool parseAnchor(const std::string& url, size_t &pos) {
          if (pos >= url.size()) return true; // no data
          if (url[pos] != '#') return false; // not anchor
          anchor = url.substr(pos+1);
          return true;
      }

      void initialize() {
        protocol = ""; host = ""; port = 0; username = ""; password = ""; path = ""; parameters = ""; anchor =""; pathless = true;
      }

  public:
      std::string to_string() const {
          std::string tmp;
          std::ostringstream oss;
            
          if (protocol.empty() == false) {
             oss << protocol << ":";
             if (host.empty() == false) {
               oss << "//";
             }
          }

          if (username.empty() == false) {
           if (password.empty() == false)
             oss << Utility::encodeURL(username) << ":" << Utility::encodeURL(password) << "@";
           else
             oss << Utility::encodeURL(username) << "@";
          }
          if (host.empty() == false)
             oss << host;
          if (!(protocol == "http" && port == 80) &&
              !(protocol == "https" && port == 443) &&
              port > 0) 
            oss << ":" << port;

          oss << path;
          if (parameters.empty() == false) {
             if (!pathless) 
                oss << "?";
             oss << parameters;
          }
          if (anchor.empty() == false)
             oss << "#" << anchor;
          return oss.str();
      }

      std::string protocol;
      std::string host;
      int port;
      std::string username;
      std::string password;
      std::string path;
      std::string parameters;
      std::string anchor;
      bool pathless;

      URL() { initialize(); }; 
      URL(const std::string& url) {
          parse(url);
      };

      URL(const char *url) {
          parse(std::string(url));
      };

      bool parse(const std::string& url) {
          // setup
          initialize();

          if (url.size() > YAHTTP_MAX_URL_LENGTH) return false;
          size_t pos = 0;
          if (*(url.begin()) != '/') { // full url?
             if (parseSchema(url, pos) == false) return false;
             if (pathless) {
                parameters = url.substr(pos);
                return true;
             }
             if (parseUserPass(url, pos) == false) return false;
             if (parseHost(url, pos) == false) return false;
          }
          if (parsePath(url, pos) == false) return false;
          if (parseParameters(url, pos) == false) return false;
          return parseAnchor(url, pos);
      };

      friend std::ostream & operator<<(std::ostream& os, const URL& url) {
         os<<url.to_string();
         return os;
      }
  };
};
#endif
