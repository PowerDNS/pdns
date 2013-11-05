#ifndef _YAHTTP_UTILITY_HPP
#define _YAHTTP_UTILITY_HPP 1

#include <string>
#include <algorithm>
#include <cstdio>

namespace YaHTTP {
  class Utility {
  public:
    static std::string decodeURL(const std::string& component) {
        std::string result = component;
        size_t pos1,pos2;
        pos2 = 0;
        while((pos1 = result.find_first_of("%", pos2))!=std::string::npos) {
           std::string code;
           char a,b,c;
           if (pos1 + 2 > result.length()) return result; // end of result
           code = result.substr(pos1+1, 2);
           a = std::tolower(code[0]); b = std::tolower(code[1]);

           if ((( '0' > a || a > '9') && ('a' > a || a > 'f')) ||
              (( '0' > b || b > '9') && ('a' > b || b > 'f'))) {
              pos2 = pos1+3;
              continue;
           }

           if ('0' <= a && a <= '9') a = a - '0';
           if ('a' <= a && a <= 'f') a = a - 'a' + 0x0a;
           if ('0' <= b && b <= '9') b = b - '0';
           if ('a' <= b && b <= 'f') b = b - 'a' + 0x0a;

           c = (a<<4)+b;
           result = result.replace(pos1,3,1,c);
           pos2=pos1;
        }
        return result;
    };
    
    static std::string encodeURL(const std::string& component, bool encodeSlash = true) {
      std::string result = component;
      char repl[3];
      size_t pos;
      for(std::string::iterator iter = result.begin(); iter != result.end(); iter++) {
        if (*iter != '+' && !(encodeSlash == false || *iter == '/') && !std::isalnum(*iter)) {
          // replace with different thing
          pos = std::distance(result.begin(), iter);
          std::snprintf(repl,3,"%02x", *iter);
          result = result.replace(pos, 1, "%", 1).insert(pos+1, repl, 2);
          iter = result.begin() + pos + 2;
        }
      }
      return result;
    };

    static std::string status2text(int status) {
       switch(status) {
       case 200:
           return "OK";
       case 201:
           return "Created";
       case 202:
           return "Accepted";
       case 203:
           return "Non-Authoritative Information";
       case 204:
           return "No Content";
       case 205:
           return "Reset Content";
       case 206:
           return "Partial Content";
       case 300:
           return "Multiple Choices";
       case 301:
           return "Moved Permanently";
       case 302:
           return "Found";
       case 303:
           return "See Other";
       case 304:
           return "Not Modified";
       case 305:
           return "Use Proxy";
       case 307:
           return "Temporary Redirect";
       case 400:
           return "Bad Request";
       case 401:
           return "Unauthorized";
       case 402:
           return "Payment Required";
       case 403: 
           return "Forbidden";
       case 404:
           return "Not Found";
       case 405:
           return "Method Not Allowed";
       case 406:
           return "Not Acceptable";
       case 407:
           return "Proxy Authentication Required";
       case 408:
           return "Request Time-out";
       case 409:
           return "Conflict";
       case 410:
           return "Gone";
       case 411:
           return "Length Required";
       case 412:
           return "Precondition Failed";
       case 413:
           return "Request Entity Too Large";
       case 414:
           return "Request-URI Too Large";
       case 415:
           return "Unsupported Media Type";
       case 416:
           return "Requested range not satisfiable";
       case 417:
           return "Expectation Failed";
       case 500:
           return "Internal Server Error";
       case 501:
           return "Not Implemented";
       case 502:
           return "Bad Gateway";
       case 503:
           return "Service Unavailable";
       case 504:
           return "Gateway Time-out";
       case 505:
           return "HTTP Version not supported";
       default:
           return "Unknown Status";
       }
    };

    static std::map<std::string,std::string> parseUrlParameters(std::string parameters) {
      std::string::size_type pos = 0;
      std::map<std::string,std::string> parameter_map;
      while (pos != std::string::npos) {
        // find next parameter start
        std::string::size_type nextpos = parameters.find("&", pos);
        std::string::size_type delim = parameters.find("=", pos);
        if (delim > nextpos) {
          delim = nextpos;
        }
        std::string key;
        std::string value;
        if (delim == std::string::npos) {
          key = parameters.substr(pos);
        } else {
          key = parameters.substr(pos, delim-pos);
          if (nextpos == std::string::npos) {
            value = parameters.substr(delim+1);
          } else {
            value = parameters.substr(delim+1, nextpos-delim);
          }
        }
        if (key.empty()) {
          // no parameters at all
          break;
        }
        key = decodeURL(key);
        value = decodeURL(value);
        parameter_map[key] = value;

        pos = nextpos;
      }
      return parameter_map;
    };

    static void trim_right(std::string &str) {
       const std::locale &loc = std::locale::classic();
       std::string::reverse_iterator iter = str.rbegin();
       while(iter != str.rend() && std::isspace(*iter, loc)) iter++;
       str.erase(iter.base(), str.end());
    };

    static std::string camelizeHeader(const std::string &str) {
       std::string::const_iterator iter = str.begin();
       std::string result;
       const std::locale &loc = std::locale::classic();

       bool doNext = true;

       while(iter != str.end()) {
         if (doNext) 
            result.insert(result.end(), std::toupper(*iter, loc));
         else 
            result.insert(result.end(), std::tolower(*iter, loc)); 
         doNext = (*(iter++) == '-');
       }

       return result;
     };
   };
};
#endif
