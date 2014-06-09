#ifndef _YAHTTP_UTILITY_HPP
#define _YAHTTP_UTILITY_HPP 1

namespace YaHTTP {
  static const char *MONTHS[] = {0,"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec",0};
  static const char *DAYS[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat",0};

  class DateTime {
  public:
     bool isSet;

     int year;

     int month;
     int day;
     int wday;

     int hours;
     int minutes;
     int seconds;

     int utc_offset;

     DateTime() { 
       initialize();
     };

     void initialize() {
       isSet = false; 
       year = month = day = wday = hours = minutes = seconds = utc_offset = 0;
       month = 1; // it's invalid otherwise
     };

     void setLocal() {
       fromLocaltime(time((time_t*)NULL)); 
     };

     void setGm() {
       fromGmtime(time((time_t*)NULL));
     }

     void fromLocaltime(time_t t) {
#ifdef HAVE_LOCALTIME_R
       struct tm tm;
       localtime_r(&t, &tm);
       fromTm(&tm);
#else
       struct tm *tm;
       tm = localtime(&t);
       fromTm(tm);
#endif
     };

     void fromGmtime(time_t t) {
#ifdef HAVE_GMTIME_R
       struct tm tm;
       gmtime_r(&t, &tm);
       fromTm(&tm);
#else
       struct tm *tm;
       tm = gmtime(&t);
       fromTm(tm);
#endif
     };

     void fromTm(const struct tm *tm) {
       year = tm->tm_year + 1900;
       month = tm->tm_mon + 1;
       day = tm->tm_mday;
       hours = tm->tm_hour;
       minutes = tm->tm_min;
       seconds = tm->tm_sec;
       wday = tm->tm_wday;
       utc_offset = tm->tm_gmtoff;
       isSet = true;
     };

     void validate() const {
       if (wday < 0 || wday > 6) throw "Invalid date";
       if (month < 1 || month > 12) throw "Invalid date";
       if (year < 0) throw "Invalid date";
       if (hours < 0 || hours > 23 ||
           minutes < 0 || minutes > 59 ||
           seconds < 0 || seconds > 60) throw "Invalid date";
     }

     std::string rfc_str() const {
       std::ostringstream oss;
       validate();
       oss << DAYS[wday] << ", " << std::setfill('0') << std::setw(2) << day << " " << MONTHS[month] << " " <<
          std::setfill('0') << std::setw(2) <<  year << " " << 
          std::setfill('0') << std::setw(2) << hours << ":" << 
          std::setfill('0') << std::setw(2) << minutes << ":" << 
          std::setfill('0') << std::setw(2) << seconds << " ";
       if (utc_offset>=0) oss << "+";
       else oss << "-";
       int tmp_off = ( utc_offset < 0 ? utc_offset*-1 : utc_offset ); 
       oss << std::setfill('0') << std::setw(2) << (tmp_off/3600);
       oss << std::setfill('0') << std::setw(2) << (tmp_off%3600)/60;

       return oss.str(); 
     };
 
     std::string cookie_str() const {
       std::ostringstream oss;
       validate();
       oss << std::setfill('0') << std::setw(2) << day << "-" << MONTHS[month] << "-" << year << " " <<
         std::setfill('0') << std::setw(2) << hours << ":" << 
         std::setfill('0') << std::setw(2) << minutes << ":" << 
         std::setfill('0') << std::setw(2) << seconds << " GMT";
       return oss.str();
     }
 
     void parse822(const std::string &rfc822_date) {
       char *pos;
       struct tm tm;
       if ( (pos = strptime(rfc822_date.c_str(), "%a, %d %b %Y %T %z", &tm)) != NULL) {
          fromTm(&tm);
       } else {
          throw "Unparseable date";
       }
     };

     void parseCookie(const std::string &cookie_date) {
       char *pos;
       struct tm tm;
       if ( (pos = strptime(cookie_date.c_str(), "%d-%b-%Y %T %Z", &tm)) != NULL) {
          fromTm(&tm);
       } else {
          throw "Unparseable date";
       }
     };

     int unixtime() const {
       struct tm tm;
       tm.tm_year = year-1900;
       tm.tm_mon = month-1;
       tm.tm_mday = day;
       tm.tm_hour = hours;
       tm.tm_min = minutes;
       tm.tm_sec = seconds;
       tm.tm_gmtoff = utc_offset;
       return mktime(&tm);
     }
     
  };
 
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
    
    static std::string encodeURL(const std::string& component, bool asUrl = true) {
      std::string result = component;
      std::string skip = "+-.:,&;_#%[]?/@(){}=";
      char repl[3];
      size_t pos;
      for(std::string::iterator iter = result.begin(); iter != result.end(); iter++) {
        if (!std::isalnum(*iter) && (!asUrl || skip.find(*iter) == std::string::npos)) {
          // replace with different thing
          pos = std::distance(result.begin(), iter);
          std::snprintf(repl,3,"%02x", static_cast<unsigned char>(*iter));
          result = result.replace(pos, 1, "%", 1).insert(pos+1, repl, 2);
          iter = result.begin() + pos + 2;
        }
      }
      return result;
    };

    static std::string encodeURL(const std::wstring& component, bool asUrl = true) {
      unsigned char const *p = reinterpret_cast<unsigned char const*>(&component[0]);
      std::size_t s = component.size() * sizeof((*component.begin()));
      std::vector<unsigned char> vec(p, p+s);

      std::ostringstream result;
      std::string skip = "+-.,&;_#%[]?/@(){}=";
      for(std::vector<unsigned char>::iterator iter = vec.begin(); iter != vec.end(); iter++) {
        if (!std::isalnum((char)*iter) && (!asUrl || skip.find((char)*iter) == std::string::npos)) {
          // bit more complex replace
          result << "%" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(*iter);
        } else result << (char)*iter;
      }
      return result.str();
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
            value = parameters.substr(delim+1, nextpos-delim-1);
          }
        }
        if (key.empty()) {
          // no parameters at all
          break;
        }
        key = decodeURL(key);
        value = decodeURL(value);
        parameter_map[key] = value;
        if (nextpos == std::string::npos) {
          // no more parameters left
          break;
        }

        pos = nextpos+1;
      }
      return parameter_map;
    };

    static bool iequals(const std::string& a, const std::string& b, size_t length) {
      std::string::const_iterator ai, bi;
      size_t i;
      for(ai = a.begin(), bi = b.begin(), i = 0; ai != a.end() && bi != b.end() && i < length; ai++,bi++,i++) {
        if (::toupper(*ai) != ::toupper(*bi)) return false;
      }

      if (ai == a.end() && bi == b.end()) return true;
      if ((ai == a.end() && bi != b.end()) ||
          (ai != a.end() && bi == b.end())) return false;
      
      return ::toupper(*ai) == ::toupper(*bi);
    }

    static bool iequals(const std::string& a, const std::string& b) {
      if (a.size() != b.size()) return false;
      return iequals(a,b,a.size());
    }

    static void trimRight(std::string &str) {
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
