namespace YaHTTP {
  /*! Implements a single cookie */
  class Cookie {
  public:
     Cookie() {
       secure = false;
       httponly = false;
       name = value = "";
       expires = DateTime();
     }; //!< Set the cookie to empty value

     Cookie(const Cookie &rhs) {
       name = rhs.name;
       value = rhs.value;
       domain = rhs.domain;
       path = rhs.path;
       secure = rhs.secure;
       httponly = rhs.httponly;
       expires = rhs.expires;
     }; //<! Copy cookie values

     Cookie& operator=(const Cookie &rhs) {
       name = rhs.name;
       value = rhs.value;
       domain = rhs.domain;
       path = rhs.path;
       secure = rhs.secure;
       httponly = rhs.httponly;
       expires = rhs.expires;
       return *this;
     }

     DateTime expires; /*!< Expiration date */
     std::string domain; /*!< Domain where cookie is valid */
     std::string path; /*!< Path where the cookie is valid */
     bool httponly; /*!< Whether the cookie is for server use only */
     bool secure; /*!< Whether the cookie is for HTTPS only */
 
     std::string name; /*!< Cookie name */
     std::string value; /*!< Cookie value */

     std::string str() const {
       std::ostringstream oss;
       oss << YaHTTP::Utility::encodeURL(name) << "=" << YaHTTP::Utility::encodeURL(value);

       if (expires.isSet) 
         oss << "; expires=" << expires.cookie_str();
       if (domain.size()>0)
         oss << "; domain=" << domain;
       if (path.size()>0)
         oss << "; path=" << path;
       if (secure)
         oss << "; secure";
       if (httponly)
         oss << "; httpOnly";
       return oss.str();
     }; //!< Stringify the cookie
  };

  /*! Implements a Cookie jar for storing multiple cookies */
  class CookieJar {
    public:
    std::map<std::string, Cookie, ASCIICINullSafeComparator> cookies;  //<! cookie container
  
    CookieJar() {}; //<! constructs empty cookie jar
    CookieJar(const CookieJar & rhs) {
      this->cookies = rhs.cookies;
    } //<! copy cookies from another cookie jar
    CookieJar& operator=(const CookieJar & rhs) = default;
  
    void clear() {
      this->cookies.clear();
    }

    void keyValuePair(const std::string &keyvalue, std::string &key, std::string &value) {
      size_t pos;
      pos = keyvalue.find("=");
      if (pos == std::string::npos) throw "Not a Key-Value pair (cookie)";
      key = std::string(keyvalue.begin(), keyvalue.begin()+pos);
      value = std::string(keyvalue.begin()+pos+1, keyvalue.end());
    } //<! key value pair parser
  
    void parseCookieHeader(const std::string &cookiestr) {
      size_t pos, npos;
      std::list<Cookie> lcookies;
      Cookie c;
      pos = 0;
      while(pos < cookiestr.size()) {
        if ((npos = cookiestr.find("; ", pos)) == std::string::npos)
          npos = cookiestr.size();
        keyValuePair(cookiestr.substr(pos, npos-pos), c.name, c.value);
        c.name = YaHTTP::Utility::decodeURL(c.name);
        c.value = YaHTTP::Utility::decodeURL(c.value);
        lcookies.push_back(c);
        pos = npos+2;
      }
      for(std::list<Cookie>::iterator i = lcookies.begin(); i != lcookies.end(); i++) {
        this->cookies[i->name] = *i;
      }
    }

    void parseSetCookieHeader(const std::string &cookiestr) {
      Cookie c;
      size_t pos,npos;
      std::string k, v;

      if ((pos = cookiestr.find("; ", 0)) == std::string::npos)
        pos = cookiestr.size();
      keyValuePair(cookiestr.substr(0, pos), c.name, c.value);
      c.name = YaHTTP::Utility::decodeURL(c.name);
      c.value = YaHTTP::Utility::decodeURL(c.value);
      if (pos < cookiestr.size()) pos+=2;

      while(pos < cookiestr.size()) {
        if ((npos = cookiestr.find("; ", pos)) == std::string::npos)
          npos = cookiestr.size();
        std::string s = cookiestr.substr(pos, npos-pos);
        if (s.find("=") != std::string::npos)
          keyValuePair(s, k, v);
        else
          k = s;
        if (k == "expires") {
          DateTime dt;
          dt.parseCookie(v);
          c.expires = dt;
        } else if (k == "domain") {
          c.domain = v;
        } else if (k == "path") {
          c.path = v;
        } else if (k == "httpOnly") {
          c.httponly = true;
        } else if (k == "secure") {
          c.secure = true;
        } else {
          // ignore crap
          break;
        }
        pos = npos+2;
      }
  
      this->cookies[c.name] = c;
    }; //<! Parse multiple cookies from header 
  };
};
