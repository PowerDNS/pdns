#ifndef _YAHTTP_EXCEPTION_HPP 
#define _YAHTTP_EXCEPTION_HPP 1

#include <exception>

namespace YaHTTP {
  class Error: public std::exception {
  public:
    Error() {};
    Error(const std::string& reason): reason(reason) {};
    virtual ~Error() throw() {};

    virtual const char* what() const throw()
    {
      return reason.c_str();
    }
    const std::string reason;
  };
  class ParseError: public YaHTTP::Error {
  public:
    ParseError() {};
    ParseError(const std::string& reason): Error(reason) {};
  };
};

#endif
