#ifndef _YAHTTP_EXCEPTION_HPP 
#define _YAHTTP_EXCEPTION_HPP 1

#include <exception>

namespace YaHTTP {
  class ParseError: public std::exception {
  public:
    ParseError() {};
    ParseError(const std::string& reason): reason(reason) {};
    virtual ~ParseError() throw() {}; 

    virtual const char* what() const throw()
    {
      return reason.c_str();
    }
    const std::string reason;
  };
};

#endif
