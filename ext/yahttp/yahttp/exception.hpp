#pragma once
#include <exception>

namespace YaHTTP {
  /*! Generic error class */
  class Error: public std::exception {
  public:
    Error() {};
    Error(const std::string& reason_): reason(reason_) {};
    virtual ~Error() throw() {};

    virtual const char* what() const throw()
    {
      return reason.c_str();
    }
    const std::string reason; //<! Cause of the error
  };
  /*! Parse error class */
  class ParseError: public YaHTTP::Error {
  public:
    ParseError() {};
    ParseError(const std::string& reason_): Error(reason_) {};
  };
};
