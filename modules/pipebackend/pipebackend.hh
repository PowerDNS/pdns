//
// File    : pdnsbackend.hh
// Version : $Id$
//

#ifndef PIPEBACKEND_HH
#define PIPEBACKEND_HH

#include <string>
#include <map>
#include <sys/types.h>
#include <regex.h>

using namespace std;

/** very small regex wrapper */
class Regex
{
public:
  /** constructor that accepts the expression to regex */
  Regex(const string &expr)
  {
    if(regcomp(&d_preg, expr.c_str(), REG_ICASE|REG_NOSUB|REG_EXTENDED))
      throw AhuException("Regular expression did not compile");
  }
  ~Regex()
  {
    regfree(&d_preg);
  }
  /** call this to find out if 'line' matches your expression */
  bool match(const string &line)
  {
    return regexec(&d_preg,line.c_str(),0,0,0)==0;
  }
  
private:
  regex_t d_preg;
};


/** The CoWrapper class wraps around a coprocess and restarts it if needed.
    It may also send out pings and expect banners */
class CoWrapper
{
public:
  CoWrapper(const string &command, int timeout=0);
  void send(const string &line);
  void receive(string &line);
private:
  CoProcess *d_cp;
  string d_command;
  void launch();
  int d_timeout;
};

class PipeBackend : public DNSBackend
{
public:
  PipeBackend(const string &suffix="");
  ~PipeBackend();
  void lookup(const QType &, const string &qdomain, DNSPacket *p=0, int zoneId=-1);
  bool list(const string &target, int domain_id);
  bool get(DNSResourceRecord &r);
  
  static DNSBackend *maker();
  
private:
  CoWrapper *d_coproc;
  string d_qname;
  QType d_qtype;
  Regex* d_regex;
  string d_regexstr;
  bool d_disavow;
};


#endif

