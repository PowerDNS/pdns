//
// File    : pdnsbackend.hh
// Version : $Id$
//

#ifndef PIPEBACKEND_HH
#define PIPEBACKEND_HH

#include <string>
#include <map>
#include <sys/types.h>
#include <boost/shared_ptr.hpp>

#include "pdns/namespaces.hh"
#include "pdns/misc.hh"


/** The CoWrapper class wraps around a coprocess and restarts it if needed.
    It may also send out pings and expect banners */
class CoWrapper
{
public:
  CoWrapper(const string &command, int timeout=0);
  ~CoWrapper();
  void send(const string &line);
  void receive(string &line);
private:
  CoProcess* d_cp;
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
  shared_ptr<CoWrapper> d_coproc;
  string d_qname;
  QType d_qtype;
  Regex* d_regex;
  string d_regexstr;
  bool d_disavow;
};


#endif

