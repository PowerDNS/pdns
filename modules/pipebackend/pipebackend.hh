//
// File    : pdnsbackend.hh
// Version : $Id$
//

#ifndef PIPEBACKEND_HH
#define PIPEBACKEND_HH

#include <string>
#include <map>
#include <sys/types.h>


#include "pdns/namespaces.hh"
#include "pdns/misc.hh"


/** The CoWrapper class wraps around a coprocess and restarts it if needed.
    It may also send out pings and expect banners */
class CoWrapper
{
public:
  CoWrapper(const string &command, int timeout, int abiVersion);
  ~CoWrapper();
  void send(const string &line);
  void receive(string &line);
private:
  CoRemote* d_cp;
  string d_command;
  void launch();
  int d_timeout;
  int d_abiVersion;
};

class PipeBackend : public DNSBackend
{
public:
  PipeBackend(const string &suffix="");
  ~PipeBackend();
  void lookup(const QType&, const DNSName& qdomain, DNSPacket *p=0, int zoneId=-1);
  bool list(const DNSName& target, int domain_id, bool include_disabled=false);
  bool get(DNSResourceRecord &r);
  string directBackendCmd(const string &query);
  static DNSBackend *maker();
  
private:
  void launch();
  void cleanup();
  unique_ptr<CoWrapper> d_coproc;
  DNSName d_qname;
  QType d_qtype;
  Regex* d_regex;
  string d_regexstr;
  bool d_disavow;
  int d_abiVersion;
};


#endif

