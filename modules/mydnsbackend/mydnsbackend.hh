#ifndef MYDNSBACKEND_HH
#define MYDNSBACKEND_HH

#include <string>
#include <map>

#include "pdns/namespaces.hh"

#include <modules/gmysqlbackend/smysql.hh>

class MyDNSBackend : public DNSBackend
{
public:
  MyDNSBackend(const string &suffix);
  ~MyDNSBackend();
  
  void lookup(const QType &, const DNSName &qdomain, DNSPacket *p=0, int zoneId=-1);
  bool list(const DNSName &target, int domain_id, bool include_disabled=false);
  bool get(DNSResourceRecord &r);
  bool getSOA(const DNSName& name, SOAData& soadata, DNSPacket*);
    
private:
  SMySQL *d_db; 

  string d_qname;
  string d_origin;
  bool d_useminimalttl;
  unsigned int d_minimum;

  SSqlStatement::result_t d_result;

  SSqlStatement* d_query_stmt;
  SSqlStatement* d_domainIdQuery_stmt;
  SSqlStatement* d_domainNoIdQuery_stmt;
  SSqlStatement* d_listQuery_stmt;
  SSqlStatement* d_soaQuery_stmt;
  SSqlStatement* d_basicQuery_stmt;
  SSqlStatement* d_anyQuery_stmt;
};

#endif /* MYDNSBACKEND_HH */
