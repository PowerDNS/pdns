#ifndef MYSQLCBACKEND_HH
#define MYSQLCBACKEND_HH

#include <string>
#include <map>

using namespace std;

#include <mysql.h>



/** The MySQLBackend is a DNSBackend that can answer DNS related questions. It looks up data
    in MySQL */
class MySQLBackend : public DNSBackend
{
public:
  MySQLBackend(const string &suffix="");
  ~MySQLBackend();
  MYSQL_RES *d_res;
  MySQLBackend *parent;
  string d_qname;
  QType d_qtype;
  
  void lookup(const QType &, const string &qdomain, DNSPacket *p=0, int zoneId=-1);
  bool list(int domain_id);
  bool get(DNSResourceRecord &r);
    
private:
  MYSQL db; 

  string sqlEscape(const string &nanme); //!< Escape ' and \ for SQL purposes
  string d_table;
};
#endif /* MYSQLCBACKEND_HH */
