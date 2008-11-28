// $Id$

#ifndef PDNSBACKEND_HH
#define PDNSBACKEND_HH

#include <string>
#include <map>

using namespace std;

#include <mysql.h>

class PdnsBackend : public DNSBackend
{
   public:

      PdnsBackend(const string &suffix = "");
      ~PdnsBackend();

      void lookup(const QType &, const string &qdomain, DNSPacket *p = 0, int zoneId = -1);
      bool list(const string &target, int inZoneId);
      bool get(DNSResourceRecord& outRecord);
      bool getSOA(const string &name, SOAData &soadata, DNSPacket *p=0);
      
      bool isMaster(const string &name, const string &ip);
      void getUnfreshSlaveInfos(vector<DomainInfo>* unfreshDomains);
      bool getDomainInfo(const string &domain, DomainInfo &di);
      bool startTransaction(const string &qname, int domain_id=-1);
      bool feedRecord(const DNSResourceRecord &rr);
      bool commitTransaction();
      bool abortTransaction();
      void setFresh(u_int32_t domain_id);

      static DNSBackend *maker();
  
   private:

      MYSQL        d_database;
      MYSQL_RES*   d_result;
      string       d_suffix;
      int          d_axfrcount;
      
      void Query(const string& inQuery);
      void Execute(const string& inStatement);
      string sqlEscape(const string &nanme);

};

#endif /* PDNSBACKEND_HH */
