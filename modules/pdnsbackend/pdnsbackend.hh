// $Id: pdnsbackend.hh,v 1.3 2002/12/09 16:24:17 ahu Exp $

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
      bool list(int inZoneId);
      bool get(DNSResourceRecord& outRecord);
      bool getSOA(const string &name, SOAData &soadata);

      static DNSBackend *maker();
  
   private:

      MYSQL        d_database;
      MYSQL_RES*   d_result;
      
      void Query(const string& inQuery);
      string sqlEscape(const string &nanme);

};

#endif /* PDNSBACKEND_HH */
