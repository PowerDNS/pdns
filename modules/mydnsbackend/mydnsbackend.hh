#ifndef MYDNSBACKEND_HH
#define MYDNSBACKEND_HH

#include <string>
#include <map>

#include "pdns/namespaces.hh"

#include <modules/gmysqlbackend/smysql.hh>

class MyDNSBackend : public DNSBackend
{
public:
        MyDNSBackend(const string &suffix="");
        ~MyDNSBackend();
        
        void lookup(const QType &, const string &qdomain, DNSPacket *p=0, int zoneId=-1);
        bool list(const string &target, int domain_id);
        bool get(DNSResourceRecord &r);
        bool getSOA(const string& name, SOAData& soadata, DNSPacket*);
          
private:
        void Query(const string& query);
        SMySQL *d_db; 

        string d_qname;
        string d_rrtable;
        string d_soatable;
        string d_soawhere;
        string d_rrwhere;
        string d_origin;
        bool d_useminimalttl;
        unsigned int d_minimum;

};
#endif /* MYDNSBACKEND_HH */
