/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <string>
#include <vector>
#include <sys/types.h>
#include "iputils.hh"
#ifndef WIN32
# include <netdb.h> 
# include <unistd.h>
# include <sys/time.h>
# include <sys/uio.h>
# include <fcntl.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# undef res_mkquery
#endif // WIN32

#include "ahuexception.hh"
#include "dns.hh"
#include "namespaces.hh"
#include "dnsbackend.hh"

class ResolverException : public AhuException
{
public:
  ResolverException(const string &reason) : AhuException(reason){}
};

// send out an update notification for a domain to an IPv4/v6 address
int sendNotification(int sock, const string &domain, const ComboAddress& remote, uint16_t id);

// make an IPv4 or IPv6 query socket 
int makeQuerySocket(const ComboAddress& local, bool udpOrTCP);
//! Resolver class. Can be used synchronously and asynchronously, over IPv4 and over IPv6 (simultaneously)
class Resolver  : public boost::noncopyable
{
public:
  Resolver();
  ~Resolver();

  typedef vector<DNSResourceRecord> res_t;
  //! synchronously resolve domain|type at IP, store result in result, rcode in ret
  int resolve(const string &ip, const char *domain, int type, res_t* result);
  
  //! only send out a resolution request
  uint16_t sendResolve(const ComboAddress& remote, const char *domain, int type, bool dnssecOk=false,
    const string& tsigkeyname="", const string& tsigalgorithm="", const string& tsigsecret="");
  
  //! see if we got a SOA response from our sendResolve
  bool tryGetSOASerial(string* theirDomain, uint32_t* theirSerial, uint32_t* theirInception, uint32_t* theirExpire, uint16_t* id);
  
  //! convenience function that calls resolve above
  void getSoaSerial(const string &, const string &, uint32_t *);
  
private:
  int d_sock4, d_sock6;
  
  int d_type;
  int d_timeout;
  string d_domain;
  uint16_t d_randomid;
  
  ComboAddress d_remote;
};

class AXFRRetriever : public boost::noncopyable
{
  public:
    AXFRRetriever(const ComboAddress& remote, const string& zone, const string& tsigkeyname=string(), const string& tsigalgorithm=string(), const string& tsigsecret=string());
	~AXFRRetriever();
    int getChunk(Resolver::res_t &res);  
  
  private:
    void connect();
    int getLength();
    void timeoutReadn(uint16_t bytes);  

    shared_array<char> d_buf;
    string d_domain;
    int d_sock;
    int d_soacount;
    ComboAddress d_remote;
    
    string d_tsigkeyname;
    string d_tsigsecret;
    TSIGRecordContent d_trc;
};

// class that one day might be more than a function to help you get IP addresses for a nameserver
class FindNS
{
public:
  vector<string> lookup(const string &name, DNSBackend *B)
  {
    vector<string> addresses;
    
    struct addrinfo* res;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    
    for(int n = 0; n < 2; ++n) {
      hints.ai_family = n ? AF_INET : AF_INET6;
      ComboAddress remote;
      remote.sin4.sin_family = AF_INET6;
      if(!getaddrinfo(name.c_str(), 0, &hints, &res)) { 
        struct addrinfo* address = res;
        do {
          memcpy(&remote, address->ai_addr, address->ai_addrlen);
          addresses.push_back(remote.toString());
        } while((address = address->ai_next));
        freeaddrinfo(res);
      }
    }
    
    B->lookup(QType(QType::ANY),name);
    DNSResourceRecord rr;
    while(B->get(rr)) 
      if(rr.qtype.getCode() == QType::A || rr.qtype.getCode()==QType::AAAA)
        addresses.push_back(rr.content);   // SOL if you have a CNAME for an NS

    return addresses;
  }
};

