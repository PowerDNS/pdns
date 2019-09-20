/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "pdns/dnsbackend.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/dns_random.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/version.hh"
#include <boost/algorithm/string.hpp>

/* FIRST PART */
class RandomBackend : public DNSBackend
{
public:
  RandomBackend(const string &suffix="")
  {
    setArgPrefix("random"+suffix);
    d_ourname=DNSName(getArg("hostname"));
    d_ourdomain = d_ourname;
    d_ourdomain.chopOff();
  }

  bool list(const DNSName &target, int id, bool include_disabled) override {
    return false; // we don't support AXFR
  }

  void lookup(const QType &type, const DNSName &qdomain, int zoneId, DNSPacket *p) override
  {
    if(qdomain == d_ourdomain){
      if(type.getCode() == QType::SOA || type.getCode() == QType::ANY) {
        d_answer="ns1." + d_ourdomain.toString() + " hostmaster." + d_ourdomain.toString() + " 1234567890 86400 7200 604800 300";
      } else {
        d_answer.clear();;
      }
    } else if (qdomain == d_ourname) {
      if(type.getCode() == QType::A || type.getCode() == QType::ANY) {
        ostringstream os;
        os<<dns_random(256)<<"."<<dns_random(256)<<"."<<dns_random(256)<<"."<<dns_random(256);
        d_answer=os.str(); // our random ip address
      } else {
        d_answer="";
      }
    } else {
      d_answer="";
    }
  }

  bool get(DNSResourceRecord &rr) override
  {
    if(d_answer.empty())
      return false;

    if(d_answer.find("ns1.") == 0){
      rr.qname=d_ourdomain;
      rr.qtype=QType::SOA;
    } else {
      rr.qname=d_ourname;
      rr.qtype=QType::A;
    }
    rr.qclass=QClass::IN;   // Internet class randomness.
    rr.ttl=5;               // 5 seconds
    rr.auth = 1;            // it may be random.. but it is auth!
    rr.content = d_answer;

    d_answer.clear();       // this was the last answer
    return true;
  }

private:
  string d_answer;
  DNSName d_ourname;
  DNSName d_ourdomain;
};

/* SECOND PART */

class RandomFactory : public BackendFactory
{
public:
  RandomFactory() : BackendFactory("random") {}
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"hostname","Hostname which is to be random","random.example.com");
  }
  DNSBackend *make(const string &suffix="")
  {
    return new RandomBackend(suffix);
  }
};

/* THIRD PART */

class RandomLoader
{
public:
  RandomLoader()
  {
    BackendMakers().report(new RandomFactory);
    g_log << Logger::Info << "[randombackend] This is the random backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }  
};

static RandomLoader randomLoader;
