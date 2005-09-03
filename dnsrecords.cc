#include "dnsparser.hh"
#include <boost/lexical_cast.hpp>
using namespace std;
using namespace boost;

class ARecordContent : public DNSRecordContent
{
public:
  static void report(void)
  {
    regist(1,1,&make,"A");
   }

  static DNSRecordContent* make(const DNSRecord& dr, PacketReader& pr) 
  {
    if(dr.d_clen!=4)
      throw MOADNSException("Wrong size for A record");

    ARecordContent* ret=new ARecordContent();
    pr.copyRecord((unsigned char*) &ret->d_ip, 4);
    return ret;
  }

  uint32_t getIP() const
  {
    return d_ip;
  }
  

  string getZoneRepresentation() const
  {
    ostringstream str;
    uint32_t ip=ntohl(d_ip);

    str<< ((ip >> 24)&0xff) << ".";
    str<< ((ip >> 16)&0xff) << ".";
    str<< ((ip >>  8)&0xff) << ".";
    str<< ((ip      )&0xff);
    return str.str();
  }

private:
  uint32_t d_ip;
};

class AAAARecordContent : public DNSRecordContent
{
public:
  static void report(void)
  {
    regist(1,ns_t_aaaa,&make,"AAAA");
  }

  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr) 
  {
    if(dr.d_clen!=16)
      throw MOADNSException("Wrong size for AAAA record");

    AAAARecordContent* ret=new AAAARecordContent();
    pr.copyRecord((unsigned char*) &ret->d_ip6, 16);
    return ret;
  }
  
  string getZoneRepresentation() const
  {
    ostringstream str;

    char hex[4];
    for(size_t n=0; n< 16 ; n+=2) {
      snprintf(hex,sizeof(hex)-1, "%x", d_ip6[n]);
      str << hex;
      snprintf(hex,sizeof(hex)-1, "%02x", d_ip6[n+1]);
      str << hex;
      if(n!=14)
	str<<":";
    }

    return str.str();
  }

private:
  unsigned char d_ip6[16];
};


namespace {
  struct soatimes 
  {
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
  };
}


class OneLabelRecordContent : public DNSRecordContent
{
public:

  OneLabelRecordContent(const DNSRecord &dr, const string& nsname) : d_type(dr.d_type), d_nsname(nsname) {}

  static void report(void)
  {
    regist(1, ns_t_ns, &make, "NS");
    regist(1, ns_t_cname, &make, "CNAME");
    regist(1, ns_t_ptr, &make, "PTR");
  }

  static DNSRecordContent* make(const DNSRecord &dr, PacketReader &pr) 
  {
    return new OneLabelRecordContent(dr, pr.getLabel());
  }

  string getZoneRepresentation() const
  {
    return d_nsname;
  }

private:
  uint16_t d_type;
  string d_nsname;

};

class SOARecordContent : public DNSRecordContent
{
public:

  SOARecordContent(const string& mname, const string& rname, const struct soatimes& st) 
    : d_mname(mname), d_rname(rname)
  {
    d_st=st;
  }

  static void report(void)
  {
    regist(1,ns_t_soa,&make,"SOA");
  }

  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr) 
  {
    uint16_t nowpos(pr.d_pos);
    string mname=pr.getLabel();
    string rname=pr.getLabel();

    uint16_t left=dr.d_clen - (pr.d_pos-nowpos);

    if(left!=sizeof(struct soatimes))
      throw MOADNSException("SOA RDATA has wrong size: "+lexical_cast<string>(left)+ ", should be "+lexical_cast<string>(sizeof(struct soatimes)));

    struct soatimes st;
    pr.copyRecord((unsigned char*)&st, sizeof(struct soatimes));

    st.serial=ntohl(st.serial);
    st.refresh=ntohl(st.refresh);
    st.retry=ntohl(st.retry);
    st.expire=ntohl(st.expire);
    st.minimum=ntohl(st.minimum);
    
    return new SOARecordContent(mname, rname, st);
  }

  string getZoneRepresentation() const
  {
    ostringstream str;

    str<<d_mname<<" "<<d_rname<<" ";
    str<<d_st.serial<<" " << d_st.refresh <<" " <<d_st.retry << " " << d_st.expire<< " "<<d_st.minimum;
    return str.str();
  }


  
private:
  string d_mname;
  string d_rname;
  struct soatimes d_st;
};

class MXRecordContent : public DNSRecordContent
{
public:

  MXRecordContent(uint16_t preference, const string& mxname) 
    : d_preference(preference), d_mxname(mxname)
  {
  }

  static void report(void)
  {
    regist(1,ns_t_mx,&make,"MX");
  }

  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr) 
  {
    uint16_t preference=pr.get16BitInt();
    string mxname=pr.getLabel();

    return new MXRecordContent(preference, mxname);
  }

  string getZoneRepresentation() const
  {
    ostringstream str;
    str<<d_preference<<" "<<d_mxname;
    return str.str();
  }

private:
  uint16_t d_preference;
  string d_mxname;
};


static struct Reporter
{
  Reporter()
  {
    ARecordContent::report();
    AAAARecordContent::report();
    OneLabelRecordContent::report();
    SOARecordContent::report();
    MXRecordContent::report();
    MXRecordContent::regist(1,255,0,"ANY");
  }
} reporter __attribute__((init_priority(65535)));
