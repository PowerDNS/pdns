#include "dnsrecords.hh"



#define boilerplate(RNAME, RTYPE)                                                                         \
RNAME##RecordContent::DNSRecordContent* RNAME##RecordContent::make(const DNSRecord& dr, PacketReader& pr) \
{                                                                                                  \
  return new RNAME##RecordContent(dr, pr);                                                         \
}                                                                                                  \
                                                                                                   \
RNAME##RecordContent::RNAME##RecordContent(const DNSRecord& dr, PacketReader& pr)                  \
{                                                                                                  \
  doRecordCheck(dr);                                                                               \
  xfrPacket(pr);                                                                                   \
}                                                                                                  \
                                                                                                   \
RNAME##RecordContent::DNSRecordContent* RNAME##RecordContent::make(const string& zonedata)         \
{                                                                                                  \
  return new RNAME##RecordContent(zonedata);                                                       \
}                                                                                                  \
                                                                                                   \
void RNAME##RecordContent::toPacket(DNSPacketWriter& pw)                                           \
{                                                                                                  \
  this->xfrPacket(pw);                                                                             \
}                                                                                                  \
                                                                                                   \
void RNAME##RecordContent::report(void)                                                            \
{                                                                                                  \
  regist(1, RTYPE, &RNAME##RecordContent::make, #RNAME);                                           \
}                                                                                                  

boilerplate(A, ns_t_a)

ARecordContent::ARecordContent(const string& zone)
{  
  if(!IpToU32(zone, &d_ip))
    throw MOADNSException("Can't convert '"+zone+"' to an IP address");
}

template<class Convertor>
void ARecordContent::xfrPacket(Convertor& conv)
{
  conv.xfr32BitInt(d_ip);
  d_ip=ntohl(d_ip);
}

uint32_t ARecordContent::getIP() const
{
  return d_ip;
}
  
string ARecordContent::getZoneRepresentation() const
{
  ostringstream str;
  uint32_t ip=ntohl(d_ip);
  
  str<< ((ip >> 24)&0xff) << ".";
  str<< ((ip >> 16)&0xff) << ".";
  str<< ((ip >>  8)&0xff) << ".";
  str<< ((ip      )&0xff);
  return str.str();
}

void ARecordContent::doRecordCheck(const DNSRecord& dr)
{  
  if(dr.d_clen!=4)
    throw MOADNSException("Wrong size for A record");
}

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

boilerplate(TXT, ns_t_txt)

string TXTRecordContent::getZoneRepresentation() const
{
  return "\""+d_text+"\""; // needs escaping?
}

template<class Convertor>
void TXTRecordContent::xfrPacket(Convertor& conv)
{
  conv.xfrText(d_text);
}

TXTRecordContent::TXTRecordContent(const string& text) : d_text(text)
{
}


boilerplate(MX, ns_t_mx)

MXRecordContent::MXRecordContent(uint16_t preference, const string& mxname) : d_preference(preference), d_mxname(mxname)
{
}

MXRecordContent::MXRecordContent(const string& str)
{
  istringstream ist;
  ist>>d_preference>>d_mxname;
}

string MXRecordContent::getZoneRepresentation() const
{
  ostringstream ost;
  ost<<d_preference<<" "<<d_mxname;
  return ost.str();
}

template<class Convertor>
void MXRecordContent::xfrPacket(Convertor& conv)
{
  conv.xfr16BitInt(d_preference);
  conv.xfrLabel(d_mxname);
}


boilerplate(NAPTR, ns_t_naptr)

NAPTRRecordContent::NAPTRRecordContent(const string& zoneData)
{
  istringstream str(zoneData);
  
  str >> d_order >> d_preference >> d_flags >> d_services >> d_regexp >> d_replacement;
}

string NAPTRRecordContent::getZoneRepresentation() const
{
  ostringstream str;
  str<<d_order<<" "<<d_preference<<" \""<<d_flags<<"\" \""<<d_services<<"\" \""<<d_regexp<<"\" "<<d_replacement;
  return str.str();
}

template<class Convertor>
void NAPTRRecordContent::xfrPacket(Convertor& conv)
{
  conv.xfr16BitInt(d_order);
  conv.xfr16BitInt(d_preference);
  conv.xfrText(d_flags);
  conv.xfrText(d_services);
  conv.xfrText(d_regexp);
  conv.xfrLabel(d_replacement);
}


boilerplate(SRV, ns_t_srv)
SRVRecordContent::SRVRecordContent(uint16_t preference, uint16_t weight, uint16_t port, const string& target) 
  : d_preference(preference), d_weight(weight), d_port(port), d_target(target)
{}

template<class Convertor>
void SRVRecordContent::xfrPacket(Convertor& conv)
{
  conv.xfr16BitInt(d_preference);
  conv.xfr16BitInt(d_weight);
  conv.xfr16BitInt(d_port);
  conv.xfrLabel(d_target);
}

string SRVRecordContent::getZoneRepresentation() const
{
  ostringstream str;
  
  str<<d_preference<<" "<<d_weight<<" ";
  str<<d_port<<" " << d_target;
  return str.str();
}

SRVRecordContent::SRVRecordContent(const string& zone)
{
  istringstream str(zone);
  
  str >> d_preference >> d_weight;
  str >> d_port >> d_target;
}

boilerplate(SOA, ns_t_soa)

SOARecordContent::SOARecordContent(const string& mname, const string& rname, const struct soatimes& st) 
  : d_mname(mname), d_rname(rname)
{
  d_st=st;
}

template<class Convertor>
void SOARecordContent::xfrPacket(Convertor& conv)
{
  conv.xfrLabel(d_mname);
  conv.xfrLabel(d_rname);
  
  conv.xfr32BitInt(d_st.serial);
  conv.xfr32BitInt(d_st.refresh);
  conv.xfr32BitInt(d_st.retry);
  conv.xfr32BitInt(d_st.expire);
  conv.xfr32BitInt(d_st.minimum);
}

SOARecordContent::SOARecordContent(const string& zone)
{
  istringstream str(zone);
  
  str >> d_mname >> d_rname;
  str >> d_st.serial >>  d_st.refresh >> d_st.retry >> d_st.expire >> d_st.minimum;
}

string SOARecordContent::getZoneRepresentation() const
{
  ostringstream str;
  
  str<<d_mname<<" "<<d_rname<<" ";
  str<<d_st.serial<<" " << d_st.refresh <<" " <<d_st.retry << " " << d_st.expire<< " "<<d_st.minimum;
  return str.str();
}


static struct Reporter
{
  Reporter()
  {
    ARecordContent::report();
    AAAARecordContent::report();
    OneLabelRecordContent::report();
    TXTRecordContent::report();
    SOARecordContent::report();
    MXRecordContent::report();
    NAPTRRecordContent::report();
    SRVRecordContent::report();
  
    DNSRecordContent::regist(1,255,0,"ANY");
  }
} reporter __attribute__((init_priority(65535)));
