/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

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
}                                                                                                  \
                                                                                                   \
RNAME##RecordContent::RNAME##RecordContent(const string& zoneData)                                 \
{                                                                                                  \
  RecordTextReader rtr(zoneData);                                                                  \
  xfrPacket(rtr);                                                                                  \
}                                                                                                  \
                                                                                                   \
string RNAME##RecordContent::getZoneRepresentation() const                                         \
{                                                                                                  \
  string ret;                                                                                      \
  RecordTextWriter rtw(ret);                                                                       \
  const_cast<RNAME##RecordContent*>(this)->xfrPacket(rtw);                                         \
  return ret;                                                                                      \
}                                                                                                  
                                                                                           

#define boilerplate_conv(RNAME, CONV)                             \
template<class Convertor>                                         \
void RNAME##RecordContent::xfrPacket(Convertor& conv)             \
{                                                                 \
  CONV;                                                           \
}                                                                 \


boilerplate(A, ns_t_a)

template<class Convertor>
void ARecordContent::xfrPacket(Convertor& conv)
{
  conv.xfrIP(d_ip);
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


boilerplate(NS, ns_t_ns)
boilerplate_conv(NS, conv.xfrLabel(d_content))

boilerplate(PTR, ns_t_ptr)
boilerplate_conv(PTR, conv.xfrLabel(d_content))

boilerplate(CNAME, ns_t_cname)
boilerplate_conv(CNAME, conv.xfrLabel(d_content))

boilerplate(TXT, ns_t_txt)
boilerplate_conv(TXT, conv.xfrText(d_text))


boilerplate(HINFO, ns_t_hinfo)
boilerplate_conv(HINFO,   conv.xfrText(d_cpu);   conv.xfrText(d_host))

boilerplate(RP, ns_t_rp)
boilerplate_conv(RP,   conv.xfrLabel(d_mbox);   conv.xfrLabel(d_info))


boilerplate(MX, ns_t_mx)

MXRecordContent::MXRecordContent(uint16_t preference, const string& mxname) : d_preference(preference), d_mxname(mxname)
{
}

template<class Convertor>
void MXRecordContent::xfrPacket(Convertor& conv)
{
  conv.xfr16BitInt(d_preference);
  conv.xfrLabel(d_mxname);
}

boilerplate(NAPTR, ns_t_naptr)

template<class Convertor>
void NAPTRRecordContent::xfrPacket(Convertor& conv)
{
  conv.xfr16BitInt(d_order);    conv.xfr16BitInt(d_preference);
  conv.xfrText(d_flags);        conv.xfrText(d_services);         conv.xfrText(d_regexp);
  conv.xfrLabel(d_replacement);
}


boilerplate(SRV, ns_t_srv)
SRVRecordContent::SRVRecordContent(uint16_t preference, uint16_t weight, uint16_t port, const string& target) 
  : d_preference(preference), d_weight(weight), d_port(port), d_target(target)
{}

template<class Convertor> void SRVRecordContent::xfrPacket(Convertor& conv)
{
  conv.xfr16BitInt(d_preference);   conv.xfr16BitInt(d_weight);   conv.xfr16BitInt(d_port);
  conv.xfrLabel(d_target);
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


static struct Reporter
{
  Reporter()
  {
    ARecordContent::report();
    AAAARecordContent::report();
    //   OneLabelRecordContent::report();
    NSRecordContent::report();
    CNAMERecordContent::report();
    PTRRecordContent::report();
    TXTRecordContent::report();
    SOARecordContent::report();
    MXRecordContent::report();
    NAPTRRecordContent::report();
    SRVRecordContent::report();
    RPRecordContent::report();
    DNSRecordContent::regist(1,255,0,"ANY");
  }
} reporter __attribute__((init_priority(65535)));
