/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2007  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "utility.hh"
#include "dnsrecords.hh"

boilerplate_conv(A, ns_t_a, conv.xfrIP(d_ip));

uint32_t ARecordContent::getIP() const
{
  return d_ip;
}

void ARecordContent::doRecordCheck(const DNSRecord& dr)
{  
  if(dr.d_clen!=4)
    throw MOADNSException("Wrong size for A record ("+lexical_cast<string>(dr.d_clen)+")");
}

class AAAARecordContent : public DNSRecordContent
{
public:
  AAAARecordContent() : DNSRecordContent(ns_t_aaaa)
  {}

  static void report(void)
  {
    regist(1, ns_t_aaaa, &make, &make, "AAAA");
  }

  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr) 
  {
    if(dr.d_clen!=16)
      throw MOADNSException("Wrong size for AAAA record");

    AAAARecordContent* ret=new AAAARecordContent();
    pr.copyRecord((unsigned char*) &ret->d_ip6, 16);
    return ret;
  }

  static DNSRecordContent* make(const string& zone) 
  {
    AAAARecordContent *ar=new AAAARecordContent();
    if(Utility::inet_pton( AF_INET6, zone.c_str(), static_cast< void * >( ar->d_ip6 )) < 0)
      throw MOADNSException("Asked to encode '"+zone+"' as an IPv6 address, but does not parse");
    return ar;
  }

  void toPacket(DNSPacketWriter& pw)
  {
    string blob(d_ip6, d_ip6+16);
    pw.xfrBlob(blob);
  }
  
  string getZoneRepresentation() const
  {
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family=AF_INET6;
    memcpy(&addr.sin6_addr, d_ip6, 16);

    char tmp[128];
    tmp[0]=0;
    Utility::inet_ntop(AF_INET6, (const char*)& addr.sin6_addr, tmp, sizeof(tmp));
    return tmp;
  }

private:
  unsigned char d_ip6[16];
};


void NSECRecordContent::report(void)
{
  regist(1, 47, &make, &make, "NSEC");
}

DNSRecordContent* NSECRecordContent::make(const string& content)
{
  return new NSECRecordContent(content);
}

NSECRecordContent::NSECRecordContent(const string& content, const string& zone) : DNSRecordContent(47)
{
  RecordTextReader rtr(content, zone);
  rtr.xfrLabel(d_next);

  while(!rtr.eof()) {
    uint16_t type;
    rtr.xfrType(type);
    d_set.insert(type);
  }
}

void NSECRecordContent::toPacket(DNSPacketWriter& pw)
{
  pw.xfrLabel(d_next);

  uint8_t res[34];
  memset(res, 0, sizeof(res));

  set<uint16_t>::const_iterator i;
  for(i=d_set.begin(); i != d_set.end() && *i<255; ++i){
    res[2+*i/8] |= 1 << (7-(*i%8));
  }
  int len=0;
  if(!d_set.empty()) 
    len=1+*--i/8;

  res[1]=len;

  string tmp;
  tmp.assign(res, res+len+2);
  pw.xfrBlob(tmp);
}

NSECRecordContent::DNSRecordContent* NSECRecordContent::make(const DNSRecord &dr, PacketReader& pr) 
{
  NSECRecordContent* ret=new NSECRecordContent();
  pr.xfrLabel(ret->d_next);
  string bitmap;
  pr.xfrBlob(bitmap);
  
  // 00 06 20 00 00 00 00 03  -> NS RRSIG NSEC  ( 2, 46, 47 ) counts from left
  
  if(bitmap.size() < 2)
    throw MOADNSException("NSEC record with impossibly small bitmap");
  
  if(bitmap[0])
    throw MOADNSException("Can't deal with NSEC mappings > 255 yet");
  
  unsigned int len=bitmap[1];
  if(bitmap.size()!=2+len)
    throw MOADNSException("Can't deal with multi-part NSEC mappings yet");
  
  for(unsigned int n=0 ; n < len ; ++n) {
    uint8_t val=bitmap[2+n];
    for(int bit = 0; bit < 8 ; ++bit , val>>=1)
      if(val & 1) {
	ret->d_set.insert((7-bit) + 8*(n));
      }
  }
  
  return ret;
}

string NSECRecordContent::getZoneRepresentation() const
{
  string ret;
  RecordTextWriter rtw(ret);
  rtw.xfrLabel(d_next);
  
  for(set<uint16_t>::const_iterator i=d_set.begin(); i!=d_set.end(); ++i) {
    ret+=" ";
    ret+=NumberToType(*i);
  }
  
  return ret;
}

boilerplate_conv(NS, ns_t_ns, conv.xfrLabel(d_content, true));
boilerplate_conv(PTR, ns_t_ptr, conv.xfrLabel(d_content, true));
boilerplate_conv(CNAME, ns_t_cname, conv.xfrLabel(d_content, true));
boilerplate_conv(MR, ns_t_mr, conv.xfrLabel(d_alias, false));
boilerplate_conv(TXT, ns_t_txt, conv.xfrText(d_text, true));
boilerplate_conv(SPF, 99, conv.xfrText(d_text, true));
boilerplate_conv(HINFO, ns_t_hinfo,  conv.xfrText(d_cpu);   conv.xfrText(d_host));

boilerplate_conv(RP, ns_t_rp,
		 conv.xfrLabel(d_mbox);   
		 conv.xfrLabel(d_info)
		 );


boilerplate_conv(OPT, ns_t_opt,
		 conv.xfrText(d_data)
		 );


boilerplate_conv(TSIG, ns_t_tsig, 
		 conv.xfrLabel(d_algoName);
		 conv.xfr48BitInt(d_time);
		 conv.xfr16BitInt(d_fudge);
		 uint16_t size=d_mac.size();
		 conv.xfr16BitInt(size);
		 conv.xfrBlob(d_mac, size);
		 conv.xfr16BitInt(d_origID);
		 conv.xfr16BitInt(d_eRcode);
		 size=d_otherData.size();
		 conv.xfr16BitInt(size);
		 conv.xfrBlob(d_otherData, size);
		 );

MXRecordContent::MXRecordContent(uint16_t preference, const string& mxname) : DNSRecordContent(ns_t_mx), d_preference(preference), d_mxname(mxname)
{
}

boilerplate_conv(MX, ns_t_mx, 
		 conv.xfr16BitInt(d_preference);
		 conv.xfrLabel(d_mxname, true);
		 )

boilerplate_conv(KX, ns_t_mx, 
		 conv.xfr16BitInt(d_preference);
		 conv.xfrLabel(d_exchanger, false);
		 )

boilerplate_conv(IPSECKEY, 45,  /* ns_t_ipsec */
		 conv.xfr8BitInt(d_preference);
		 conv.xfr8BitInt(d_gatewaytype);
		 conv.xfr8BitInt(d_algorithm);
		 conv.xfrLabel(d_gateway, false);
		 conv.xfrBlob(d_publickey);
		 )

boilerplate_conv(DHCID, 49, 
		 conv.xfrBlob(d_content);
		 )


boilerplate_conv(AFSDB, ns_t_afsdb, 
		 conv.xfr16BitInt(d_subtype);
		 conv.xfrLabel(d_hostname);
		 )


boilerplate_conv(NAPTR, ns_t_naptr,
		 conv.xfr16BitInt(d_order);    conv.xfr16BitInt(d_preference);
		 conv.xfrText(d_flags);        conv.xfrText(d_services);         conv.xfrText(d_regexp);
		 conv.xfrLabel(d_replacement);
		 )


SRVRecordContent::SRVRecordContent(uint16_t preference, uint16_t weight, uint16_t port, const string& target) 
  : DNSRecordContent(ns_t_srv), d_preference(preference), d_weight(weight), d_port(port), d_target(target)
{}

boilerplate_conv(SRV, ns_t_srv, 
		 conv.xfr16BitInt(d_preference);   conv.xfr16BitInt(d_weight);   conv.xfr16BitInt(d_port);
		 conv.xfrLabel(d_target);
		 )



SOARecordContent::SOARecordContent(const string& mname, const string& rname, const struct soatimes& st) 
  : DNSRecordContent(ns_t_soa), d_mname(mname), d_rname(rname)
{
  d_st=st;
}

boilerplate_conv(SOA, ns_t_soa, 
		 conv.xfrLabel(d_mname, true);
		 conv.xfrLabel(d_rname, true);
		 conv.xfr32BitInt(d_st.serial);
		 conv.xfr32BitInt(d_st.refresh);
		 conv.xfr32BitInt(d_st.retry);
		 conv.xfr32BitInt(d_st.expire);
		 conv.xfr32BitInt(d_st.minimum);
		 );
#undef KEY
boilerplate_conv(KEY, ns_t_key, 
		 conv.xfr16BitInt(d_flags); 
		 conv.xfr8BitInt(d_protocol); 
		 conv.xfr8BitInt(d_algorithm); 
		 conv.xfrBlob(d_certificate);
		 );

boilerplate_conv(CERT, 37, 
		 conv.xfr16BitInt(d_type); 
		 conv.xfr16BitInt(d_tag); 
		 conv.xfr8BitInt(d_algorithm); 
		 conv.xfrBlob(d_certificate);
		 )
#undef DS
boilerplate_conv(DS, 43, 
		 conv.xfr16BitInt(d_tag); 
		 conv.xfr8BitInt(d_algorithm); 
		 conv.xfr8BitInt(d_digesttype); 
		 conv.xfrHexBlob(d_digest);
		 )

boilerplate_conv(SSHFP, 44, 
		 conv.xfr8BitInt(d_algorithm); 
		 conv.xfr8BitInt(d_fptype); 
		 conv.xfrHexBlob(d_fingerprint);
		 )

boilerplate_conv(RRSIG, 46, 
		 conv.xfrType(d_type); 
  		 conv.xfr8BitInt(d_algorithm); 
  		 conv.xfr8BitInt(d_labels); 

  		 conv.xfr32BitInt(d_originalttl); 
  		 conv.xfrTime(d_sigexpire); 
  		 conv.xfrTime(d_siginception); 
		 conv.xfr16BitInt(d_tag); 
		 conv.xfrLabel(d_signer);
		 conv.xfrBlob(d_signature);
		 )
		 
boilerplate_conv(DNSKEY, 48, 
		 conv.xfr16BitInt(d_flags); 
		 conv.xfr8BitInt(d_protocol); 
		 conv.xfr8BitInt(d_algorithm); 
		 conv.xfrBlob(d_key);
		 )

void reportBasicTypes()
{
  ARecordContent::report();
  AAAARecordContent::report();
  NSRecordContent::report();
  CNAMERecordContent::report();
  MXRecordContent::report();
  SOARecordContent::report();
  SRVRecordContent::report();
  PTRRecordContent::report();
  DNSRecordContent::regist(3, ns_t_txt, &TXTRecordContent::make, &TXTRecordContent::make, "TXT");
  TXTRecordContent::report();
  DNSRecordContent::regist(1, 255, 0, 0, "ANY");
}

void reportOtherTypes()
{
   AFSDBRecordContent::report();
   SPFRecordContent::report();
   NAPTRRecordContent::report();
   LOCRecordContent::report();
   HINFORecordContent::report();
   RPRecordContent::report();
   KEYRecordContent::report();
   DNSKEYRecordContent::report();
   RRSIGRecordContent::report();
   DSRecordContent::report();
   SSHFPRecordContent::report();
   CERTRecordContent::report();
   NSECRecordContent::report();
   TSIGRecordContent::report();
   OPTRecordContent::report();
}

void reportAllTypes()
{
  reportBasicTypes();
  reportOtherTypes();
}

#if 0
static struct Reporter
{
  Reporter()
  {
    reportAllTypes();
  }
} reporter __attribute__((init_priority(65535)));
#endif
