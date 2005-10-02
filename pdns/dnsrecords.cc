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

boilerplate_conv(A, ns_t_a, conv.xfrIP(d_ip));

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


void NSECRecordContent::report(void)
{
  regist(1, 47, &make, "NSEC");
}

NSECRecordContent::NSECRecordContent(const string& content, const string& zone)
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
  
  int len=bitmap[1];
  if(bitmap.size()!=2+len)
    throw MOADNSException("Can't deal with multi-part NSEC mappings yet");
  
  for(int n=0 ; n < len ; ++n) {
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



boilerplate_conv(NS, ns_t_ns, conv.xfrLabel(d_content));
boilerplate_conv(PTR, ns_t_ptr, conv.xfrLabel(d_content));
boilerplate_conv(CNAME, ns_t_cname, conv.xfrLabel(d_content));
boilerplate_conv(TXT, ns_t_txt, conv.xfrText(d_text));
boilerplate_conv(SPF, 99, conv.xfrText(d_text));
boilerplate_conv(HINFO, ns_t_hinfo,  conv.xfrText(d_cpu);   conv.xfrText(d_host));

boilerplate_conv(RP, ns_t_rp,
		 conv.xfrLabel(d_mbox);   
		 conv.xfrLabel(d_info)
		 );


boilerplate_conv(OPT, ns_t_opt,
		 conv.xfrText(d_data)
		 );

MXRecordContent::MXRecordContent(uint16_t preference, const string& mxname) : d_preference(preference), d_mxname(mxname)
{
}

boilerplate_conv(MX, ns_t_mx, 
		 conv.xfr16BitInt(d_preference);
		 conv.xfrLabel(d_mxname);
		 )


boilerplate_conv(NAPTR, ns_t_naptr,
		 conv.xfr16BitInt(d_order);    conv.xfr16BitInt(d_preference);
		 conv.xfrText(d_flags);        conv.xfrText(d_services);         conv.xfrText(d_regexp);
		 conv.xfrLabel(d_replacement);
		 )



SRVRecordContent::SRVRecordContent(uint16_t preference, uint16_t weight, uint16_t port, const string& target) 
  : d_preference(preference), d_weight(weight), d_port(port), d_target(target)
{}

boilerplate_conv(SRV, ns_t_srv, 
		 conv.xfr16BitInt(d_preference);   conv.xfr16BitInt(d_weight);   conv.xfr16BitInt(d_port);
		 conv.xfrLabel(d_target);
		 )



SOARecordContent::SOARecordContent(const string& mname, const string& rname, const struct soatimes& st) 
  : d_mname(mname), d_rname(rname)
{
  d_st=st;
}

boilerplate_conv(SOA, ns_t_soa, 
		 conv.xfrLabel(d_mname);
		 conv.xfrLabel(d_rname);
		 conv.xfr32BitInt(d_st.serial);
		 conv.xfr32BitInt(d_st.refresh);
		 conv.xfr32BitInt(d_st.retry);
		 conv.xfr32BitInt(d_st.expire);
		 conv.xfr32BitInt(d_st.minimum);
		 );


boilerplate_conv(DS, 43, 
		 conv.xfr16BitInt(d_tag); 
		 conv.xfr8BitInt(d_algorithm); 
		 conv.xfr8BitInt(d_digesttype); 
		 conv.xfrBlob(d_digest);
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
    SPFRecordContent::report();
    SOARecordContent::report();
    MXRecordContent::report();
    NAPTRRecordContent::report();
    SRVRecordContent::report();
    RPRecordContent::report();
    DNSKEYRecordContent::report();
    RRSIGRecordContent::report();
    DSRecordContent::report();
    NSECRecordContent::report();
    OPTRecordContent::report();
    DNSRecordContent::regist(1,255,0,"ANY");
  }
} reporter __attribute__((init_priority(65535)));
