/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2009  PowerDNS.COM BV

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

ARecordContent::ARecordContent(uint32_t ip) : DNSRecordContent(ns_t_a)
{
  d_ip = ip;
}

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
        	   conv.xfrBlob(d_data)
        	 );

void OPTRecordContent::getData(vector<pair<uint16_t, string> >& options)
{
  string::size_type pos=0;
  uint16_t code, len;
  while(d_data.size() >= 4 + pos) {
    code = 0xff * d_data[pos] + d_data[pos+1];
    len = 0xff * d_data[pos+2] + d_data[pos+3];
    pos+=4;

    if(pos + len > d_data.size())
      break;

    string field(d_data.c_str() + pos, len);
    pos+=len;
    options.push_back(make_pair(code, field));
  }
}

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

boilerplate_conv(KX, ns_t_kx, 
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
DSRecordContent::DSRecordContent() : DNSRecordContent(43) {}
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
        	 
RRSIGRecordContent::RRSIGRecordContent() : DNSRecordContent(46) {}

boilerplate_conv(DNSKEY, 48, 
        	 conv.xfr16BitInt(d_flags); 
        	 conv.xfr8BitInt(d_protocol); 
        	 conv.xfr8BitInt(d_algorithm); 
        	 conv.xfrBlob(d_key);
        	 )
DNSKEYRecordContent::DNSKEYRecordContent() : DNSRecordContent(48) {}

uint16_t DNSKEYRecordContent::getTag()
{
  string data=this->serialize("");
  const unsigned char* key=(const unsigned char*)data.c_str();
  unsigned int keysize=data.length();

  unsigned long ac;     /* assumed to be 32 bits or larger */
  unsigned int i;                /* loop index */
  
  for ( ac = 0, i = 0; i < keysize; ++i )
    ac += (i & 1) ? key[i] : key[i] << 8;
  ac += (ac >> 16) & 0xFFFF;
  return ac & 0xFFFF;
}

void DNSKEYRecordContent::getExpLen(uint16_t& startPos, uint16_t& expLen) const
{
  unsigned char* decoded=(unsigned char*) d_key.c_str();
  if(decoded[0] != 0) {
    startPos=1;
    expLen=decoded[0];
  }
  else {
    startPos=3;
    expLen=decoded[1]*0xff + decoded[2]; // XXX FIXME
  }
}

string DNSKEYRecordContent::getExponent() const
{
  uint16_t startPos, expLen;
  getExpLen(startPos, expLen);
  return d_key.substr(startPos, expLen);
}

string DNSKEYRecordContent::getModulus() const
{
  uint16_t startPos, expLen;
  getExpLen(startPos, expLen);

  return d_key.substr(startPos+expLen);
}


// "fancy records" 
boilerplate_conv(URL, QType::URL, 
        	 conv.xfrLabel(d_url);
        	 )

boilerplate_conv(MBOXFW, QType::MBOXFW, 
        	 conv.xfrLabel(d_mboxfw);
        	 )

bool getEDNSOpts(const MOADNSParser& mdp, EDNSOpts* eo)
{
  if(mdp.d_header.arcount && !mdp.d_answers.empty() && 
     mdp.d_answers.back().first.d_type == QType::OPT) {
    eo->d_packetsize=mdp.d_answers.back().first.d_class;
    
    EDNS0Record stuff;
    uint32_t ttl=ntohl(mdp.d_answers.back().first.d_ttl);
    memcpy(&stuff, &ttl, sizeof(stuff));

    eo->d_extRCode=stuff.extRCode;
    eo->d_version=stuff.version;
    eo->d_Z = ntohs(stuff.Z);
    OPTRecordContent* orc = 
      dynamic_cast<OPTRecordContent*>(mdp.d_answers.back().first.d_content.get());
    if(!orc)
      return false;
    orc->getData(eo->d_options);

    return true;
  }
  else
    return false;
}


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
  DNSRecordContent::regist(1, QType::ANY, 0, 0, "ANY");
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
   NSEC3RecordContent::report();
   NSEC3PARAMRecordContent::report();
   DNSRecordContent::regist(0xff, QType::TSIG, &TSIGRecordContent::make, &TSIGRecordContent::make, "TSIG");
   OPTRecordContent::report();
}

void reportFancyTypes()
{
  URLRecordContent::report();
  MBOXFWRecordContent::report();
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
