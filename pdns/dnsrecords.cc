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
#include <boost/foreach.hpp>

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

boilerplate_conv(AAAA, ns_t_aaaa, conv.xfrIP6(d_ip6); );

boilerplate_conv(NS, ns_t_ns, conv.xfrLabel(d_content, true));
boilerplate_conv(PTR, ns_t_ptr, conv.xfrLabel(d_content, true));
boilerplate_conv(CNAME, ns_t_cname, conv.xfrLabel(d_content, true));
boilerplate_conv(MR, ns_t_mr, conv.xfrLabel(d_alias, true));
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
    code = 256 * (unsigned char)d_data[pos] + (unsigned char)d_data[pos+1];
    len = 256 * (unsigned char)d_data[pos+2] + (unsigned char)d_data[pos+3];
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

boilerplate_conv(IPSECKEY, ns_t_ipseckey,
   conv.xfr8BitInt(d_preference);
   conv.xfr8BitInt(d_gatewaytype);
   conv.xfr8BitInt(d_algorithm);
 
   // now we need to determine values
   switch(d_gatewaytype) {
   case 0: // NO KEY
     break;
   case 1: // IPv4 GW
     conv.xfrIP(d_ip4);
     break;
   case 2: // IPv6 GW
     conv.xfrIP6(d_ip6);
     break;
   case 3: // DNS label
     conv.xfrLabel(d_gateway, false); 
     break;
   default:
     throw MOADNSException("Parsing record content: invalid gateway type");
   };

   switch(d_algorithm) {
   case 0:
     break;
   case 1:
   case 2:
     conv.xfrBlob(d_publickey);
     break;
   default:
     throw MOADNSException("Parsing record content: invalid algorithm type");
   }
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
		 
boilerplate_conv(TLSA, 52, 
        	 conv.xfr8BitInt(d_certusage); 
        	 conv.xfr8BitInt(d_selector); 
        	 conv.xfr8BitInt(d_matchtype); 
        	 conv.xfrHexBlob(d_cert, true);
        	 )		 
		 
#undef DS
DSRecordContent::DSRecordContent() : DNSRecordContent(43) {}
boilerplate_conv(DS, 43, 
        	 conv.xfr16BitInt(d_tag); 
        	 conv.xfr8BitInt(d_algorithm); 
        	 conv.xfr8BitInt(d_digesttype); 
        	 conv.xfrHexBlob(d_digest, true); // keep reading across spaces
        	 )

DLVRecordContent::DLVRecordContent() : DNSRecordContent(32769) {}
boilerplate_conv(DLV,32769 , 
        	 conv.xfr16BitInt(d_tag); 
        	 conv.xfr8BitInt(d_algorithm); 
        	 conv.xfr8BitInt(d_digesttype); 
        	 conv.xfrHexBlob(d_digest, true); // keep reading across spaces
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

/* EUI48 start */

void EUI48RecordContent::report(void) 
{
    regist(1, ns_t_eui48, &make, &make, "EUI48");
}
DNSRecordContent* EUI48RecordContent::make(const DNSRecord &dr, PacketReader& pr)
{
    if(dr.d_clen!=6)
      throw MOADNSException("Wrong size for EUI48 record");

    EUI48RecordContent* ret=new EUI48RecordContent();
    pr.copyRecord((uint8_t*) &ret->d_eui48, 6);
    return ret;
}
DNSRecordContent* EUI48RecordContent::make(const string& zone)
{
    // try to parse
    EUI48RecordContent *ret=new EUI48RecordContent();
    // format is 6 hex bytes and dashes    
    if (sscanf(zone.c_str(), "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx", 
           ret->d_eui48, ret->d_eui48+1, ret->d_eui48+2, 
           ret->d_eui48+3, ret->d_eui48+4, ret->d_eui48+5) != 6) {
       throw MOADNSException("Asked to encode '"+zone+"' as an EUI48 address, but does not parse");
    }
    return ret;
}
void EUI48RecordContent::toPacket(DNSPacketWriter& pw)
{
    string blob(d_eui48, d_eui48+6);
    pw.xfrBlob(blob); 
}
string EUI48RecordContent::getZoneRepresentation() const
{
    char tmp[18]; 
    snprintf(tmp,18,"%02x-%02x-%02x-%02x-%02x-%02x", 
           d_eui48[0], d_eui48[1], d_eui48[2], 
           d_eui48[3], d_eui48[4], d_eui48[5]);
    return tmp;
}

/* EUI48 end */

/* EUI64 start */

void EUI64RecordContent::report(void)
{
    regist(1, ns_t_eui64, &make, &make, "EUI64");
}
DNSRecordContent* EUI64RecordContent::make(const DNSRecord &dr, PacketReader& pr)
{
    if(dr.d_clen!=8)
      throw MOADNSException("Wrong size for EUI64 record");

    EUI64RecordContent* ret=new EUI64RecordContent();
    pr.copyRecord((uint8_t*) &ret->d_eui64, 8);
    return ret;
}
DNSRecordContent* EUI64RecordContent::make(const string& zone)
{
    // try to parse
    EUI64RecordContent *ret=new EUI64RecordContent();
    // format is 8 hex bytes and dashes
    if (sscanf(zone.c_str(), "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx", 
           ret->d_eui64, ret->d_eui64+1, ret->d_eui64+2,
           ret->d_eui64+3, ret->d_eui64+4, ret->d_eui64+5,
           ret->d_eui64+6, ret->d_eui64+7) != 8) {
       throw MOADNSException("Asked to encode '"+zone+"' as an EUI64 address, but does not parse");
    }
    return ret;
}
void EUI64RecordContent::toPacket(DNSPacketWriter& pw)
{
    string blob(d_eui64, d_eui64+8);
    pw.xfrBlob(blob);
}
string EUI64RecordContent::getZoneRepresentation() const
{
    char tmp[24]; 
    snprintf(tmp,24,"%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x",
           d_eui64[0], d_eui64[1], d_eui64[2],
           d_eui64[3], d_eui64[4], d_eui64[5],
           d_eui64[6], d_eui64[7]);
    return tmp;
}

/* EUI64 end */


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

// "fancy records" 
boilerplate_conv(URL, QType::URL, 
        	 conv.xfrLabel(d_url);
        	 )

boilerplate_conv(MBOXFW, QType::MBOXFW, 
        	 conv.xfrLabel(d_mboxfw);
        	 )



bool getEDNSOpts(const MOADNSParser& mdp, EDNSOpts* eo)
{
  if(mdp.d_header.arcount && !mdp.d_answers.empty()) {
    BOOST_FOREACH(const MOADNSParser::answers_t::value_type& val, mdp.d_answers) {
      if(val.first.d_place == DNSRecord::Additional && val.first.d_type == QType::OPT) {
	eo->d_packetsize=val.first.d_class;
       
	EDNS0Record stuff;
	uint32_t ttl=ntohl(val.first.d_ttl);
	memcpy(&stuff, &ttl, sizeof(stuff));
	
	eo->d_extRCode=stuff.extRCode;
	eo->d_version=stuff.version;
	eo->d_Z = ntohs(stuff.Z);
	OPTRecordContent* orc = 
	  dynamic_cast<OPTRecordContent*>(val.first.d_content.get());
	if(!orc)
	  return false;
	orc->getData(eo->d_options);
	return true;
      }
    }
  }
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
   TLSARecordContent::report();
   DLVRecordContent::report();
   DNSRecordContent::regist(0xff, QType::TSIG, &TSIGRecordContent::make, &TSIGRecordContent::make, "TSIG");
   OPTRecordContent::report();
   EUI48RecordContent::report();
   EUI64RecordContent::report();
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
