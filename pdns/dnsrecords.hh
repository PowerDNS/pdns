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
#pragma once
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dnsparser.hh"
#include "dnswriter.hh"
#include "lock.hh"
#include "rcpgenerator.hh"
#include <set>
#include <bitset>
#include "namespaces.hh"
#include "iputils.hh"
#include "svc-records.hh"

struct ReportIsOnlyCallableByReportAllTypes;

#define includeboilerplate(RNAME)   RNAME##RecordContent(const DNSRecord& dr, PacketReader& pr); \
  RNAME##RecordContent(const string& zoneData);                                                  \
  static void report(const ReportIsOnlyCallableByReportAllTypes& guard);                         \
  static std::shared_ptr<DNSRecordContent> make(const DNSRecord &dr, PacketReader& pr);          \
  static std::shared_ptr<DNSRecordContent> make(const string& zonedata);                         \
  string getZoneRepresentation(bool noDot=false) const override;                                 \
  void toPacket(DNSPacketWriter& pw) const override;                                             \
  uint16_t getType() const override { return QType::RNAME; }                                     \
  template<class Convertor> void xfrPacket(Convertor& conv, bool noDot=false) const;             \
  template<class Convertor> void xfrPacket(Convertor& conv, bool noDot=false);

class NAPTRRecordContent : public DNSRecordContent
{
public:
  NAPTRRecordContent(uint16_t order, uint16_t preference, string flags, string services, string regexp, DNSName replacement);

  includeboilerplate(NAPTR)
  template<class Convertor> void xfrRecordContent(Convertor& conv);
  const string& getFlags() const
  {
    return d_flags;
  }
  const DNSName& getReplacement() const
  {
    return d_replacement;
  }
private:
  uint16_t d_order, d_preference;
  string d_flags, d_services, d_regexp;
  DNSName d_replacement;
};


class ARecordContent : public DNSRecordContent
{
public:
  explicit ARecordContent(const ComboAddress& ca);
  explicit ARecordContent(uint32_t ip);
  includeboilerplate(A)
  void doRecordCheck(const DNSRecord& dr);
  ComboAddress getCA(int port=0) const;
  bool operator==(const DNSRecordContent& rhs) const override
  {
    if(typeid(*this) != typeid(rhs))
      return false;
    return d_ip == dynamic_cast<const ARecordContent&>(rhs).d_ip;
  }
private:
  uint32_t d_ip;
};

class AAAARecordContent : public DNSRecordContent
{
public:
  AAAARecordContent(std::string &val);
  explicit AAAARecordContent(const ComboAddress& ca);
  includeboilerplate(AAAA)
  ComboAddress getCA(int port=0) const;
  bool operator==(const DNSRecordContent& rhs) const override
  {
    if(typeid(*this) != typeid(rhs))
      return false;
    return d_ip6 == dynamic_cast<const decltype(this)>(&rhs)->d_ip6;
  }
private:
  string d_ip6; // why??
};

class MXRecordContent : public DNSRecordContent
{
public:
  MXRecordContent(uint16_t preference, DNSName  mxname);

  includeboilerplate(MX)

  uint16_t d_preference;
  DNSName d_mxname;

  bool operator==(const DNSRecordContent& rhs) const override
  {
    if(typeid(*this) != typeid(rhs))
      return false;
    auto rrhs =dynamic_cast<const decltype(this)>(&rhs);
    return std::tie(d_preference, d_mxname) == std::tie(rrhs->d_preference, rrhs->d_mxname);
  }

};

class KXRecordContent : public DNSRecordContent
{
public:
  KXRecordContent(uint16_t preference, const DNSName& exchanger);

  includeboilerplate(KX)

private:
  uint16_t d_preference;
  DNSName d_exchanger;
};

class IPSECKEYRecordContent : public DNSRecordContent
{
public:
  IPSECKEYRecordContent(uint16_t preference, uint8_t gatewaytype, uint8_t algo, const DNSName& gateway, const string& publickey);

  includeboilerplate(IPSECKEY)

private:
  uint32_t d_ip4;
  DNSName d_gateway;
  string d_publickey;
  string d_ip6;
  uint8_t d_preference, d_gatewaytype, d_algorithm;
};

class DHCIDRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(DHCID)

private:
  string d_content;
};


class SRVRecordContent : public DNSRecordContent
{
public:
  SRVRecordContent(uint16_t preference, uint16_t weight, uint16_t port, DNSName  target);

  includeboilerplate(SRV)

  uint16_t d_weight, d_port;
  DNSName d_target;
  uint16_t d_preference;
};

class TSIGRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(TSIG)
  TSIGRecordContent() = default;

  uint16_t d_origID{0};
  uint16_t d_fudge{0};

  DNSName d_algoName;
  string d_mac;
  string d_otherData;
  uint64_t d_time{0};
  //  uint16_t d_macSize;
  uint16_t d_eRcode{0};
  // uint16_t d_otherLen
};


class TXTRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(TXT)

  string d_text;
};

#ifdef HAVE_LUA_RECORDS
class LUARecordContent : public DNSRecordContent
{
public:
  includeboilerplate(LUA)
  string getCode() const;
  uint16_t d_type;
  string d_code;
};
#endif

class ENTRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(ENT)
};

class SPFRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(SPF)
  const std::string& getText() const
  {
    return d_text;
  }

private:
  string d_text;
};


class NSRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(NS)
  explicit NSRecordContent(const DNSName& content) : d_content(content){}
  const DNSName& getNS() const { return d_content; }
  bool operator==(const DNSRecordContent& rhs) const override
  {
    if(typeid(*this) != typeid(rhs))
      return false;
    auto rrhs =dynamic_cast<const decltype(this)>(&rhs);
    return d_content == rrhs->d_content;
  }

private:
  DNSName d_content;
};

class PTRRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(PTR)
  explicit PTRRecordContent(const DNSName& content) : d_content(content){}
  const DNSName& getContent() const { return d_content; }
private:
  DNSName d_content;
};

class CNAMERecordContent : public DNSRecordContent
{
public:
  includeboilerplate(CNAME)
  CNAMERecordContent(const DNSName& content) : d_content(content){}
  DNSName getTarget() const { return d_content; }
private:
  DNSName d_content;
};

#if !defined(RECURSOR)
class ALIASRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(ALIAS)

  [[nodiscard]] const DNSName& getContent() const
  {
    return d_content;
  }
private:
  DNSName d_content;
};
#endif

class DNAMERecordContent : public DNSRecordContent
{
public:
  includeboilerplate(DNAME)
  DNAMERecordContent(const DNSName& content) : d_content(content){}
  const DNSName& getTarget() const { return d_content; }
private:
  DNSName d_content;
};


class MBRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(MB)

private:
  DNSName d_madname;
};

class MGRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(MG)

private:
  DNSName d_mgmname;
};

class MRRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(MR)

private:
  DNSName d_alias;
};

class MINFORecordContent : public DNSRecordContent
{
public:
  includeboilerplate(MINFO)

private:
  DNSName d_rmailbx;
  DNSName d_emailbx;
};

class OPTRecordContent : public DNSRecordContent
{
public:
  OPTRecordContent() = default;
  includeboilerplate(OPT)
  void getData(vector<pair<uint16_t, string> > &opts) const;
private:
  string d_data;
};


class HINFORecordContent : public DNSRecordContent
{
public:
  includeboilerplate(HINFO)

private:
  string d_cpu, d_host;
};

class RPRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(RP)

private:
  DNSName d_mbox, d_info;
};


class DNSKEYRecordContent : public DNSRecordContent
{
public:
  DNSKEYRecordContent();
  includeboilerplate(DNSKEY)
  uint16_t getTag() const;

  uint16_t d_flags{0};
  uint8_t d_protocol{0};
  uint8_t d_algorithm{0};
  string d_key;
  bool operator<(const DNSKEYRecordContent& rhs) const
  {
    return std::tie(d_flags, d_protocol, d_algorithm, d_key) <
      std::tie(rhs.d_flags, rhs.d_protocol, rhs.d_algorithm, rhs.d_key);
  }
};

class CDNSKEYRecordContent : public DNSRecordContent
{
public:
  CDNSKEYRecordContent();
  includeboilerplate(CDNSKEY)
  uint16_t getTag();

  uint16_t d_flags{0};
  uint8_t d_protocol{0};
  uint8_t d_algorithm{0};
  string d_key;
};

class DSRecordContent : public DNSRecordContent
{
public:
  DSRecordContent();
  bool operator==(const DNSRecordContent& rhs) const override
  {
    if(typeid(*this) != typeid(rhs))
      return false;
    auto rrhs =dynamic_cast<const decltype(this)>(&rhs);
    return std::tie(d_tag, d_algorithm, d_digesttype, d_digest) ==
      std::tie(rrhs->d_tag, rrhs->d_algorithm, rrhs->d_digesttype, rrhs->d_digest);
  }
  bool operator<(const DSRecordContent& rhs) const
  {
    return std::tie(d_tag, d_algorithm, d_digesttype, d_digest) <
      std::tie(rhs.d_tag, rhs.d_algorithm, rhs.d_digesttype, rhs.d_digest);
  }

  includeboilerplate(DS)

  uint16_t d_tag{0};
  uint8_t d_algorithm{0}, d_digesttype{0};
  string d_digest;
};

class CDSRecordContent : public DNSRecordContent
{
public:
  CDSRecordContent();
  includeboilerplate(CDS)

  uint16_t d_tag{0};
  uint8_t d_algorithm{0}, d_digesttype{0};
  string d_digest;
};

class DLVRecordContent : public DNSRecordContent
{
public:
  DLVRecordContent();
  includeboilerplate(DLV)

  uint16_t d_tag{0};
  uint8_t d_algorithm{0}, d_digesttype{0};
  string d_digest;
};


class SSHFPRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(SSHFP)

private:
  uint8_t d_algorithm, d_fptype;
  string d_fingerprint;
};

class KEYRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(KEY)

private:
  uint16_t d_flags;
  uint8_t d_protocol, d_algorithm;
  string d_certificate;
};

class AFSDBRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(AFSDB)

private:
  uint16_t d_subtype;
  DNSName d_hostname;
};


#ifdef CERT
#error likely openssl/ssl2.h is included, defining CERT, avoid that or undef CERT before including dnsrecords.hh
#endif

class CERTRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(CERT)

private:
  uint16_t d_type, d_tag;
  string d_certificate;
  uint8_t d_algorithm;
};

class TLSARecordContent : public DNSRecordContent
{
public:
  includeboilerplate(TLSA)

private:
  uint8_t d_certusage, d_selector, d_matchtype;
  string d_cert;
};

class SMIMEARecordContent : public DNSRecordContent
{
public:
  includeboilerplate(SMIMEA)

private:
  uint8_t d_certusage, d_selector, d_matchtype;
  string d_cert;
};

class OPENPGPKEYRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(OPENPGPKEY)

private:
  string d_keyring;
};

class SVCBBaseRecordContent : public DNSRecordContent
{
  public:
    const DNSName& getTarget() const {return d_target;}
    uint16_t getPriority() const {return d_priority;}
    // Returns true if a value for |key| was set to 'auto'
    bool autoHint(const SvcParam::SvcParamKey &key) const;
    // Sets the |addresses| to the existing hints for |key|
    void setHints(const SvcParam::SvcParamKey &key, const std::vector<ComboAddress> &addresses);
    // Removes the parameter for |key| from d_params
    void removeParam(const SvcParam::SvcParamKey &key);
    // Whether or not there are any parameter
    bool hasParams() const;
    // Whether or not the param of |key| exists
    bool hasParam(const SvcParam::SvcParamKey &key) const;
    // Get the parameter with |key|, will throw out_of_range if param isn't there
    SvcParam getParam(const SvcParam::SvcParamKey &key) const;
    virtual std::shared_ptr<SVCBBaseRecordContent> clone() const = 0;

  protected:
    std::set<SvcParam> d_params;
    DNSName d_target;
    uint16_t d_priority;

    // Get the iterator to parameter with |key|, return value can be d_params::end
  std::set<SvcParam>::const_iterator getParamIt(const SvcParam::SvcParamKey &key) const;
};

class SVCBRecordContent : public SVCBBaseRecordContent
{
public:
  includeboilerplate(SVCB)
  std::shared_ptr<SVCBBaseRecordContent> clone() const override;
};

class HTTPSRecordContent : public SVCBBaseRecordContent
{
public:
  includeboilerplate(HTTPS)
  std::shared_ptr<SVCBBaseRecordContent> clone() const override;
};

class RRSIGRecordContent : public DNSRecordContent
{
public:
  RRSIGRecordContent();
  includeboilerplate(RRSIG)

  uint16_t d_type{0};
  uint16_t d_tag{0};
  DNSName d_signer;
  string d_signature;
  uint32_t d_originalttl{0}, d_sigexpire{0}, d_siginception{0};
  uint8_t d_algorithm{0}, d_labels{0};
};

//namespace {
  struct soatimes
  {
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
  };
//}

class RKEYRecordContent : public DNSRecordContent
{
public:
  RKEYRecordContent();
  includeboilerplate(RKEY)
  uint16_t d_flags{0};
  uint8_t d_protocol{0}, d_algorithm{0};
  string d_key;
};

class SOARecordContent : public DNSRecordContent
{
public:
  includeboilerplate(SOA)
  SOARecordContent(DNSName  mname, DNSName  rname, const struct soatimes& st);

  DNSName d_mname;
  DNSName d_rname;
  struct soatimes d_st;
};

class ZONEMDRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(ZONEMD)
  //ZONEMDRecordContent(uint32_t serial, uint8_t scheme, uint8_t hashalgo, string digest);

  uint32_t d_serial;
  uint8_t d_scheme;
  uint8_t d_hashalgo;
  string d_digest;
};

class NSECBitmap
{
public:
  NSECBitmap(): d_bitset(nullptr)
  {
  }
  NSECBitmap(const NSECBitmap& rhs): d_set(rhs.d_set)
  {
    if (rhs.d_bitset) {
      d_bitset = std::make_unique<std::bitset<nbTypes>>(*(rhs.d_bitset));
    }
  }
  NSECBitmap& operator=(const NSECBitmap& rhs)
  {
    d_set = rhs.d_set;

    if (rhs.d_bitset) {
      d_bitset = std::make_unique<std::bitset<nbTypes>>(*(rhs.d_bitset));
    }

    return *this;
  }
  NSECBitmap(NSECBitmap&& rhs) noexcept :
    d_bitset(std::move(rhs.d_bitset)), d_set(std::move(rhs.d_set))
  {
  }
  bool isSet(uint16_t type) const
  {
    if (d_bitset) {
      return d_bitset->test(type);
    }
    return d_set.count(type);
  }
  void set(uint16_t type)
  {
    if (!d_bitset) {
      if (d_set.size() >= 200) {
        migrateToBitSet();
      }
    }
    if (d_bitset) {
      d_bitset->set(type);
    }
    else {
      d_set.insert(type);
    }
  }
  size_t count() const
  {
    if (d_bitset) {
      return d_bitset->count();
    }
    else {
      return d_set.size();
    }
  }

  void fromPacket(PacketReader& pr);
  void toPacket(DNSPacketWriter& pw) const;
  std::string getZoneRepresentation() const;

  static constexpr size_t const nbTypes = 65536;

private:

  void migrateToBitSet()
  {
    d_bitset = std::make_unique<std::bitset<nbTypes>>();
    for (const auto& type : d_set) {
      d_bitset->set(type);
    }
    d_set.clear();
  }
  /* using a dynamic set is very efficient for a small number of
     types covered (~200), but uses a lot of memory (up to 3MB)
     when there are a lot of them.
     So we start with the set, but allocate and switch to a bitset
     if the number of covered types increases a lot */
  std::unique_ptr<std::bitset<nbTypes>> d_bitset;
  std::set<uint16_t> d_set;
};

class NSECRecordContent : public DNSRecordContent
{
public:
  static void report(const ReportIsOnlyCallableByReportAllTypes& guard);
  NSECRecordContent() = default;
  NSECRecordContent(const string& content, const DNSName& zone=DNSName());

  static std::shared_ptr<DNSRecordContent> make(const DNSRecord &dr, PacketReader& pr);
  static std::shared_ptr<DNSRecordContent> make(const string& content);
  string getZoneRepresentation(bool noDot=false) const override;
  void toPacket(DNSPacketWriter& pw) const override;
  uint16_t getType() const override
  {
    return QType::NSEC;
  }
  bool isSet(uint16_t type) const
  {
    return d_bitmap.isSet(type);
  }
  void set(uint16_t type)
  {
    d_bitmap.set(type);
  }
  void set(const NSECBitmap& bitmap)
  {
    d_bitmap = bitmap;
  }
  size_t numberOfTypesSet() const
  {
    return d_bitmap.count();
  }

  DNSName d_next;
private:
  NSECBitmap d_bitmap;
};

class NSEC3RecordContent : public DNSRecordContent
{
public:
  static void report(const ReportIsOnlyCallableByReportAllTypes& guard);
  NSEC3RecordContent() = default;
  NSEC3RecordContent(const string& content, const DNSName& zone=DNSName());

  static std::shared_ptr<DNSRecordContent> make(const DNSRecord &dr, PacketReader& pr);
  static std::shared_ptr<DNSRecordContent> make(const string& content);
  string getZoneRepresentation(bool noDot=false) const override;
  void toPacket(DNSPacketWriter& pw) const override;

  uint8_t d_algorithm{0}, d_flags{0};
  uint16_t d_iterations{0};
  string d_salt;
  string d_nexthash;

  uint16_t getType() const override
  {
    return QType::NSEC3;
  }
  bool isSet(uint16_t type) const
  {
    return d_bitmap.isSet(type);
  }
  void set(uint16_t type)
  {
    d_bitmap.set(type);
  }
  void set(const NSECBitmap& bitmap)
  {
    d_bitmap = bitmap;
  }
  size_t numberOfTypesSet() const
  {
    return d_bitmap.count();
  }
  bool isOptOut() const
  {
    return d_flags & 1;
  }

private:
  NSECBitmap d_bitmap;
};

class CSYNCRecordContent : public DNSRecordContent
{
public:
  static void report(const ReportIsOnlyCallableByReportAllTypes& guard);
  CSYNCRecordContent() = default;
  CSYNCRecordContent(const string& content, const DNSName& zone=DNSName());

  static std::shared_ptr<DNSRecordContent> make(const DNSRecord &dr, PacketReader& pr);
  static std::shared_ptr<DNSRecordContent> make(const string& content);
  string getZoneRepresentation(bool noDot=false) const override;
  void toPacket(DNSPacketWriter& pw) const override;

  uint16_t getType() const override
  {
    return QType::CSYNC;
  }

  void set(uint16_t type)
  {
    d_bitmap.set(type);
  }

private:
  uint32_t d_serial{0};
  uint16_t d_flags{0};
  NSECBitmap d_bitmap;
};

class NSEC3PARAMRecordContent : public DNSRecordContent
{
public:
  static void report(const ReportIsOnlyCallableByReportAllTypes& guard);
  NSEC3PARAMRecordContent() = default;
  NSEC3PARAMRecordContent(const string& content, const DNSName& zone=DNSName());

  static std::shared_ptr<DNSRecordContent> make(const DNSRecord &dr, PacketReader& pr);
  static std::shared_ptr<DNSRecordContent> make(const string& content);
  string getZoneRepresentation(bool noDot=false) const override;
  void toPacket(DNSPacketWriter& pw) const override;

  uint16_t getType() const override
  {
    return QType::NSEC3PARAM;
  }


  uint8_t d_algorithm{0}, d_flags{0};
  uint16_t d_iterations{0};
  string d_salt;
};


class LOCRecordContent : public DNSRecordContent
{
public:
  static void report(const ReportIsOnlyCallableByReportAllTypes& guard);
  LOCRecordContent() = default;
  LOCRecordContent(const string& content, const string& zone="");

  static std::shared_ptr<DNSRecordContent> make(const DNSRecord &dr, PacketReader& pr);
  static std::shared_ptr<DNSRecordContent> make(const string& content);
  string getZoneRepresentation(bool noDot=false) const override;
  void toPacket(DNSPacketWriter& pw) const override;

  uint8_t d_version{0}, d_size{0}, d_horizpre{0}, d_vertpre{0};
  uint32_t d_latitude{0}, d_longitude{0}, d_altitude{0};
  uint16_t getType() const override
  {
    return QType::LOC;
  }

private:
};


class NIDRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(NID);

private:
  uint16_t d_preference;
  NodeOrLocatorID d_node_id;
};

class L32RecordContent : public DNSRecordContent
{
public:
  includeboilerplate(L32);

private:
  uint16_t d_preference;
  uint32_t d_locator;
};

class L64RecordContent : public DNSRecordContent
{
public:
  includeboilerplate(L64);

private:
  uint16_t d_preference;
  NodeOrLocatorID d_locator;
};

class LPRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(LP);

private:
  uint16_t d_preference;
  DNSName d_fqdn;
};

class EUI48RecordContent : public DNSRecordContent
{
public:
  EUI48RecordContent() = default;
  static void report(const ReportIsOnlyCallableByReportAllTypes& guard);
  static std::shared_ptr<DNSRecordContent> make(const DNSRecord &dr, PacketReader& pr);
  static std::shared_ptr<DNSRecordContent> make(const string& zone); // FIXME400: DNSName& zone?
  string getZoneRepresentation(bool noDot=false) const override;
  void toPacket(DNSPacketWriter& pw) const override;
  uint16_t getType() const override { return QType::EUI48; }
private:
 // storage for the bytes
 uint8_t d_eui48[6];
};

class EUI64RecordContent : public DNSRecordContent
{
public:
  EUI64RecordContent() = default;
  static void report(const ReportIsOnlyCallableByReportAllTypes& guard);
  static std::shared_ptr<DNSRecordContent> make(const DNSRecord &dr, PacketReader& pr);
  static std::shared_ptr<DNSRecordContent> make(const string& zone); // FIXME400: DNSName& zone?
  string getZoneRepresentation(bool noDot=false) const override;
  void toPacket(DNSPacketWriter& pw) const override;
  uint16_t getType() const override { return QType::EUI64; }
private:
 // storage for the bytes
 uint8_t d_eui64[8];
};

#define APL_FAMILY_IPV4 1
#define APL_FAMILY_IPV6 2
typedef struct s_APLRDataElement {
  uint16_t d_family;
  uint8_t d_prefix;
  bool d_n : 1;
  unsigned int d_afdlength : 7;
  union u_d_ip {
      uint8_t d_ip4[4];
      uint8_t d_ip6[16];
  } d_ip;
} APLRDataElement;
class APLRecordContent : public DNSRecordContent
{
public:
  APLRecordContent() = default;
  includeboilerplate(APL)
private:
  std::vector<APLRDataElement> aplrdata;
  APLRDataElement parseAPLElement(const string &element);
};


class TKEYRecordContent : public DNSRecordContent
{
public:
  TKEYRecordContent();
  includeboilerplate(TKEY)

  // storage for the bytes
  uint16_t d_othersize{0};
  uint16_t d_mode{0};
  uint32_t d_inception{0};
  uint32_t d_expiration{0};

  DNSName d_algo;
  string d_key;
  string d_other;

  uint16_t d_error{0};
  uint16_t d_keysize{0};
private:
};

class URIRecordContent : public DNSRecordContent {
  public:
    includeboilerplate(URI)
  private:
    uint16_t d_priority, d_weight;
    string d_target;
};

class CAARecordContent : public DNSRecordContent {
  public:
    includeboilerplate(CAA)
  private:
    uint8_t d_flags;
    string d_tag, d_value;
};

#define boilerplate(RNAME)                                                                         \
std::shared_ptr<RNAME##RecordContent::DNSRecordContent> RNAME##RecordContent::make(const DNSRecord& dr, PacketReader& pr) \
{                                                                                                  \
  return std::make_shared<RNAME##RecordContent>(dr, pr);                                           \
}                                                                                                  \
                                                                                                   \
RNAME##RecordContent::RNAME##RecordContent(const DNSRecord& dr, PacketReader& pr)                  \
{                                                                                                  \
  doRecordCheck(dr);                                                                               \
  xfrPacket(pr);                                                                                   \
}                                                                                                  \
                                                                                                   \
std::shared_ptr<RNAME##RecordContent::DNSRecordContent> RNAME##RecordContent::make(const string& zonedata)         \
{                                                                                                  \
  return std::make_shared<RNAME##RecordContent>(zonedata);                                         \
}                                                                                                  \
                                                                                                   \
void RNAME##RecordContent::toPacket(DNSPacketWriter& pw) const                                     \
{                                                                                                  \
  this->xfrPacket(pw);                                                                             \
}                                                                                                  \
                                                                                                   \
void RNAME##RecordContent::report(const ReportIsOnlyCallableByReportAllTypes& /* unused */)        \
{                                                                                                  \
  regist(1, QType::RNAME, &RNAME##RecordContent::make, &RNAME##RecordContent::make, #RNAME);       \
  regist(254, QType::RNAME, &RNAME##RecordContent::make, &RNAME##RecordContent::make, #RNAME);     \
}                                                                                                  \
                                                                                                   \
RNAME##RecordContent::RNAME##RecordContent(const string& zoneData)                                 \
{                                                                                                  \
  try {                                                                                            \
    RecordTextReader rtr(zoneData);                                                                \
    xfrPacket(rtr);                                                                                \
  }                                                                                                \
  catch(RecordTextException& rte) {                                                                \
    throw MOADNSException("Parsing record content (try 'pdnsutil check-zone'): "+string(rte.what()));  \
  }                                                                                                \
}                                                                                                  \
                                                                                                   \
string RNAME##RecordContent::getZoneRepresentation(bool noDot) const                               \
{                                                                                                  \
  string ret;                                                                                      \
  RecordTextWriter rtw(ret, noDot);                                                                       \
  const_cast<RNAME##RecordContent*>(this)->xfrPacket(rtw);                                         \
  return ret;                                                                                      \
}


#define boilerplate_conv(RNAME, CONV)                                   \
boilerplate(RNAME)                                                      \
template<class Convertor>                                               \
void RNAME##RecordContent::xfrPacket(Convertor& conv, bool /* noDot */) \
{                                                                       \
  CONV;                                                                 \
  if (conv.eof() == false) throw MOADNSException("When parsing " #RNAME " trailing data was not parsed: '" + conv.getRemaining() + "'"); \
}                                                                       \
template<class Convertor>                                               \
void RNAME##RecordContent::xfrPacket(Convertor& conv, bool /* noDot */) const \
{                                                                       \
  CONV;                                                                 \
  if (conv.eof() == false) throw MOADNSException("When parsing " #RNAME " trailing data was not parsed: '" + conv.getRemaining() + "'"); \
}                                                                       \

struct EDNSOpts
{
  enum zFlags { DNSSECOK=32768 };
  vector<pair<uint16_t, string> > d_options;
  uint16_t d_packetsize{0};
  uint16_t d_extFlags{0};
  uint8_t d_extRCode, d_version;

  [[nodiscard]] vector<pair<uint16_t, string>>::const_iterator getFirstOption(uint16_t optionCode) const;
};
//! Convenience function that fills out EDNS0 options, and returns true if there are any

class MOADNSParser;
bool getEDNSOpts(const MOADNSParser& mdp, EDNSOpts* eo);
void reportAllTypes();
ComboAddress getAddr(const DNSRecord& dr, uint16_t defport=0);
void checkHostnameCorrectness(const DNSResourceRecord& rr);
