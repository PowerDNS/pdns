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
#include "dnsrecords.hh"
#include "dnspacket.hh"

#include <string>
#include <vector>
#include <optional>
#include <map>
#include "misc.hh"

class UeberBackend;

// rules of the road: Algorithm must be set in 'make' for each KeyEngine, and will NEVER change!

class DNSCryptoKeyEngine
{
  public:
    explicit DNSCryptoKeyEngine(unsigned int algorithm) : d_algorithm(algorithm) {}
    virtual ~DNSCryptoKeyEngine() = default;
    [[nodiscard]] virtual string getName() const = 0;

    using stormap_t = std::map<std::string, std::string>;
    using storvector_t = std::vector<std::pair<std::string, std::string>>;
    virtual void create(unsigned int bits)=0;

    virtual void createFromPEMFile(DNSKEYRecordContent& /* drc */, std::FILE& /* inputFile */, const std::optional<std::reference_wrapper<const std::string>> filename = std::nullopt)
    {
      if (filename.has_value()) {
        throw std::runtime_error("Can't create key from PEM file `" + filename->get() + "`");
      }

      throw std::runtime_error("Can't create key from PEM contents");
    }

    /**
     * \brief Creates a key engine from a PEM string.
     *
     * Receives PEM contents and creates a key engine.
     *
     * \param[in] drc Key record contents to be populated.
     *
     * \param[in] contents The PEM string contents.
     *
     * \return A key engine populated with the contents of the PEM string.
     */
    void createFromPEMString(DNSKEYRecordContent& drc, const std::string& contents)
    {
      // NOLINTNEXTLINE(*-cast): POSIX APIs.
      pdns::UniqueFilePtr inputFile{fmemopen(const_cast<char*>(contents.data()), contents.length(), "r")};
      createFromPEMFile(drc, *inputFile);
    }

    [[nodiscard]] virtual storvector_t convertToISCVector() const =0;
    [[nodiscard]] std::string convertToISC() const ;

    virtual void convertToPEMFile(std::FILE& /* outputFile */) const
    {
      throw std::runtime_error(getName() + ": Conversion to PEM not supported");
    };

    /**
     * \brief Converts the key into a PEM string.
     *
     * \return A string containing the key's PEM contents.
     */
    [[nodiscard]] auto convertToPEMString() const -> std::string
    {
      const size_t buflen = 4096;

      std::string output{};
      output.resize(buflen);
      pdns::UniqueFilePtr outputFile{fmemopen(output.data(), output.length() - 1, "w")};
      convertToPEMFile(*outputFile);
      std::fflush(outputFile.get());
      output.resize(std::ftell(outputFile.get()));

      return output;
    };

    [[nodiscard]] virtual std::string sign(const std::string& msg) const =0;

    [[nodiscard]] virtual std::string hash(const std::string& msg) const
    {
       throw std::runtime_error("hash() function not implemented");
       return msg;
    }

    [[nodiscard]] virtual bool verify(const std::string& msg, const std::string& signature) const =0;

    [[nodiscard]] virtual std::string getPublicKeyString()const =0;
    [[nodiscard]] virtual int getBits() const =0;
    [[nodiscard]] virtual unsigned int getAlgorithm() const
    {
      return d_algorithm;
    }

    virtual void fromISCMap(DNSKEYRecordContent& drc, stormap_t& stormap) = 0;
    virtual void fromPublicKeyString(const std::string& content) = 0;

    [[nodiscard]] virtual bool checkKey(std::optional<std::reference_wrapper<std::vector<std::string>>> /* errorMessages */ = std::nullopt) const
    {
      return true;
    }

    static std::unique_ptr<DNSCryptoKeyEngine> makeFromISCFile(DNSKEYRecordContent& drc, const char* fname);

    /**
     * \brief Creates a key engine from a PEM file.
     *
     * Receives an open file handle with PEM contents and creates a key engine
     * corresponding to the algorithm requested.
     *
     * \param[in] drc Key record contents to be populated.
     *
     * \param[in] algorithm Which algorithm to use. See
     * https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
     *
     * \param[in] fp An open file handle to a file containing PEM contents.
     *
     * \param[in] filename Only used for providing filename information in error messages.
     *
     * \return A key engine corresponding to the requested algorithm and populated with
     * the contents of the PEM file.
     */
    static std::unique_ptr<DNSCryptoKeyEngine> makeFromPEMFile(DNSKEYRecordContent& drc, uint8_t algorithm, std::FILE& inputFile, const std::string& filename);

    /**
     * \brief Creates a key engine from a PEM string.
     *
     * Receives PEM contents and creates a key engine corresponding to the algorithm
     * requested.
     *
     * \param[in] drc Key record contents to be populated.
     *
     * \param[in] algorithm Which algorithm to use. See
     * https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
     *
     * \param[in] contents The PEM contents.
     *
     * \return A key engine corresponding to the requested algorithm and populated with
     * the contents of the PEM string.
     */
    static std::unique_ptr<DNSCryptoKeyEngine> makeFromPEMString(DNSKEYRecordContent& drc, uint8_t algorithm, const std::string& contents);

    static std::unique_ptr<DNSCryptoKeyEngine> makeFromISCString(DNSKEYRecordContent& drc, const std::string& content);
    static std::unique_ptr<DNSCryptoKeyEngine> makeFromPublicKeyString(unsigned int algorithm, const std::string& raw);
    static std::unique_ptr<DNSCryptoKeyEngine> make(unsigned int algorithm);
    static bool isAlgorithmSupported(unsigned int algo);
    static bool isAlgorithmSwitchedOff(unsigned int algo);
    static void switchOffAlgorithm(unsigned int algo);
    static bool isDigestSupported(uint8_t digest);

    using maker_t = std::unique_ptr<DNSCryptoKeyEngine> (unsigned int);

    static void report(unsigned int algorithm, maker_t* maker, bool fallback=false);
    static void testMakers(unsigned int algorithm, maker_t* creator, maker_t* signer, maker_t* verifier);
    static vector<pair<uint8_t, string>> listAllAlgosWithBackend();
    static bool testAll();
    static bool testOne(int algo);
    static bool verifyOne(unsigned int algo);
    static bool testVerify(unsigned int algo, maker_t* verifier);
    static string listSupportedAlgoNames();

  private:
    using makers_t = std::map<unsigned int, maker_t *>;
    using allmakers_t = std::map<unsigned int, vector<maker_t *>>;
    static makers_t& getMakers()
    {
      static makers_t s_makers;
      return s_makers;
    }
    static allmakers_t& getAllMakers()
    {
      static allmakers_t s_allmakers;
      return s_allmakers;
    }
    // Must be set before going multi-threaded and not changed after that
    static std::unordered_set<unsigned int> s_switchedOff;

  protected:
    const unsigned int d_algorithm;
};

struct DNSSECPrivateKey
{
  uint16_t getTag() const
  {
    return getDNSKEY().getTag();
  }

  const std::shared_ptr<DNSCryptoKeyEngine>& getKey() const
  {
    return d_key;
  }

  // be aware that calling setKey() will also set the algorithm
  void setKey(std::shared_ptr<DNSCryptoKeyEngine>& key, uint16_t flags, std::optional<uint8_t> algorithm = std::nullopt)
  {
    d_key = key;
    d_flags = flags;
    d_algorithm = algorithm ? *algorithm : d_key->getAlgorithm();
    computeDNSKEY();
  }

  // be aware that calling setKey() will also set the algorithm
  void setKey(std::unique_ptr<DNSCryptoKeyEngine>&& key, uint16_t flags, std::optional<uint8_t> algorithm = std::nullopt)
  {
    d_key = std::move(key);
    d_flags = flags;
    d_algorithm = algorithm ? *algorithm : d_key->getAlgorithm();
    computeDNSKEY();
  }

  const DNSKEYRecordContent& getDNSKEY() const;

  uint16_t getFlags() const
  {
    return d_flags;
  }

  uint8_t getAlgorithm() const
  {
    return d_algorithm;
  }

private:
  void computeDNSKEY();

  DNSKEYRecordContent d_dnskey;
  std::shared_ptr<DNSCryptoKeyEngine> d_key;
  uint16_t d_flags{0};
  uint8_t d_algorithm{0};
};



struct CanonicalCompare
{
  bool operator()(const std::string& a, const std::string& b) {
    std::vector<std::string> avect, bvect;

    stringtok(avect, a, ".");
    stringtok(bvect, b, ".");

    reverse(avect.begin(), avect.end());
    reverse(bvect.begin(), bvect.end());

    return avect < bvect;
  }
};

struct sharedDNSSECRecordCompare {
    bool operator() (const shared_ptr<const DNSRecordContent>& a, const shared_ptr<const DNSRecordContent>& b) const {
      return a->serialize(g_rootdnsname, true, true) < b->serialize(g_rootdnsname, true, true);
    }
};

typedef std::set<std::shared_ptr<const DNSRecordContent>, sharedDNSSECRecordCompare> sortedRecords_t;

string getMessageForRRSET(const DNSName& qname, const RRSIGRecordContent& rrc, const sortedRecords_t& signRecords, bool processRRSIGLabels = false, bool includeRRSIG_RDATA = true);

DSRecordContent makeDSFromDNSKey(const DNSName& qname, const DNSKEYRecordContent& drc, uint8_t digest);

class DNSSECKeeper;

uint32_t getStartOfWeek();

string hashQNameWithSalt(const NSEC3PARAMRecordContent& ns3prc, const DNSName& qname);
string hashQNameWithSalt(const std::string& salt, unsigned int iterations, const DNSName& qname);

void incrementHash(std::string& raw);
void decrementHash(std::string& raw);

void addRRSigs(DNSSECKeeper& dk, UeberBackend& db, const std::set<ZoneName>& authSet, vector<DNSZoneRecord>& rrs, DNSPacket* packet=nullptr);

void addTSIG(DNSPacketWriter& pw, TSIGRecordContent& trc, const DNSName& tsigkeyname, const string& tsigsecret, const string& tsigprevious, bool timersonly);
bool validateTSIG(const std::string& packet, size_t sigPos, const TSIGTriplet& tt, const TSIGRecordContent& trc, const std::string& previousMAC, const std::string& theirMAC, bool timersOnly, unsigned int dnsHeaderOffset=0);

uint64_t signatureCacheSize(const std::string& str);
