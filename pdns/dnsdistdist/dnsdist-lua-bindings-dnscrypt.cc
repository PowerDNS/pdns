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

#include "config.h"
#include "dnsdist.hh"
#include "dnsdist-lua.hh"

#include "dolog.hh"

void setupLuaBindingsDNSCrypt(LuaContext& luaCtx)
{
#ifdef HAVE_DNSCRYPT
    /* DNSCryptContext bindings */
    luaCtx.registerFunction<std::string(DNSCryptContext::*)()const>("getProviderName", [](const DNSCryptContext& ctx) { return ctx.getProviderName().toStringNoDot(); });
    luaCtx.registerFunction("markActive", &DNSCryptContext::markActive);
    luaCtx.registerFunction("markInactive", &DNSCryptContext::markInactive);
    luaCtx.registerFunction("reloadCertificates", &DNSCryptContext::reloadCertificates);
    luaCtx.registerFunction("removeInactiveCertificate", &DNSCryptContext::removeInactiveCertificate);
    luaCtx.registerFunction<void(std::shared_ptr<DNSCryptContext>::*)(const std::string& certFile, const std::string& keyFile, std::optional<bool> active)>("loadNewCertificate", [](std::shared_ptr<DNSCryptContext> ctx, const std::string& certFile, const std::string& keyFile, std::optional<bool> active) {

      if (ctx == nullptr) {
        throw std::runtime_error("DNSCryptContext::loadNewCertificate() called on a nil value");
      }

      ctx->loadNewCertificate(certFile, keyFile, active ? *active : true);
    });
    luaCtx.registerFunction<void(std::shared_ptr<DNSCryptContext>::*)(const DNSCryptCert& newCert, const DNSCryptPrivateKey& newKey, std::optional<bool> active)>("addNewCertificate", [](std::shared_ptr<DNSCryptContext> ctx, const DNSCryptCert& newCert, const DNSCryptPrivateKey& newKey, std::optional<bool> active) {

      if (ctx == nullptr) {
        throw std::runtime_error("DNSCryptContext::addNewCertificate() called on a nil value");
      }

      ctx->addNewCertificate(newCert, newKey, active ? *active : true);
    });
    luaCtx.registerFunction<std::map<int, std::shared_ptr<DNSCryptCertificatePair>>(std::shared_ptr<DNSCryptContext>::*)()>("getCertificatePairs", [](std::shared_ptr<DNSCryptContext> ctx) {
      std::map<int, std::shared_ptr<DNSCryptCertificatePair>> result;

      if (ctx != nullptr) {
        size_t idx = 1;
        for (auto pair : ctx->getCertificates()) {
          result[idx++] = pair;
        }
      }

      return result;
    });

    luaCtx.registerFunction<std::shared_ptr<DNSCryptCertificatePair>(std::shared_ptr<DNSCryptContext>::*)(size_t idx)>("getCertificatePair", [](std::shared_ptr<DNSCryptContext> ctx, size_t idx) {

      if (ctx == nullptr) {
        throw std::runtime_error("DNSCryptContext::getCertificatePair() called on a nil value");
      }

      std::shared_ptr<DNSCryptCertificatePair> result = nullptr;
      auto pairs = ctx->getCertificates();
      if (idx < pairs.size()) {
        result = pairs.at(idx);
      }

      return result;
    });

    luaCtx.registerFunction<const DNSCryptCert(std::shared_ptr<DNSCryptContext>::*)(size_t idx)>("getCertificate", [](std::shared_ptr<DNSCryptContext> ctx, size_t idx) {

      if (ctx == nullptr) {
        throw std::runtime_error("DNSCryptContext::getCertificate() called on a nil value");
      }

      auto pairs = ctx->getCertificates();
      if (idx < pairs.size()) {
        return pairs.at(idx)->cert;
      }

      throw std::runtime_error("This DNSCrypt context has no certificate at index " + std::to_string(idx));
    });

    luaCtx.registerFunction<std::string(std::shared_ptr<DNSCryptContext>::*)()const>("printCertificates", [](const std::shared_ptr<DNSCryptContext> ctx) {
      ostringstream ret;

      if (ctx != nullptr) {
        size_t idx = 1;
        boost::format fmt("%1$-3d %|5t|%2$-8d %|10t|%3$-7d %|20t|%4$-21.21s %|41t|%5$-21.21s");
        ret << (fmt % "#" % "Serial" % "Version" % "From" % "To" ) << endl;

        for (auto pair : ctx->getCertificates()) {
          const auto cert = pair->cert;
          const DNSCryptExchangeVersion version = DNSCryptContext::getExchangeVersion(cert);

          ret << (fmt % idx % cert.getSerial() % (version == DNSCryptExchangeVersion::VERSION1 ? 1 : 2) % DNSCryptContext::certificateDateToStr(cert.getTSStart()) % DNSCryptContext::certificateDateToStr(cert.getTSEnd())) << endl;
        }
      }

      return ret.str();
    });

    luaCtx.registerFunction<void(DNSCryptContext::*)(const std::string& providerPrivateKeyFile, uint32_t serial, time_t begin, time_t end, std::optional<DNSCryptExchangeVersion> version)>("generateAndLoadInMemoryCertificate", [](DNSCryptContext& ctx, const std::string& providerPrivateKeyFile, uint32_t serial, time_t begin, time_t end, std::optional<DNSCryptExchangeVersion> version) {
        DNSCryptPrivateKey privateKey;
        DNSCryptCert cert;

        try {
          if (generateDNSCryptCertificate(providerPrivateKeyFile, serial, begin, end, version ? *version : DNSCryptExchangeVersion::VERSION1, cert, privateKey)) {
            ctx.addNewCertificate(cert, privateKey);
          }
        }
        catch(const std::exception& e) {
          errlog(e.what());
          g_outputBuffer="Error: "+string(e.what())+"\n";
        }
    });

    /* DNSCryptCertificatePair */
    luaCtx.registerFunction<const DNSCryptCert(std::shared_ptr<DNSCryptCertificatePair>::*)()const>("getCertificate", [](const std::shared_ptr<DNSCryptCertificatePair> pair) {
      if (pair == nullptr) {
        throw std::runtime_error("DNSCryptCertificatePair::getCertificate() called on a nil value");
      }
      return pair->cert;
    });
    luaCtx.registerFunction<bool(std::shared_ptr<DNSCryptCertificatePair>::*)()const>("isActive", [](const std::shared_ptr<DNSCryptCertificatePair> pair) {
      if (pair == nullptr) {
        throw std::runtime_error("DNSCryptCertificatePair::isActive() called on a nil value");
      }
      return pair->active;
    });

    /* DNSCryptCert */
    luaCtx.registerFunction<std::string(DNSCryptCert::*)()const>("getMagic", [](const DNSCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.magic), sizeof(cert.magic)); });
    luaCtx.registerFunction<std::string(DNSCryptCert::*)()const>("getEsVersion", [](const DNSCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.esVersion), sizeof(cert.esVersion)); });
    luaCtx.registerFunction<std::string(DNSCryptCert::*)()const>("getProtocolMinorVersion", [](const DNSCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.protocolMinorVersion), sizeof(cert.protocolMinorVersion)); });
    luaCtx.registerFunction<std::string(DNSCryptCert::*)()const>("getSignature", [](const DNSCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.signature), sizeof(cert.signature)); });
    luaCtx.registerFunction<std::string(DNSCryptCert::*)()const>("getResolverPublicKey", [](const DNSCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.signedData.resolverPK), sizeof(cert.signedData.resolverPK)); });
    luaCtx.registerFunction<std::string(DNSCryptCert::*)()const>("getClientMagic", [](const DNSCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.signedData.clientMagic), sizeof(cert.signedData.clientMagic)); });
    luaCtx.registerFunction<uint32_t(DNSCryptCert::*)()const>("getSerial", [](const DNSCryptCert& cert) { return cert.getSerial(); });
    luaCtx.registerFunction<uint32_t(DNSCryptCert::*)()const>("getTSStart", [](const DNSCryptCert& cert) { return ntohl(cert.getTSStart()); });
    luaCtx.registerFunction<uint32_t(DNSCryptCert::*)()const>("getTSEnd", [](const DNSCryptCert& cert) { return ntohl(cert.getTSEnd()); });
#endif
}
