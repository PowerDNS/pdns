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

#include <string>
#include <openssl/sha.h>
#include <openssl/evp.h>

inline std::string pdns_sha1sum(const std::string& input)
{
  unsigned char result[20] = {0};
  SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

inline std::string pdns_sha256sum(const std::string& input)
{
  unsigned char result[32] = {0};
  SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

inline std::string pdns_sha384sum(const std::string& input)
{
  unsigned char result[48] = {0};
  SHA384(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

inline std::string pdns_sha512sum(const std::string& input)
{
  unsigned char result[64] = {0};
  SHA512(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

namespace pdns
{
  class SHADigest
  {
  public:
    SHADigest(int bits)
    {
      mdctx = EVP_MD_CTX_new();
      if (mdctx == nullptr) {
        throw std::runtime_error("VSHADigest: P_MD_CTX_new failed");
      }
      switch (bits) {
      case 256:
        md = EVP_sha256();
        break;
      case 384:
        md = EVP_sha384();
        break;
      case 512:
        md = EVP_sha512();
        break;
      default:
        throw std::runtime_error("SHADigest: unsupported size");
      }
      if (EVP_DigestInit_ex(mdctx, md, NULL) == 0) {
        throw std::runtime_error("SHADigest: init error");
      }
    }

    ~SHADigest()
    {
      // No free of md needed afaik
      if (mdctx != nullptr) {
        EVP_MD_CTX_free(mdctx);
      }
    }

    void process(const std::string& msg, size_t sz)
    {
      if (EVP_DigestUpdate(mdctx, msg.data(), msg.size()) == 0) {
        throw std::runtime_error("SHADigest: update error");
      }
    }

    std::string digest()
    {
      std::string md_value;
      md_value.resize(EVP_MD_size(md));
      unsigned int md_len;
      if (EVP_DigestFinal_ex(mdctx, reinterpret_cast<unsigned char*>(md_value.data()), &md_len) == 0) {
        throw std::runtime_error("SHADigest: finalize error");
      }
      if (md_len != md_value.size()) {
        throw std::runtime_error("SHADigest: inconsisten size");
      }
      return md_value;
    }
  private:
    EVP_MD_CTX *mdctx{nullptr};
    const EVP_MD *md;
  };
}
