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

#include "config.h"
#include <memory>
#include <stdexcept>
#include <string>

#include <openssl/evp.h>

namespace pdns
{
inline std::string hash(const EVP_MD* messageDigest, const std::string& input)
{
#if defined(HAVE_EVP_MD_CTX_NEW) && defined(HAVE_EVP_MD_CTX_FREE)
  auto mdctx = std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#else
  auto mdctx = std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)>(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#endif
  if (!mdctx) {
    throw std::runtime_error(std::string(EVP_MD_name(messageDigest)) + " context initialization failed");
  }

  if (EVP_DigestInit_ex(mdctx.get(), messageDigest, nullptr) != 1) {
    throw std::runtime_error(std::string(EVP_MD_name(messageDigest)) + " EVP initialization failed");
  }

  if (EVP_DigestUpdate(mdctx.get(), input.data(), input.size()) != 1) {
    throw std::runtime_error(std::string(EVP_MD_name(messageDigest)) + " EVP update failed");
  }

  unsigned int written = 0;
  std::string result;
  result.resize(EVP_MD_size(messageDigest));

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  if (EVP_DigestFinal_ex(mdctx.get(), const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(result.c_str())), &written) != 1) {
    throw std::runtime_error(std::string(EVP_MD_name(messageDigest)) + " EVP final failed");
  }

  if (written != result.size()) {
    throw std::runtime_error(std::string(EVP_MD_name(messageDigest)) + " EVP final wrote " + std::to_string(written) + ", expected " + std::to_string(result.size()));
  }

  return result;
}

inline std::string md5(const std::string& input)
{
  const auto* const messageDigest = EVP_md5();
  if (messageDigest == nullptr) {
    throw std::runtime_error("The MD5 digest is not available via the OpenSSL EVP interface");
  }

  return pdns::hash(messageDigest, input);
}

inline std::string sha1(const std::string& input)
{
  const auto* const messageDigest = EVP_sha1();
  if (messageDigest == nullptr) {
    throw std::runtime_error("The SHA1 digest is not available via the OpenSSL EVP interface");
  }

  return pdns::hash(messageDigest, input);
}
}
