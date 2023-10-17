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
#include <array>
#include <string>
#include <cstdint>
#include <cstring>

#if defined(HAVE_LIBSODIUM)
#include <sodium.h>
#endif

struct SodiumNonce
{
  SodiumNonce() = default;
  SodiumNonce(const SodiumNonce&) = default;
  SodiumNonce(SodiumNonce&&) = default;
  SodiumNonce& operator=(const SodiumNonce&) = default;
  SodiumNonce& operator=(SodiumNonce&&) = default;
  ~SodiumNonce() = default;

  void init();
  void merge(const SodiumNonce& lower, const SodiumNonce& higher);
  void increment();

#if !defined(HAVE_LIBSODIUM)
  std::array<unsigned char, 1> value{};
#else
  std::array<unsigned char, crypto_secretbox_NONCEBYTES> value{};
#endif
};

std::string sodEncryptSym(const std::string_view& msg, const std::string& key, SodiumNonce& nonce, bool incrementNonce = true);
std::string sodDecryptSym(const std::string_view& msg, const std::string& key, SodiumNonce& nonce, bool incrementNonce = true);
std::string newKey(bool base64Encoded = true);
bool sodIsValidKey(const std::string& key);

namespace dnsdist::crypto::authenticated
{
constexpr size_t getEncryptedSize(size_t plainTextSize)
{
#if defined(HAVE_LIBSODIUM)
  return plainTextSize + crypto_secretbox_MACBYTES;
#else
  return plainTextSize;
#endif
}
}
