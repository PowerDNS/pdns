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

#include <cstdint>
#include <string>

class SensitiveData
{
public:
  SensitiveData(size_t bytes);
  SensitiveData(std::string&& data);
  SensitiveData& operator=(SensitiveData&&) noexcept;

  ~SensitiveData();
  void clear();
  const std::string& getString() const
  {
    return d_data;
  }
  std::string& getString()
  {
    return d_data;
  }

private:
  std::string d_data;
};

std::string hashPassword(const std::string& password);
std::string hashPassword(const std::string& password, uint64_t workFactor, uint64_t parallelFactor, uint64_t blockSize);
bool verifyPassword(const std::string& hash, const std::string& password);
bool verifyPassword(const std::string& binaryHash, const std::string& salt, uint64_t workFactor, uint64_t parallelFactor, uint64_t blockSize, const std::string& binaryPassword);
bool isPasswordHashed(const std::string& password);

class CredentialsHolder
{
public:
  /* if hashPlaintext is true, the password is in cleartext and hashing is available,
     the hashed form will be kept in memory.
     Note that accepting hashed password from an untrusted source might open
     us to a denial of service, since we currently don't cap the the parameters,
     including the work factor */
  CredentialsHolder(std::string&& password, bool hashPlaintext);
  ~CredentialsHolder();

  CredentialsHolder(const CredentialsHolder&) = delete;
  CredentialsHolder& operator=(const CredentialsHolder&) = delete;

  bool matches(const std::string& password) const;
  /* whether it was constructed from a hashed and salted string */
  bool wasHashed() const
  {
    return d_wasHashed;
  }
  /* whether it is hashed in memory */
  bool isHashed() const
  {
    return d_isHashed;
  }

  static bool isHashingAvailable();
  static SensitiveData readFromTerminal();

  static uint64_t const s_defaultWorkFactor;
  static uint64_t const s_defaultParallelFactor;
  static uint64_t const s_defaultBlockSize;

private:
  SensitiveData d_credentials;
  /* if the password is hashed, we only extract
     the salt and parameters once */
  std::string d_salt;
  uint64_t d_workFactor{0};
  uint64_t d_parallelFactor{0};
  uint64_t d_blockSize{0};
  /* seed our hash so it's not predictable */
  uint32_t d_fallbackHashPerturb{0};
  uint32_t d_fallbackHash{0};
  /* whether it was constructed from a hashed and salted string */
  bool d_wasHashed{false};
  /* whether it is hashed in memory */
  bool d_isHashed{false};
};
