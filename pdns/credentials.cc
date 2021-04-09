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

#include <stdexcept>

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif

#include "credentials.hh"
#include "misc.hh"

std::string hashPassword(const std::string& password)
{
#ifdef HAVE_CRYPTO_PWHASH_STR
  std::string result;
  result.resize(crypto_pwhash_STRBYTES);
  sodium_mlock(result.data(), result.size());

  int res = crypto_pwhash_str(const_cast<char*>(result.c_str()),
                              password.c_str(),
                              password.size(),
                              crypto_pwhash_OPSLIMIT_INTERACTIVE,
                              crypto_pwhash_MEMLIMIT_INTERACTIVE);
  if (res != 0) {
    throw std::runtime_error("Error while hashing the supplied password");
  }

  return result;
#else
  throw std::runtime_error("Hashing a password requires libsodium support, and it is not available");
#endif
}

bool verifyPassword(const std::string& hash, const std::string& password)
{
#ifdef HAVE_CRYPTO_PWHASH_STR
  if (hash.size() > crypto_pwhash_STRBYTES) {
    throw std::runtime_error("Invalid password hash supplied for verification, size is " + std::to_string(hash.size()) + ", expected at most " + std::to_string(crypto_pwhash_STRBYTES));
  }

  return crypto_pwhash_str_verify(hash.c_str(),
                                  password.c_str(),
                                  password.size())
    == 0;
#else
  throw std::runtime_error("Verifying a hashed password requires libsodium support, and it is not available");
#endif
}

bool isPasswordHashed(const std::string& password)
{
#ifdef HAVE_CRYPTO_PWHASH_STR
  if (password.size() > crypto_pwhash_STRBYTES) {
    return false;
  }

  int res = crypto_pwhash_str_needs_rehash(password.c_str(),
                                           crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                           crypto_pwhash_MEMLIMIT_INTERACTIVE);

  if (res == -1) {
    return false;
  }
  /* 1 means a rehashing is needed (different parameters), 0 is fine.
     Either way this is a valid hash */
  return true;
#else
  return false;
#endif
}

/* if the password is in cleartext and hashing is available,
   the hashed form will be kept in memory */
CredentialsHolder::CredentialsHolder(std::string&& password, bool hashPlaintext)
{
  bool locked = false;

  if (isHashingAvailable()) {
    if (!isPasswordHashed(password)) {
      if (hashPlaintext) {
        d_credentials = hashPassword(password);
        locked = true;
        d_isHashed = true;
      }
    }
    else {
      d_wasHashed = true;
      d_isHashed = true;
      d_credentials = std::move(password);
    }
  }

  if (!d_isHashed) {
    d_fallbackHashPerturb = random();
    d_fallbackHash = burtle(reinterpret_cast<const unsigned char*>(password.data()), password.size(), d_fallbackHashPerturb);
    d_credentials = std::move(password);
  }

  if (!locked) {
#ifdef HAVE_LIBSODIUM
    sodium_mlock(d_credentials.data(), d_credentials.size());
#endif
  }
}

CredentialsHolder::~CredentialsHolder()
{
#ifdef HAVE_LIBSODIUM
  sodium_munlock(d_credentials.data(), d_credentials.size());
#endif
  d_fallbackHashPerturb = 0;
  d_fallbackHash = 0;
}

bool CredentialsHolder::matches(const std::string& password) const
{
  if (d_isHashed) {
    return verifyPassword(d_credentials, password);
  }
  else {
    uint32_t fallback = burtle(reinterpret_cast<const unsigned char*>(password.data()), password.size(), d_fallbackHashPerturb);
    if (fallback != d_fallbackHash) {
      return false;
    }

    return constantTimeStringEquals(password, d_credentials);
  }
}

bool CredentialsHolder::isHashingAvailable()
{
#ifdef HAVE_CRYPTO_PWHASH_STR
  return true;
#else
  return false;
#endif
}
