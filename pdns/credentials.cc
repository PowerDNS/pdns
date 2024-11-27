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

#include <cmath>
#include <stdexcept>

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif

#if !defined(DISABLE_HASHED_CREDENTIALS) && defined(HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT)
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#endif

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base64.hh"
#include "dns_random.hh"
#include "credentials.hh"
#include "misc.hh"

#if !defined(DISABLE_HASHED_CREDENTIALS) && defined(HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT)
static size_t const pwhash_max_size = 128U; /* maximum size of the output */
static size_t const pwhash_output_size = 32U; /* size of the hashed output (before base64 encoding) */
static unsigned int const pwhash_salt_size = 16U; /* size of the salt (before base64 encoding */
static uint64_t const pwhash_max_work_factor = 32768U; /* max N for interactive login purposes */

/* PHC string format, storing N as log2(N) as done by passlib.
   for now we only support one algo but we might have to change that later */
static std::string const pwhash_prefix = "$scrypt$";
static size_t const pwhash_prefix_size = pwhash_prefix.size();
#endif

SensitiveData::SensitiveData(std::string&& data) :
  d_data(std::move(data))
{
  data.clear();
#ifdef HAVE_LIBSODIUM
  sodium_mlock(d_data.data(), d_data.size());
#endif
}

SensitiveData& SensitiveData::operator=(SensitiveData&& rhs) noexcept
{
  d_data = std::move(rhs.d_data);
  rhs.clear();
  return *this;
}

SensitiveData::SensitiveData(size_t bytes)
{
  d_data.resize(bytes);
#ifdef HAVE_LIBSODIUM
  sodium_mlock(d_data.data(), d_data.size());
#endif
}

SensitiveData::~SensitiveData()
{
  clear();
}

void SensitiveData::clear()
{
#ifdef HAVE_LIBSODIUM
  sodium_munlock(d_data.data(), d_data.size());
#endif
  d_data.clear();
}

static std::string hashPasswordInternal([[maybe_unused]] const std::string& password, [[maybe_unused]] const std::string& salt, [[maybe_unused]] uint64_t workFactor, [[maybe_unused]] uint64_t parallelFactor, [[maybe_unused]] uint64_t blockSize)
{
#if !defined(DISABLE_HASHED_CREDENTIALS) && defined(HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT)
  auto pctx = std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX*)>(EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, nullptr), EVP_PKEY_CTX_free);
  if (!pctx) {
    throw std::runtime_error("Error getting a scrypt context to hash the supplied password");
  }

  if (EVP_PKEY_derive_init(pctx.get()) <= 0) {
    throw std::runtime_error("Error intializing the scrypt context to hash the supplied password");
  }

  // OpenSSL 3.0 changed the string arg to const unsigned char*, other versions use const char *
  // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
#if OPENSSL_VERSION_MAJOR >= 3
  const auto* passwordData = reinterpret_cast<const char*>(password.data());
#else
  const auto* passwordData = reinterpret_cast<const unsigned char*>(password.data());
#endif
  if (EVP_PKEY_CTX_set1_pbe_pass(pctx.get(), passwordData, password.size()) <= 0) {
    throw std::runtime_error("Error adding the password to the scrypt context to hash the supplied password");
  }

  if (EVP_PKEY_CTX_set1_scrypt_salt(pctx.get(), reinterpret_cast<const unsigned char*>(salt.data()), salt.size()) <= 0) {
    throw std::runtime_error("Error adding the salt to the scrypt context to hash the supplied password");
  }
  // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)

  if (EVP_PKEY_CTX_set_scrypt_N(pctx.get(), workFactor) <= 0) {
    throw std::runtime_error("Error setting the work factor to the scrypt context to hash the supplied password");
  }

  if (EVP_PKEY_CTX_set_scrypt_r(pctx.get(), blockSize) <= 0) {
    throw std::runtime_error("Error setting the block size to the scrypt context to hash the supplied password");
  }

  if (EVP_PKEY_CTX_set_scrypt_p(pctx.get(), parallelFactor) <= 0) {
    throw std::runtime_error("Error setting the parallel factor to the scrypt context to hash the supplied password");
  }

  std::string out;
  out.resize(pwhash_output_size);
  size_t outlen = out.size();

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (EVP_PKEY_derive(pctx.get(), reinterpret_cast<unsigned char*>(out.data()), &outlen) <= 0 || outlen != pwhash_output_size) {
    throw std::runtime_error("Error deriving the output from the scrypt context to hash the supplied password");
  }

  return out;
#else
  throw std::runtime_error("Hashing support is not available");
#endif
}

static std::string generateRandomSalt()
{
#if !defined(DISABLE_HASHED_CREDENTIALS) && defined(HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT)
  /* generate a random salt */
  std::string salt;
  salt.resize(pwhash_salt_size);

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), static_cast<int>(salt.size())) != 1) {
    throw std::runtime_error("Error while generating a salt to hash the supplied password");
  }

  return salt;
#else
  throw std::runtime_error("Generating a salted password requires scrypt support in OpenSSL, and it is not available");
#endif
}

std::string hashPassword([[maybe_unused]] const std::string& password, [[maybe_unused]] uint64_t workFactor, [[maybe_unused]] uint64_t parallelFactor, [[maybe_unused]] uint64_t blockSize)
{
#if !defined(DISABLE_HASHED_CREDENTIALS) && defined(HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT)
  if (workFactor == 0) {
    throw std::runtime_error("Invalid work factor of " + std::to_string(workFactor) + " passed to hashPassword()");
  }

  std::string result;
  result.reserve(pwhash_max_size);

  result.append(pwhash_prefix);
  result.append("ln=");
  result.append(std::to_string(static_cast<uint64_t>(std::log2(workFactor))));
  result.append(",p=");
  result.append(std::to_string(parallelFactor));
  result.append(",r=");
  result.append(std::to_string(blockSize));
  result.append("$");
  auto salt = generateRandomSalt();
  result.append(Base64Encode(salt));
  result.append("$");

  auto out = hashPasswordInternal(password, salt, workFactor, parallelFactor, blockSize);

  result.append(Base64Encode(out));

  return result;
#else
  throw std::runtime_error("Hashing a password requires scrypt support in OpenSSL, and it is not available");
#endif
}

std::string hashPassword([[maybe_unused]] const std::string& password)
{
#if !defined(DISABLE_HASHED_CREDENTIALS) && defined(HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT)
  return hashPassword(password, CredentialsHolder::s_defaultWorkFactor, CredentialsHolder::s_defaultParallelFactor, CredentialsHolder::s_defaultBlockSize);
#else
  throw std::runtime_error("Hashing a password requires scrypt support in OpenSSL, and it is not available");
#endif
}

bool verifyPassword([[maybe_unused]] const std::string& binaryHash, [[maybe_unused]] const std::string& salt, [[maybe_unused]] uint64_t workFactor, [[maybe_unused]] uint64_t parallelFactor, [[maybe_unused]] uint64_t blockSize, [[maybe_unused]] const std::string& binaryPassword)
{
#if !defined(DISABLE_HASHED_CREDENTIALS) && defined(HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT)
  auto expected = hashPasswordInternal(binaryPassword, salt, workFactor, parallelFactor, blockSize);
  return constantTimeStringEquals(expected, binaryHash);
#else
  throw std::runtime_error("Hashing a password requires scrypt support in OpenSSL, and it is not available");
#endif
}

/* parse a hashed password in PHC string format */
static void parseHashed([[maybe_unused]] const std::string& hash, [[maybe_unused]] std::string& salt, [[maybe_unused]] std::string& hashedPassword, [[maybe_unused]] uint64_t& workFactor, [[maybe_unused]] uint64_t& parallelFactor, [[maybe_unused]] uint64_t& blockSize)
{
#if !defined(DISABLE_HASHED_CREDENTIALS) && defined(HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT)
  auto parametersEnd = hash.find('$', pwhash_prefix.size());
  if (parametersEnd == std::string::npos || parametersEnd == hash.size()) {
    throw std::runtime_error("Invalid hashed password format, no parameters");
  }

  auto parametersStr = hash.substr(pwhash_prefix.size(), parametersEnd);
  std::vector<std::string> parameters;
  parameters.reserve(3);
  stringtok(parameters, parametersStr, ",");
  if (parameters.size() != 3) {
    throw std::runtime_error("Invalid hashed password format, expecting 3 parameters, got " + std::to_string(parameters.size()));
  }

  if (!boost::starts_with(parameters.at(0), "ln=")) {
    throw std::runtime_error("Invalid hashed password format, ln= parameter not found");
  }

  if (!boost::starts_with(parameters.at(1), "p=")) {
    throw std::runtime_error("Invalid hashed password format, p= parameter not found");
  }

  if (!boost::starts_with(parameters.at(2), "r=")) {
    throw std::runtime_error("Invalid hashed password format, r= parameter not found");
  }

  auto saltPos = parametersEnd + 1;
  auto saltEnd = hash.find('$', saltPos);
  if (saltEnd == std::string::npos || saltEnd == hash.size()) {
    throw std::runtime_error("Invalid hashed password format");
  }

  try {
    workFactor = pdns::checked_stoi<uint64_t>(parameters.at(0).substr(3));
    workFactor = static_cast<uint64_t>(1) << workFactor;
    if (workFactor > pwhash_max_work_factor) {
      throw std::runtime_error("Invalid work factor of " + std::to_string(workFactor) + " in hashed password string, maximum is " + std::to_string(pwhash_max_work_factor));
    }

    parallelFactor = pdns::checked_stoi<uint64_t>(parameters.at(1).substr(2));
    blockSize = pdns::checked_stoi<uint64_t>(parameters.at(2).substr(2));

    auto b64Salt = hash.substr(saltPos, saltEnd - saltPos);
    salt.reserve(pwhash_salt_size);
    B64Decode(b64Salt, salt);

    if (salt.size() != pwhash_salt_size) {
      throw std::runtime_error("Invalid salt in hashed password string");
    }

    hashedPassword.reserve(pwhash_output_size);
    B64Decode(hash.substr(saltEnd + 1), hashedPassword);

    if (hashedPassword.size() != pwhash_output_size) {
      throw std::runtime_error("Invalid hash in hashed password string");
    }
  }
  catch (const std::exception& e) {
    throw std::runtime_error("Invalid hashed password format, unable to parse parameters");
  }
#endif
}

bool verifyPassword(const std::string& hash, [[maybe_unused]] const std::string& password)
{
  if (!isPasswordHashed(hash)) {
    return false;
  }

#if !defined(DISABLE_HASHED_CREDENTIALS) && defined(HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT)
  std::string salt;
  std::string hashedPassword;
  uint64_t workFactor = 0;
  uint64_t parallelFactor = 0;
  uint64_t blockSize = 0;
  parseHashed(hash, salt, hashedPassword, workFactor, parallelFactor, blockSize);

  auto expected = hashPasswordInternal(password, salt, workFactor, parallelFactor, blockSize);

  return constantTimeStringEquals(expected, hashedPassword);
#else
  throw std::runtime_error("Verifying a hashed password requires scrypt support in OpenSSL, and it is not available");
#endif
}

bool isPasswordHashed([[maybe_unused]] const std::string& password)
{
#if !defined(DISABLE_HASHED_CREDENTIALS) && defined(HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT)
  if (password.size() < pwhash_prefix_size || password.size() > pwhash_max_size) {
    return false;
  }

  if (!boost::starts_with(password, pwhash_prefix)) {
    return false;
  }

  auto parametersEnd = password.find('$', pwhash_prefix.size());
  if (parametersEnd == std::string::npos || parametersEnd == password.size()) {
    return false;
  }

  size_t parametersSize = parametersEnd - pwhash_prefix.size();
  /* ln=X,p=Y,r=Z */
  if (parametersSize < 12) {
    return false;
  }

  auto saltEnd = password.find('$', parametersEnd + 1);
  if (saltEnd == std::string::npos || saltEnd == password.size()) {
    return false;
  }

  /* the salt is base64 encoded so it has to be larger than that */
  if ((saltEnd - parametersEnd - 1) < pwhash_salt_size) {
    return false;
  }

  /* the hash base64 encoded so it has to be larger than that */
  if ((password.size() - saltEnd - 1) < pwhash_output_size) {
    return false;
  }

  return true;
#else
  return false;
#endif
}

/* if the password is in cleartext and hashing is available,
   the hashed form will be kept in memory */
CredentialsHolder::CredentialsHolder(std::string&& password, bool hashPlaintext) :
  d_credentials(std::move(password))
{
  if (isHashingAvailable()) {
    if (!isPasswordHashed(d_credentials.getString())) {
      if (hashPlaintext) {
        d_salt = generateRandomSalt();
        d_workFactor = s_defaultWorkFactor;
        d_parallelFactor = s_defaultParallelFactor;
        d_blockSize = s_defaultBlockSize;
        d_credentials = SensitiveData(hashPasswordInternal(d_credentials.getString(), d_salt, d_workFactor, d_parallelFactor, d_blockSize));
        d_isHashed = true;
      }
    }
    else {
      d_wasHashed = true;
      d_isHashed = true;
      std::string hashedPassword;
      parseHashed(d_credentials.getString(), d_salt, hashedPassword, d_workFactor, d_parallelFactor, d_blockSize);
      d_credentials = SensitiveData(std::move(hashedPassword));
    }
  }

  if (!d_isHashed) {
    d_fallbackHashPerturb = dns_random_uint32();
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    d_fallbackHash = burtle(reinterpret_cast<const unsigned char*>(d_credentials.getString().data()), d_credentials.getString().size(), d_fallbackHashPerturb);
  }
}

CredentialsHolder::~CredentialsHolder()
{
  d_fallbackHashPerturb = 0;
  d_fallbackHash = 0;
}

bool CredentialsHolder::matches(const std::string& password) const
{
  if (d_isHashed) {
    return verifyPassword(d_credentials.getString(), d_salt, d_workFactor, d_parallelFactor, d_blockSize, password);
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  uint32_t fallback = burtle(reinterpret_cast<const unsigned char*>(password.data()), password.size(), d_fallbackHashPerturb);
  if (fallback != d_fallbackHash) {
    return false;
  }

  return constantTimeStringEquals(password, d_credentials.getString());
}

bool CredentialsHolder::isHashingAvailable()
{
#if !defined(DISABLE_HASHED_CREDENTIALS) && defined(HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT)
  return true;
#else
  return false;
#endif
}

#include <csignal>
#include <termios.h>

SensitiveData CredentialsHolder::readFromTerminal()
{
  termios term{};
  termios oterm{};
  bool restoreTermSettings = false;
  int termAction = TCSAFLUSH;
#ifdef TCSASOFT
  termAction |= TCSASOFT;
#endif

  FDWrapper input(open("/dev/tty", O_RDONLY));
  if (int(input) != -1) {
    if (tcgetattr(input, &oterm) == 0) {
      memcpy(&term, &oterm, sizeof(term));
      term.c_lflag &= ~(ECHO | ECHONL);
      tcsetattr(input, termAction, &term);
      restoreTermSettings = true;
    }
  }
  else {
    input = FDWrapper(dup(STDIN_FILENO));
    restoreTermSettings = false;
  }

  FDWrapper output(open("/dev/tty", O_WRONLY));
  if (int(output) == -1) {
    output = FDWrapper(dup(STDERR_FILENO));
  }

  struct std::map<int, struct sigaction> signals;
  struct sigaction sigact // just sigaction does not work, it clashes with sigaction(2)
  {
  };
  sigemptyset(&sigact.sa_mask);
  sigact.sa_flags = 0;
  sigact.sa_handler = [](int /* s */) {};
  sigaction(SIGALRM, &sigact, &signals[SIGALRM]);
  sigaction(SIGHUP, &sigact, &signals[SIGHUP]);
  sigaction(SIGINT, &sigact, &signals[SIGINT]);
  sigaction(SIGPIPE, &sigact, &signals[SIGPIPE]);
  sigaction(SIGQUIT, &sigact, &signals[SIGQUIT]);
  sigaction(SIGTERM, &sigact, &signals[SIGTERM]);
  sigaction(SIGTSTP, &sigact, &signals[SIGTSTP]);
  sigaction(SIGTTIN, &sigact, &signals[SIGTTIN]);
  sigaction(SIGTTOU, &sigact, &signals[SIGTTOU]);

  std::string buffer;
  /* let's allocate a huge buffer now to prevent reallocation,
     which would leave parts of the buffer around */
  buffer.reserve(512);

  for (;;) {
    char character = '\0';
    auto got = read(input, &character, 1);
    if (got == 1 && character != '\n' && character != '\r') {
      buffer.push_back(character);
    }
    else {
      break;
    }
  }

  if (restoreTermSettings) {
    tcsetattr(input, termAction, &oterm);
  }

  for (const auto& sig : signals) {
    sigaction(sig.first, &sig.second, nullptr);
  }

  return {std::move(buffer)};
}
