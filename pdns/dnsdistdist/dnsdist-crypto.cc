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
#include <iostream>
#include <arpa/inet.h>

#include "dnsdist-crypto.hh"

#include "namespaces.hh"
#include "noinitvector.hh"
#include "misc.hh"
#include "base64.hh"

namespace dnsdist::crypto::authenticated
{
#ifdef HAVE_LIBSODIUM
string newKey(bool base64Encoded)
{
  std::string key;
  key.resize(crypto_secretbox_KEYBYTES);

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  randombytes_buf(reinterpret_cast<unsigned char*>(key.data()), key.size());

  if (!base64Encoded) {
    return key;
  }
  return "\"" + Base64Encode(key) + "\"";
}

bool isValidKey(const std::string& key)
{
  return key.size() == crypto_secretbox_KEYBYTES;
}

std::string encryptSym(const std::string_view& msg, const std::string& key, Nonce& nonce, bool incrementNonce)
{
  if (!isValidKey(key)) {
    throw std::runtime_error("Invalid encryption key of size " + std::to_string(key.size()) + " (" + std::to_string(crypto_secretbox_KEYBYTES) + " expected), use setKey() to set a valid key");
  }

  std::string ciphertext;
  ciphertext.resize(msg.length() + crypto_secretbox_MACBYTES);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  crypto_secretbox_easy(reinterpret_cast<unsigned char*>(ciphertext.data()),
                        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                        reinterpret_cast<const unsigned char*>(msg.data()),
                        msg.length(),
                        nonce.value.data(),
                        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                        reinterpret_cast<const unsigned char*>(key.data()));

  if (incrementNonce) {
    nonce.increment();
  }

  return ciphertext;
}

std::string decryptSym(const std::string_view& msg, const std::string& key, Nonce& nonce, bool incrementNonce)
{
  std::string decrypted;

  if (msg.length() < crypto_secretbox_MACBYTES) {
    throw std::runtime_error("Could not decrypt message of size " + std::to_string(msg.length()));
  }

  if (!isValidKey(key)) {
    throw std::runtime_error("Invalid decryption key of size " + std::to_string(key.size()) + ", use setKey() to set a valid key");
  }

  decrypted.resize(msg.length() - crypto_secretbox_MACBYTES);

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (crypto_secretbox_open_easy(reinterpret_cast<unsigned char*>(decrypted.data()),
                                 // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                                 reinterpret_cast<const unsigned char*>(msg.data()),
                                 msg.length(),
                                 nonce.value.data(),
                                 // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                                 reinterpret_cast<const unsigned char*>(key.data()))
      != 0) {
    throw std::runtime_error("Could not decrypt message, please check that the key configured with setKey() is correct");
  }

  if (incrementNonce) {
    nonce.increment();
  }

  return decrypted;
}

void Nonce::init()
{
  randombytes_buf(value.data(), value.size());
}

#elif defined(HAVE_LIBCRYPTO)
#include <openssl/evp.h>
#include <openssl/rand.h>

static constexpr size_t s_CHACHA20_POLY1305_KEY_SIZE = 32U;
static constexpr size_t s_POLY1305_BLOCK_SIZE = 16U;

string newKey(bool base64Encoded)
{
  std::string key;
  key.resize(s_CHACHA20_POLY1305_KEY_SIZE);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (RAND_priv_bytes(reinterpret_cast<unsigned char*>(key.data()), key.size()) != 1) {
    throw std::runtime_error("Could not initialize random number generator for cryptographic functions");
  }
  if (!base64Encoded) {
    return key;
  }
  return "\"" + Base64Encode(key) + "\"";
}

bool isValidKey(const std::string& key)
{
  return key.size() == s_CHACHA20_POLY1305_KEY_SIZE;
}

std::string encryptSym(const std::string_view& msg, const std::string& key, Nonce& nonce, bool incrementNonce)
{
  if (!isValidKey(key)) {
    throw std::runtime_error("Invalid encryption key of size " + std::to_string(key.size()) + " (" + std::to_string(s_CHACHA20_POLY1305_KEY_SIZE) + " expected), use setKey() to set a valid key");
  }

  // Each thread gets its own cipher context
  static thread_local auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(nullptr, EVP_CIPHER_CTX_free);

  if (!ctx) {
    ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
      throw std::runtime_error("encryptSym: EVP_CIPHER_CTX_new() could not initialize cipher context");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
      throw std::runtime_error("encryptSym: EVP_EncryptInit_ex() could not initialize encryption operation");
    }
  }

  std::string ciphertext;
  /* plus one so we can access the last byte in EncryptFinal which does nothing for this algo */
  ciphertext.resize(s_POLY1305_BLOCK_SIZE + msg.length() + 1);
  int outLength{0};
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), nonce.value.data()) != 1) {
    throw std::runtime_error("encryptSym: EVP_EncryptInit_ex() could not initialize encryption key and IV");
  }

  if (!msg.empty()) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (EVP_EncryptUpdate(ctx.get(),
                          reinterpret_cast<unsigned char*>(&ciphertext.at(s_POLY1305_BLOCK_SIZE)), &outLength,
                          reinterpret_cast<const unsigned char*>(msg.data()), msg.length())
        != 1) {
      throw std::runtime_error("encryptSym: EVP_EncryptUpdate() could not encrypt message");
    }
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (EVP_EncryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(&ciphertext.at(s_POLY1305_BLOCK_SIZE + outLength)), &outLength) != 1) {
    throw std::runtime_error("encryptSym: EVP_EncryptFinal_ex() could finalize message encryption");
    ;
  }

  /* Get the tag */
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, s_POLY1305_BLOCK_SIZE, ciphertext.data()) != 1) {
    throw std::runtime_error("encryptSym: EVP_CIPHER_CTX_ctrl() could not get tag");
  }

  if (incrementNonce) {
    nonce.increment();
  }

  ciphertext.resize(ciphertext.size() - 1);
  return ciphertext;
}

std::string decryptSym(const std::string_view& msg, const std::string& key, Nonce& nonce, bool incrementNonce)
{
  if (msg.length() < s_POLY1305_BLOCK_SIZE) {
    throw std::runtime_error("Could not decrypt message of size " + std::to_string(msg.length()));
  }

  if (!isValidKey(key)) {
    throw std::runtime_error("Invalid decryption key of size " + std::to_string(key.size()) + ", use setKey() to set a valid key");
  }

  if (msg.length() == s_POLY1305_BLOCK_SIZE) {
    if (incrementNonce) {
      nonce.increment();
    }
    return std::string();
  }

  // Each thread gets its own cipher context
  static thread_local auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(nullptr, EVP_CIPHER_CTX_free);
  if (!ctx) {
    ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
      throw std::runtime_error("decryptSym: EVP_CIPHER_CTX_new() could not initialize cipher context");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
      throw std::runtime_error("decryptSym: EVP_DecryptInit_ex() could not initialize decryption operation");
    }
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), nonce.value.data()) != 1) {
    throw std::runtime_error("decryptSym: EVP_DecryptInit_ex() could not initialize decryption key and IV");
  }

  const auto tag = msg.substr(0, s_POLY1305_BLOCK_SIZE);
  std::string decrypted;
  /* plus one so we can access the last byte in DecryptFinal, which does nothing */
  decrypted.resize(msg.length() - s_POLY1305_BLOCK_SIZE + 1);
  int outLength{0};
  if (msg.size() > s_POLY1305_BLOCK_SIZE) {
    if (!EVP_DecryptUpdate(ctx.get(),
                           // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                           reinterpret_cast<unsigned char*>(decrypted.data()), &outLength,
                           // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                           reinterpret_cast<const unsigned char*>(&msg.at(s_POLY1305_BLOCK_SIZE)), msg.size() - s_POLY1305_BLOCK_SIZE)) {
      throw std::runtime_error("Could not decrypt message (update failed), please check that the key configured with setKey() is correct");
    }
  }

  /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): sorry, OpenSSL's API is terrible
  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, s_POLY1305_BLOCK_SIZE, const_cast<char*>(tag.data()))) {
    throw std::runtime_error("Could not decrypt message (invalid tag), please check that the key configured with setKey() is correct");
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (!EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(&decrypted.at(outLength)), &outLength)) {
    throw std::runtime_error("Could not decrypt message (final failed), please check that the key configured with setKey() is correct");
  }

  if (incrementNonce) {
    nonce.increment();
  }

  decrypted.resize(decrypted.size() - 1);
  return decrypted;
}

void Nonce::init()
{
  if (RAND_priv_bytes(value.data(), value.size()) != 1) {
    throw std::runtime_error("Could not initialize random number generator for cryptographic functions");
  }
}
#endif

#if defined(HAVE_LIBSODIUM) || defined(HAVE_LIBCRYPTO)
void Nonce::merge(const Nonce& lower, const Nonce& higher)
{
  constexpr size_t halfSize = std::tuple_size<decltype(value)>{} / 2;
  memcpy(value.data(), lower.value.data(), halfSize);
  memcpy(value.data() + halfSize, higher.value.data() + halfSize, halfSize);
}

void Nonce::increment()
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  auto* ptr = reinterpret_cast<uint32_t*>(value.data());
  uint32_t count = htonl(*ptr) + 1;
  *ptr = ntohl(count);
}

#else
void Nonce::init()
{
}

void Nonce::merge(const Nonce& lower, const Nonce& higher)
{
}

void Nonce::increment()
{
}

std::string encryptSym(const std::string_view& msg, const std::string& key, Nonce& nonce, bool incrementNonce)
{
  return std::string(msg);
}
std::string decryptSym(const std::string_view& msg, const std::string& key, Nonce& nonce, bool incrementNonce)
{
  return std::string(msg);
}

string newKey(bool base64Encoded)
{
  return "\"plaintext\"";
}

bool isValidKey(const std::string& key)
{
  return true;
}

#endif
}

#include <cinttypes>

namespace anonpdns
{
static char B64Decode1(char cInChar)
{
  // The incoming character will be A-Z, a-z, 0-9, +, /, or =.
  // The idea is to quickly determine which grouping the
  // letter belongs to and return the associated value
  // without having to search the global encoding string
  // (the value we're looking for would be the resulting
  // index into that string).
  //
  // To do that, we'll play some tricks...
  unsigned char iIndex = '\0';
  switch (cInChar) {
  case '+':
    iIndex = 62;
    break;

  case '/':
    iIndex = 63;
    break;

  case '=':
    iIndex = 0;
    break;

  default:
    // Must be 'A'-'Z', 'a'-'z', '0'-'9', or an error...
    //
    // Numerically, small letters are "greater" in value than
    // capital letters and numerals (ASCII value), and capital
    // letters are "greater" than numerals (again, ASCII value),
    // so we check for numerals first, then capital letters,
    // and finally small letters.
    iIndex = '9' - cInChar;
    if (iIndex > 0x3F) {
      // Not from '0' to '9'...
      iIndex = 'Z' - cInChar;
      if (iIndex > 0x3F) {
        // Not from 'A' to 'Z'...
        iIndex = 'z' - cInChar;
        if (iIndex > 0x3F) {
          // Invalid character...cannot
          // decode!
          iIndex = 0x80; // set the high bit
        } // if
        else {
          // From 'a' to 'z'
          iIndex = (('z' - iIndex) - 'a') + 26;
        } // else
      } // if
      else {
        // From 'A' to 'Z'
        iIndex = ('Z' - iIndex) - 'A';
      } // else
    } // if
    else {
      // Adjust the index...
      iIndex = (('9' - iIndex) - '0') + 52;
    } // else
    break;

  } // switch

  return static_cast<char>(iIndex);
}

static inline char B64Encode1(unsigned char input)
{
  if (input < 26) {
    return static_cast<char>('A' + input);
  }
  if (input < 52) {
    return static_cast<char>('a' + (input - 26));
  }
  if (input < 62) {
    return static_cast<char>('0' + (input - 52));
  }
  if (input == 62) {
    return '+';
  }
  return '/';
};

}
using namespace anonpdns;

template <typename Container>
int B64Decode(const std::string& strInput, Container& strOutput)
{
  // Set up a decoding buffer
  long cBuf = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  char* pBuf = reinterpret_cast<char*>(&cBuf);

  // Decoding management...
  int iBitGroup = 0;
  int iInNum = 0;

  // While there are characters to process...
  //
  // We'll decode characters in blocks of 4, as
  // there are 4 groups of 6 bits in 3 bytes. The
  // incoming Base64 character is first decoded, and
  // then it is inserted into the decode buffer
  // (with any relevant shifting, as required).
  // Later, after all 3 bytes have been reconstituted,
  // we assign them to the output string, ultimately
  // to be returned as the original message.
  int iInSize = static_cast<int>(strInput.size());
  unsigned char cChar = '\0';
  uint8_t pad = 0;
  while (iInNum < iInSize) {
    // Fill the decode buffer with 4 groups of 6 bits
    cBuf = 0; // clear
    pad = 0;
    for (iBitGroup = 0; iBitGroup < 4; ++iBitGroup) {
      if (iInNum < iInSize) {
        // Decode a character
        if (strInput.at(iInNum) == '=') {
          pad++;
        }
        while (isspace(strInput.at(iInNum))) {
          iInNum++;
        }
        cChar = B64Decode1(strInput.at(iInNum++));

      } // if
      else {
        // Decode a padded zero
        cChar = '\0';
      } // else

      // Check for valid decode
      if (cChar > 0x7F) {
        return -1;
      }

      // Adjust the bits
      switch (iBitGroup) {
      case 0:
        // The first group is copied into
        // the least significant 6 bits of
        // the decode buffer...these 6 bits
        // will eventually shift over to be
        // the most significant bits of the
        // third byte.
        cBuf = cBuf | cChar;
        break;

      default:
        // For groupings 1-3, simply shift
        // the bits in the decode buffer over
        // by 6 and insert the 6 from the
        // current decode character.
        cBuf = (cBuf << 6) | cChar;
        break;

      } // switch
    } // for

    // Interpret the resulting 3 bytes...note there
    // may have been padding, so those padded bytes
    // are actually ignored.
#if BYTE_ORDER == BIG_ENDIAN
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    strOutput.push_back(pBuf[sizeof(long) - 3]);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    strOutput.push_back(pBuf[sizeof(long) - 2]);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    strOutput.push_back(pBuf[sizeof(long) - 1]);
#else
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    strOutput.push_back(pBuf[2]);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    strOutput.push_back(pBuf[1]);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    strOutput.push_back(pBuf[0]);
#endif
  } // while
  if (pad) {
    strOutput.resize(strOutput.size() - pad);
  }

  return 1;
}

template int B64Decode<std::vector<uint8_t>>(const std::string& strInput, std::vector<uint8_t>& strOutput);
template int B64Decode<PacketBuffer>(const std::string& strInput, PacketBuffer& strOutput);
template int B64Decode<std::string>(const std::string& strInput, std::string& strOutput);

/*
www.kbcafe.com
Copyright 2001-2002 Randy Charles Morin
The Encode static method takes an array of 8-bit values and returns a base-64 stream.
*/

std::string Base64Encode(const std::string& src)
{
  std::string retval;
  if (src.empty()) {
    return retval;
  }
  for (unsigned int i = 0; i < src.size(); i += 3) {
    unsigned char by1 = 0;
    unsigned char by2 = 0;
    unsigned char by3 = 0;
    by1 = src[i];
    if (i + 1 < src.size()) {
      by2 = src[i + 1];
    };
    if (i + 2 < src.size()) {
      by3 = src[i + 2];
    }
    unsigned char by4 = 0;
    unsigned char by5 = 0;
    unsigned char by6 = 0;
    unsigned char by7 = 0;
    by4 = by1 >> 2;
    by5 = ((by1 & 0x3) << 4) | (by2 >> 4);
    by6 = ((by2 & 0xf) << 2) | (by3 >> 6);
    by7 = by3 & 0x3f;
    retval += B64Encode1(by4);
    retval += B64Encode1(by5);
    if (i + 1 < src.size()) {
      retval += B64Encode1(by6);
    }
    else {
      retval += "=";
    };
    if (i + 2 < src.size()) {
      retval += B64Encode1(by7);
    }
    else {
      retval += "=";
    };
    /*      if ((i % (76 / 4 * 3)) == 0)
      {
        retval += "\r\n";
        }*/
  };
  return retval;
};
