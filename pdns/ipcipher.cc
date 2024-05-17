#include "ipcipher.hh"
#include "ext/ipcrypt/ipcrypt.h"
#include <cassert>
#include <openssl/aes.h>
#include <openssl/evp.h>

#ifdef HAVE_IPCIPHER
/*
int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
                           const unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out);
*/
std::string makeIPCipherKey(const std::string& password)
{
  static const char salt[] = "ipcipheripcipher";
  unsigned char out[16];

  PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), (const unsigned char*)salt, sizeof(salt) - 1, 50000, sizeof(out), out);

  return std::string((const char*)out, (const char*)out + sizeof(out));
}

static ComboAddress encryptCA4(const ComboAddress& ca, const std::string& key)
{
  if (key.size() != 16) {
    throw std::runtime_error("Need 128 bits of key for ipcrypt");
  }

  ComboAddress ret = ca;

  // always returns 0, has no failure mode
  ipcrypt_encrypt((unsigned char*)&ret.sin4.sin_addr.s_addr,
                  (const unsigned char*)&ca.sin4.sin_addr.s_addr,
                  (const unsigned char*)key.c_str());

  return ret;
}

static ComboAddress decryptCA4(const ComboAddress& ca, const std::string& key)
{
  if (key.size() != 16) {
    throw std::runtime_error("Need 128 bits of key for ipcrypt");
  }

  ComboAddress ret = ca;

  // always returns 0, has no failure mode
  ipcrypt_decrypt((unsigned char*)&ret.sin4.sin_addr.s_addr,
                  (const unsigned char*)&ca.sin4.sin_addr.s_addr,
                  (const unsigned char*)key.c_str());

  return ret;
}

static ComboAddress encryptCA6(const ComboAddress& address, const std::string& key)
{
  if (key.size() != 16) {
    throw std::runtime_error("Need 128 bits of key for ipcrypt");
  }

  ComboAddress ret = address;

#if OPENSSL_VERSION_MAJOR >= 3
  auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error("encryptCA6: Could not initialize cipher context");
  }

  auto aes128cbc = std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)>(EVP_CIPHER_fetch(nullptr, "AES-128-CBC", nullptr), &EVP_CIPHER_free);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  if (EVP_EncryptInit(ctx.get(), aes128cbc.get(), reinterpret_cast<const unsigned char*>(key.c_str()), nullptr) == 0) {
    throw pdns::OpenSSL::error("encryptCA6: Could not initialize encryption algorithm");
  }

  // Disable padding
  const auto inSize = sizeof(address.sin6.sin6_addr.s6_addr);
  static_assert(inSize == 16, "We disable padding and so we must assume a data size of 16 bytes");
  const auto blockSize = EVP_CIPHER_get_block_size(aes128cbc.get());
  if (blockSize != 16) {
    throw pdns::OpenSSL::error("encryptCA6: unexpected block size");
  }
  EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

  int updateLen = 0;
  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  const auto* input = reinterpret_cast<const unsigned char*>(&address.sin6.sin6_addr.s6_addr);
  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  auto* output = reinterpret_cast<unsigned char*>(&ret.sin6.sin6_addr.s6_addr);
  if (EVP_EncryptUpdate(ctx.get(), output, &updateLen, input, static_cast<int>(inSize)) == 0) {
    throw pdns::OpenSSL::error("encryptCA6: Could not encrypt address");
  }

  int finalLen = 0;
  if (EVP_EncryptFinal_ex(ctx.get(), output + updateLen, &finalLen) == 0) {
    throw pdns::OpenSSL::error("encryptCA6: Could not finalize address encryption");
  }

  if ((updateLen + finalLen) != inSize) {
    throw pdns::OpenSSL::error("encryptCA6: unexpected final size");
  }
#else
  AES_KEY wctx;
  AES_set_encrypt_key((const unsigned char*)key.c_str(), 128, &wctx);
  AES_encrypt((const unsigned char*)&address.sin6.sin6_addr.s6_addr,
              (unsigned char*)&ret.sin6.sin6_addr.s6_addr, &wctx);
#endif

  return ret;
}

static ComboAddress decryptCA6(const ComboAddress& address, const std::string& key)
{
  if (key.size() != 16) {
    throw std::runtime_error("Need 128 bits of key for ipcrypt");
  }

  ComboAddress ret = address;

#if OPENSSL_VERSION_MAJOR >= 3
  auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error("decryptCA6: Could not initialize cipher context");
  }

  auto aes128cbc = std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)>(EVP_CIPHER_fetch(nullptr, "AES-128-CBC", nullptr), &EVP_CIPHER_free);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  if (EVP_DecryptInit(ctx.get(), aes128cbc.get(), reinterpret_cast<const unsigned char*>(key.c_str()), nullptr) == 0) {
    throw pdns::OpenSSL::error("decryptCA6: Could not initialize decryption algorithm");
  }

  // Disable padding
  const auto inSize = sizeof(address.sin6.sin6_addr.s6_addr);
  static_assert(inSize == 16, "We disable padding and so we must assume a data size of 16 bytes");
  const auto blockSize = EVP_CIPHER_get_block_size(aes128cbc.get());
  if (blockSize != 16) {
    throw pdns::OpenSSL::error("decryptCA6: unexpected block size");
  }
  EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

  int updateLen = 0;
  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  const auto* input = reinterpret_cast<const unsigned char*>(&address.sin6.sin6_addr.s6_addr);
  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  auto* output = reinterpret_cast<unsigned char*>(&ret.sin6.sin6_addr.s6_addr);
  if (EVP_DecryptUpdate(ctx.get(), output, &updateLen, input, static_cast<int>(inSize)) == 0) {
    throw pdns::OpenSSL::error("decryptCA6: Could not decrypt address");
  }

  int finalLen = 0;
  if (EVP_DecryptFinal_ex(ctx.get(), output + updateLen, &finalLen) == 0) {
    throw pdns::OpenSSL::error("decryptCA6: Could not finalize address decryption");
  }

  if ((updateLen + finalLen) != inSize) {
    throw pdns::OpenSSL::error("decryptCA6: unexpected final size");
  }
#else
  AES_KEY wctx;
  AES_set_decrypt_key((const unsigned char*)key.c_str(), 128, &wctx);
  AES_decrypt((const unsigned char*)&address.sin6.sin6_addr.s6_addr,
              (unsigned char*)&ret.sin6.sin6_addr.s6_addr, &wctx);
#endif

  return ret;
}

ComboAddress encryptCA(const ComboAddress& ca, const std::string& key)
{
  if (ca.sin4.sin_family == AF_INET) {
    return encryptCA4(ca, key);
  }

  if (ca.sin4.sin_family == AF_INET6) {
    return encryptCA6(ca, key);
  }

  throw std::runtime_error("ipcrypt can't encrypt non-IP addresses");
}

ComboAddress decryptCA(const ComboAddress& ca, const std::string& key)
{
  if (ca.sin4.sin_family == AF_INET) {
    return decryptCA4(ca, key);
  }

  if (ca.sin4.sin_family == AF_INET6) {
    return decryptCA6(ca, key);
  }

  throw std::runtime_error("ipcrypt can't decrypt non-IP addresses");
}

#endif /* HAVE_IPCIPHER */
