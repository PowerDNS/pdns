#include "ipcipher.hh"
#include "ext/ipcrypt/ipcrypt.h"
#include <openssl/aes.h>
#include <openssl/evp.h>

/*
int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
                           const unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out);
*/
std::string makeIPCipherKey(const std::string& password)
{
  static const char salt[]="ipcipheripcipher";
  unsigned char out[16];

  PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), (const unsigned char*)salt, sizeof(salt)-1, 50000, sizeof(out), out);

  return std::string((const char*)out, (const char*)out + sizeof(out));
}

static ComboAddress encryptCA4(const ComboAddress& ca, const std::string &key)
{
  if(key.size() != 16)
    throw std::runtime_error("Need 128 bits of key for ipcrypt");

  ComboAddress ret=ca;

  // always returns 0, has no failure mode
  ipcrypt_encrypt(      (unsigned char*)&ret.sin4.sin_addr.s_addr,
                 (const unsigned char*)  &ca.sin4.sin_addr.s_addr,
                 (const unsigned char*)key.c_str());
  return ret;
}

static ComboAddress decryptCA4(const ComboAddress& ca, const std::string &key)
{
  if(key.size() != 16)
    throw std::runtime_error("Need 128 bits of key for ipcrypt");

  ComboAddress ret=ca;

  // always returns 0, has no failure mode
  ipcrypt_decrypt(      (unsigned char*)&ret.sin4.sin_addr.s_addr,
                 (const unsigned char*)  &ca.sin4.sin_addr.s_addr,
                 (const unsigned char*)key.c_str());
  return ret;
}


static ComboAddress encryptCA6(const ComboAddress& ca, const std::string &key)
{
  if(key.size() != 16)
    throw std::runtime_error("Need 128 bits of key for ipcrypt");

  ComboAddress ret=ca;

  AES_KEY wctx;
  AES_set_encrypt_key((const unsigned char*)key.c_str(), 128, &wctx);
  AES_encrypt((const unsigned char*)&ca.sin6.sin6_addr.s6_addr,
              (unsigned char*)&ret.sin6.sin6_addr.s6_addr, &wctx);

  return ret;
}

static ComboAddress decryptCA6(const ComboAddress& ca, const std::string &key)
{
  if(key.size() != 16)
    throw std::runtime_error("Need 128 bits of key for ipcrypt");

  ComboAddress ret=ca;
  AES_KEY wctx;
  AES_set_decrypt_key((const unsigned char*)key.c_str(), 128, &wctx);
  AES_decrypt((const unsigned char*)&ca.sin6.sin6_addr.s6_addr,
              (unsigned char*)&ret.sin6.sin6_addr.s6_addr, &wctx);

  return ret;
}


ComboAddress encryptCA(const ComboAddress& ca, const std::string& key)
{
  if(ca.sin4.sin_family == AF_INET)
    return encryptCA4(ca, key);
  else if(ca.sin4.sin_family == AF_INET6)
    return encryptCA6(ca, key);
  else
    throw std::runtime_error("ipcrypt can't encrypt non-IP addresses");
}

ComboAddress decryptCA(const ComboAddress& ca, const std::string& key)
{
  if(ca.sin4.sin_family == AF_INET)
    return decryptCA4(ca, key);
  else if(ca.sin4.sin_family == AF_INET6)
    return decryptCA6(ca, key);
  else
    throw std::runtime_error("ipcrypt can't decrypt non-IP addresses");

}
