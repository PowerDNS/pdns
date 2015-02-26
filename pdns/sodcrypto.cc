#include <sodium.h>
#include <iostream>
#include "namespaces.hh"
#include "misc.hh"
#include "base64.hh"
#include "sodcrypto.hh"


string newKey()
{
  unsigned char key[crypto_secretbox_KEYBYTES];
  randombytes_buf(key, sizeof key);
  return "\""+Base64Encode(string((char*)key, sizeof key))+"\"";
}

std::string sodEncryptSym(const std::string& msg, const std::string& key, SodiumNonce& nonce)
{
  unsigned char ciphertext[msg.length() + crypto_secretbox_MACBYTES];
  crypto_secretbox_easy(ciphertext, (unsigned char*)msg.c_str(), msg.length(), nonce.value, (unsigned char*)key.c_str());

  nonce.increment();
  return string((char*)ciphertext, sizeof(ciphertext));
}

std::string sodDecryptSym(const std::string& msg, const std::string& key, SodiumNonce& nonce)
{
  unsigned char decrypted[msg.length() - crypto_secretbox_MACBYTES];

  if (crypto_secretbox_open_easy(decrypted, (const unsigned char*)msg.c_str(), 
				 msg.length(), nonce.value, (const unsigned char*)key.c_str()) != 0) {
    throw std::runtime_error("Could not decrypt message");
  }
  nonce.increment();
  return string((char*)decrypted, sizeof(decrypted));
}


