#pragma once
#include "config.h"
#include <string>
#include <stdint.h>

#include <arpa/inet.h>

#ifndef HAVE_LIBSODIUM
struct SodiumNonce
{
	void init(){};
	void increment(){};
	unsigned char value[1];
};
#else
#include <sodium.h>

struct SodiumNonce
{
  void init()
  {
    randombytes_buf(value, sizeof value);
  }
  
  void increment()
  {
    uint32_t* p = (uint32_t*)value;
    uint32_t count=htonl(*p);
    *p=ntohl(++count);
  }

  string toString() const
  {
    return string((const char*)value, crypto_secretbox_NONCEBYTES);
  }

  unsigned char value[crypto_secretbox_NONCEBYTES];
};
#endif
std::string newKeypair();
std::string sodEncryptSym(const std::string& msg, const std::string& key, SodiumNonce&);
std::string sodDecryptSym(const std::string& msg, const std::string& key, SodiumNonce&);
std::string newKey();
