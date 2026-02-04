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

#include "base64.hh"
#include <stdexcept>
#include <boost/scoped_array.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>

template <typename Container>
int B64Decode(const std::string& src, Container& dst)
{
  if (src.empty()) {
    dst.clear();
    return 0;
  }
  // check if the dlen computation might overflow or it does not fit into an int (for IO_write)
  if (src.length() > std::numeric_limits<size_t>::max() / 7 || src.length() > std::numeric_limits<int>::max()) {
    throw std::runtime_error("B64Decode too large");
  }
  const size_t dlen = (src.length() * 6 + 7) / 8;
  dst.resize(dlen);
  BIO* bio = BIO_new(BIO_s_mem());
  if (bio == nullptr) {
    throw std::runtime_error("BIO_new failed");
  }
  if (BIO_write(bio, src.c_str(), src.length()) != static_cast<int>(src.length())) {
    BIO_free_all(bio);
    throw std::runtime_error("BIO_write failed");
  }
  BIO* b64 = BIO_new(BIO_f_base64());
  if (b64 == nullptr) {
    BIO_free_all(bio);
    throw std::runtime_error("BIO_new failed");
  }
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  ssize_t olen = BIO_read(b64, &dst.at(0), dlen);
  if ((olen == 0 || olen == -1) && BIO_should_retry(bio)) {
    BIO_free_all(bio);
    throw std::runtime_error("BIO_read failed to read all data from memory buffer");
  }
  BIO_free_all(bio);
  if (olen > 0) {
    dst.resize(olen);
    return 0;
  }
  return -1;
}

template int B64Decode<std::string>(const std::string& strInput, std::string& strOutput);

std::string Base64Encode(const std::string& src)
{
  if (!src.empty()) {
    BIO* b64 = BIO_new(BIO_f_base64());
    if (b64 == nullptr) {
      throw std::runtime_error("BIO_new failed");
    }
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
      BIO_free_all(b64);
      std::runtime_error("BIO_new failed");
    }
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int bioWriteRet = BIO_write(bio, src.c_str(), src.length());
    if (bioWriteRet < 0 || (size_t)bioWriteRet != src.length()) {
      BIO_free_all(bio);
      throw std::runtime_error("BIO_write failed to write all data to memory buffer");
    }
    (void)BIO_flush(bio);
    char* pp;
    std::string out;
    size_t olen = BIO_get_mem_data(bio, &pp);
    if (olen > 0) {
      out = std::string(pp, olen);
    }
    BIO_free_all(bio);
    return out;
  }
  return "";
}

#if 0
#include <iostream>
int main() {
  std::string in = "PowerDNS Test String 1";
  std::string out = Base64Encode(in);
  std::cout << out << std::endl;
  if (out != "UG93ZXJETlMgVGVzdCBTdHJpbmcgMQ==") {
    std::cerr << "output did not match expected data" << std::endl;
  }
  std::string roundtrip;
  B64Decode(out, roundtrip);
  std::cout << roundtrip << std::endl;
  if (roundtrip != in) {
    std::cerr << "roundtripped data did not match input data" << std::endl;
  }
  return 0;
}
#endif
