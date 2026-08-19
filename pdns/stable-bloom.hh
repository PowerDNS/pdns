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

#include <vector>
#include <cmath>
#include <random>
#include <arpa/inet.h>
#include <boost/dynamic_bitset.hpp>
#include "misc.hh"
#include "noinitvector.hh"
#include "ext/probds/murmur3.h"

namespace bf
{
// Based on http://webdocs.cs.ualberta.ca/~drafiei/papers/DupDetExt.pdf
// Max is always 1 in this implementation, which is best for streaming data
// This also means we can use a bitset for storing values which is very
// efficient
class stableBF
{
public:
  stableBF(float fp_rate, uint32_t num_cells, uint8_t pArg) :
    d_k(optimalK(fp_rate)),
    d_num_cells(num_cells),
    d_p(pArg),
    d_cells(num_cells),
    d_gen(std::random_device()()),
    d_dis(0, static_cast<int>(num_cells)) {}
  stableBF(uint8_t kArg, uint32_t num_cells, uint8_t pArg, const std::string& bitstr) :
    d_k(kArg),
    d_num_cells(num_cells),
    d_p(pArg),
    d_cells(bitstr),
    d_gen(std::random_device()()),
    d_dis(0, static_cast<int>(num_cells)) {}

  void add(const std::string& data)
  {
    decrement();
    auto hashes = hash(data);
    for (auto& hash : hashes) {
      d_cells.set(hash % d_num_cells);
    }
  }

  [[nodiscard]] bool test(const std::string& data) const
  {
    auto hashes = hash(data);
    for (auto& hash : hashes) { // NOLINT(readability-use-anyofallof) not more clear IMO
      if (!d_cells.test(hash % d_num_cells)) {
        return false;
      }
    }
    return true;
  }

  bool testAndAdd(const std::string& data)
  {
    auto hashes = hash(data);
    bool retval = true;
    for (auto& hash : hashes) {
      if (!d_cells.test(hash % d_num_cells)) {
        retval = false;
        break;
      }
    }
    decrement();
    for (auto& hash : hashes) {
      d_cells.set(hash % d_num_cells);
    }
    return retval;
  }

  void dump(std::ostream& ostr)
  {
    ostr.write(charPtr(&d_k), sizeof(d_k));
    uint32_t nint = htonl(d_num_cells);
    ostr.write(charPtr(&nint), sizeof(nint));
    ostr.write(charPtr(&d_p), sizeof(d_p));
    std::string temp_str;
    boost::to_string(d_cells, temp_str);
    uint32_t bitstr_length = htonl(static_cast<uint32_t>(temp_str.length()));
    ostr.write(charPtr(&bitstr_length), sizeof(bitstr_length));
    ostr.write(charPtr(temp_str.c_str()), static_cast<std::streamsize>(temp_str.length()));
    if (ostr.fail()) {
      throw std::runtime_error("SBF: Failed to dump");
    }
  }

  void restore(std::istream& istr)
  {
    uint8_t kValue{};
    istr.read(charPtr(&kValue), sizeof(kValue));
    if (istr.fail()) {
      throw std::runtime_error("SBF: read failed (file too short?)");
    }
    uint32_t num_cells{};
    istr.read(charPtr(&num_cells), sizeof(num_cells));
    if (istr.fail()) {
      throw std::runtime_error("SBF: read failed (file too short?)");
    }
    num_cells = ntohl(num_cells);
    uint8_t pValue{};
    istr.read(charPtr(&pValue), sizeof(pValue));
    if (istr.fail()) {
      throw std::runtime_error("SBF: read failed (file too short?)");
    }
    uint32_t bitstr_len{};
    istr.read(charPtr(&bitstr_len), sizeof(bitstr_len));
    if (istr.fail()) {
      throw std::runtime_error("SBF: read failed (file too short?)");
    }
    bitstr_len = ntohl(bitstr_len);
    if (bitstr_len > 2 * 64 * 1024 * 1024U) { // twice the current size
      throw std::runtime_error("SBF: read failed (bitstr_len too big)");
    }
    auto bitcstr = NoInitVector<char>(bitstr_len);
    istr.read(bitcstr.data(), bitstr_len);
    if (istr.fail()) {
      throw std::runtime_error("SBF: read failed (file too short?)");
    }
    const std::string bitstr(bitcstr.data(), bitstr_len);
    stableBF tempbf(kValue, num_cells, pValue, bitstr);
    swap(tempbf);
  }

private:
  static const char* charPtr(const void* ptr)
  {
    return static_cast<const char*>(ptr);
  }

  static char* charPtr(void* ptr)
  {
    return static_cast<char*>(ptr);
  }

  static unsigned int optimalK(float fp_rate)
  {
    return std::ceil(std::log2(1.0 / fp_rate));
  }

  void decrement()
  {
    // Choose a random cell then decrement the next p-1
    // The stable bloom algorithm described in the paper says
    // to choose p independent positions, but that is much slower
    // and this shouldn't change the properties of the SBF
    size_t randomValue = d_dis(d_gen);
    for (uint64_t i = 0; i < d_p; ++i) {
      d_cells.reset((randomValue + i) % d_num_cells);
    }
  }

  void swap(stableBF& rhs)
  {
    std::swap(d_k, rhs.d_k);
    std::swap(d_num_cells, rhs.d_num_cells);
    std::swap(d_p, rhs.d_p);
    d_cells.swap(rhs.d_cells);
  }

  // This is a double hash implementation returning an array of
  // k hashes
  [[nodiscard]] std::vector<uint32_t> hash(const std::string& data) const
  {
    uint32_t hash1{};
    uint32_t hash2{};
    // MurmurHash3 assumes the data is uint32_t aligned, so fixup if needed
    // It does handle string lengths that are not a multiple of sizeof(uint32_t) correctly
    if (reinterpret_cast<uintptr_t>(data.data()) % sizeof(uint32_t) != 0) { // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      NoInitVector<uint32_t> vec((data.length() / sizeof(uint32_t)) + 1);
      memcpy(vec.data(), data.data(), data.length());
      MurmurHash3_x86_32(vec.data(), static_cast<int>(data.length()), 1, &hash1);
      MurmurHash3_x86_32(vec.data(), static_cast<int>(data.length()), 2, &hash2);
    }
    else {
      MurmurHash3_x86_32(data.data(), static_cast<int>(data.length()), 1, &hash1);
      MurmurHash3_x86_32(data.data(), static_cast<int>(data.length()), 2, &hash2);
    }
    std::vector<uint32_t> ret_hashes(d_k);
    for (size_t i = 0; i < d_k; ++i) {
      ret_hashes[i] = hash1 + i * hash2;
    }
    return ret_hashes;
  }

  uint8_t d_k;
  uint32_t d_num_cells;
  uint8_t d_p;
  boost::dynamic_bitset<> d_cells;
  std::mt19937 d_gen;
  std::uniform_int_distribution<> d_dis;
};
}
