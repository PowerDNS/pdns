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
#include "ext/probds/murmur3.h"

namespace bf
{
  // Based on http://webdocs.cs.ualberta.ca/~drafiei/papers/DupDetExt.pdf
  // Max is always 1 in this implementation, which is best for streaming data
  // This also means we can use a bitset for storing values which is very
  // efficient
  class stableBF {
  public:
    stableBF(float fp_rate, uint32_t num_cells, uint8_t p): d_k(optimalK(fp_rate)), d_num_cells(num_cells), d_p(p), d_cells(num_cells), d_gen(std::random_device()()), d_dis(0, num_cells) {}
    stableBF(uint8_t k, uint32_t num_cells, uint8_t p, const std::string& bitstr): d_k(k), d_num_cells(num_cells), d_p(p), d_cells(bitstr), d_gen(std::random_device()()), d_dis(0, num_cells) {}
    void add(const std::string& data) {
      decrement();
      auto hashes = hash(data);
      for (auto& i : hashes) {
        d_cells.set(i % d_num_cells);
      }
    }
    bool test(const std::string& data) {
      auto hashes = hash(data);
      for (auto& i : hashes) {
        if (d_cells.test(i % d_num_cells) == false)
          return false;
      }
      return true;
    }
    bool testAndAdd(const std::string& data) {
      auto hashes = hash(data);
      bool retval = true;
      for (auto& i : hashes) {
        if (d_cells.test(i % d_num_cells) == false) {
          retval = false;
          break;
        }
      }
      decrement();
      for (auto& i : hashes) {
        d_cells.set(i % d_num_cells);
      }
      return retval;
    }
    void dump(std::ostream& os) {
      os.write((char*)&d_k, sizeof(d_k));
      uint32_t nint = htonl(d_num_cells);
      os.write((char*)&nint, sizeof(nint));
      os.write((char*)&d_p, sizeof(d_p));
      std::string temp_str;
      boost::to_string(d_cells, temp_str);
      uint32_t bitstr_length = htonl((uint32_t)temp_str.length());
      os.write((char*)&bitstr_length, sizeof(bitstr_length));
      os.write((char*)temp_str.c_str(), temp_str.length());
      if (os.fail()) {
        throw std::runtime_error("SBF: Failed to dump");
      }
    }
    void restore(std::istream& is) {
      uint8_t k, p;
      uint32_t num_cells, bitstr_len;
      is.read((char*)&k, sizeof(k));
      is.read((char*)&num_cells, sizeof(num_cells));
      num_cells = ntohl(num_cells);
      is.read((char*)&p, sizeof(p));
      is.read((char*)&bitstr_len, sizeof(bitstr_len));
      bitstr_len = ntohl(bitstr_len);
      char* bitcstr = new char[bitstr_len];
      is.read((char*)bitcstr, bitstr_len);
      std::string bitstr(bitcstr, bitstr_len);
      delete[]  bitcstr;
      stableBF tempbf(k, num_cells, p, bitstr);
      swap(tempbf);
    }
  private:
    unsigned int optimalK(float fp_rate) {
      return std::ceil(std::log2(1/fp_rate));
    }
    void decrement() {
      // Choose a random cell then decrement the next p-1
      // The stable bloom algorithm described in the paper says
      // to choose p independent positions, but that is much slower
      // and this shouldn't change the properties of the SBF
      size_t r = d_dis(d_gen);
      for (uint64_t i=0; i<d_p; ++i) {
        d_cells.reset((r+i) % d_num_cells);
      }
    }
    void swap(stableBF& rhs) {
      std::swap(d_k, rhs.d_k);
      std::swap(d_num_cells, rhs.d_num_cells);
      std::swap(d_p, rhs.d_p);
      d_cells.swap(rhs.d_cells);
    }
    // This is a double hash implementation returning an array of
    // k hashes
    std::vector<uint32_t> hash(const std::string& data) {
      uint32_t h1, h2;
      MurmurHash3_x86_32(data.c_str(), data.length(), 1, (void*)&h1);
      MurmurHash3_x86_32(data.c_str(), data.length(), 2, (void*)&h2);
      std::vector<uint32_t> ret_hashes(d_k);
      for (size_t i=0; i < d_k; ++i) {
        ret_hashes[i] = h1 + i * h2;
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
