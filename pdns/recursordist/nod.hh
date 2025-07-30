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

#include <mutex>
#include <thread>
#include <boost/filesystem.hpp>

#include "dnsname.hh"
#include "lock.hh"
#include "stable-bloom.hh"

namespace nod
{
const float c_fp_rate = 0.01;
const size_t c_num_cells = 67108864;
const uint8_t c_num_dec = 10;
const unsigned int snapshot_interval_default = 600;
const std::string bf_suffix = "bf";
const std::string sbf_prefix = "sbf";

// Theses classes are not designed to be shared between threads
// Use a new instance per-thread, e.g. using thread local storage
// Synchronization (at the class level) is still needed for reading from
// and writing to the cache dir
// Synchronization (at the instance level) is needed when snapshotting
class PersistentSBF
{
public:
  PersistentSBF() :
    d_sbf(bf::stableBF(c_fp_rate, c_num_cells, c_num_dec)) {}
  PersistentSBF(uint32_t num_cells) :
    d_sbf(bf::stableBF(c_fp_rate, num_cells, c_num_dec)) {}
  bool init(bool ignore_pid = false);
  void setPrefix(const std::string& prefix) { d_prefix = prefix; } // Added to filenames in cachedir
  void setCacheDir(const std::string& cachedir);
  bool snapshotCurrent(std::thread::id tid); // Write the current file out to disk
  void add(const std::string& data)
  {
    d_sbf.lock()->add(data);
  }
  bool test(const std::string& data) { return d_sbf.lock()->test(data); }
  bool testAndAdd(const std::string& data)
  {
    return d_sbf.lock()->testAndAdd(data);
  }

private:
  void remove_tmp_files(const boost::filesystem::path&, std::scoped_lock<std::mutex>&);

  LockGuarded<bf::stableBF> d_sbf; // Stable Bloom Filter
  std::string d_cachedir;
  std::string d_prefix = sbf_prefix;
  // One mutex for all instances of this class, used to avoid multiple init() calls happening
  // simulateneously.  The snapshot code is thread safe wrt file operations, so it does not need to
  // acquire this mutex, assuming the init() code never runs simulatenously with the snapshot code.
  static std::mutex d_cachedir_mutex;
};

class NODDB
{
public:
  NODDB() = default;
  NODDB(uint32_t num_cells) :
    d_psbf{num_cells} {}
  // Set ignore_pid to true if you don't mind loading files
  // created by the current process
  bool init(bool ignore_pid = false)
  {
    d_psbf.setPrefix("nod");
    return d_psbf.init(ignore_pid);
  }
  bool isNewDomain(const std::string& domain); // Returns true if newly observed domain
  bool isNewDomain(const DNSName& dname); // As above
  bool isNewDomainWithParent(const std::string& domain, std::string& observed); // Returns true if newly observed domain, in which case "observed" contains the parent domain which *was* observed (or "" if domain is . or no parent domains observed)
  bool isNewDomainWithParent(const DNSName& dname, std::string& observed); // As above
  void addDomain(const DNSName& dname); // You need to add this to refresh frequently used domains
  void addDomain(const std::string& domain); // As above
  void setSnapshotInterval(unsigned int secs) { d_snapshot_interval = secs; }
  void setCacheDir(const std::string& cachedir) { d_psbf.setCacheDir(cachedir); }
  bool snapshotCurrent(std::thread::id tid) { return d_psbf.snapshotCurrent(tid); }
  void housekeepingThread(std::thread::id tid);

private:
  PersistentSBF d_psbf;
  unsigned int d_snapshot_interval{snapshot_interval_default}; // Number seconds between snapshots
};

class UniqueResponseDB
{
public:
  UniqueResponseDB() = default;
  UniqueResponseDB(uint32_t num_cells) :
    d_psbf{num_cells} {}
  bool init(bool ignore_pid = false)
  {
    d_psbf.setPrefix("udr");
    return d_psbf.init(ignore_pid);
  }
  bool isUniqueResponse(const std::string& response);
  void addResponse(const std::string& response);
  void setSnapshotInterval(unsigned int secs) { d_snapshot_interval = secs; }
  void setCacheDir(const std::string& cachedir) { d_psbf.setCacheDir(cachedir); }
  bool snapshotCurrent(std::thread::id tid) { return d_psbf.snapshotCurrent(tid); }
  void housekeepingThread(std::thread::id tid);

private:
  PersistentSBF d_psbf;
  unsigned int d_snapshot_interval{snapshot_interval_default}; // Number seconds between snapshots
};

}
