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
#include <atomic>
#include <mutex>
#include "dnsname.hh"
#include "ext/hll/hyperloglog.hpp"

namespace nod {

  const unsigned int rotate_days_default = 1;
  const unsigned int max_files_default = 365;
  const unsigned int snapshot_interval_default = 600;
  const unsigned int hll_width_default = 10;
  const std::string current_filename = "current";
  const std::string hll_suffix = "hll";
  
  class NODDB {
  public:
    NODDB(): d_current_creation(time(0)) {}
    bool init(); // Initialize the NODDB
    bool isNewDomain(const std::string& domain); // Returns true if newly observed domain
    bool isNewDomain(const DNSName& dname); // As above
    bool isNewDomainWithParent(const std::string& domain, std::string& observed); // Returns true if newly observed domain, in which case "observed" contains the parent domain which *was* observed (or "" if domain is .)
    bool isNewDomainWithParent(const DNSName& dname, std::string& observed); // As above
    void addDomain(const DNSName& dname); // This just adds to current HLL (i.e. if domain is already known about
    void addDomain(const std::string& domain); // As above
    void setRotateDays(unsigned int days) { d_rotatedays = days; }
    void setSnapshotInterval(unsigned int secs) { d_snapshot_interval = secs; }
    void setMaxFiles(unsigned int max_files) { d_maxfiles = max_files; }
    void setCacheDir(const std::string& cachedir);
    bool snapshotCurrent(); // Write the current file out to disk
    bool rotateCurrent(); // Write, rename the current file on disk & start new current
    bool removeCacheFiles(); // Remove all hll cache files from cache dir
    bool pruneCacheFiles(); // Remove oldest cache files if more than max no
    static void startHousekeepingThread(std::shared_ptr<NODDB> noddbp) {
      noddbp->d_housekeeping = true;
      noddbp->housekeepingThread();
    }
    void stopHousekeepingThread() { d_housekeeping = false; }
  private:
    void housekeepingThread();
    bool checkCardinality(const std::string& native_domain);
    bool snapshotCurrentInternal();
    bool rotateCurrentInternal();
    bool pruneCacheFilesInternal();
    std::atomic<bool> d_init{false};
    hll::HyperLogLog d_hll_master{hll_width_default}; // This contains the merged entries
    hll::HyperLogLog d_hll_current{hll_width_default}; // This only contains current entries
    time_t d_current_creation; // When current hll was created
    std::atomic<unsigned int> d_rotatedays{rotate_days_default}; // Number of days before rotating current
    std::atomic<unsigned int> d_maxfiles{max_files_default}; // Maximum number of files to keep before deleting oldest
    std::atomic<unsigned int> d_snapshot_interval{snapshot_interval_default}; // Number seconds between snapshots
    std::atomic<bool> d_housekeeping{false};
    uint64_t d_cached_cardinality{0};
    std::string d_cachedir;
    std::mutex d_mutex;
  };

}
