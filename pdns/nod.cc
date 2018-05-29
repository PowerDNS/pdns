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

#include "nod.hh"
#include "pdnsexception.hh"
#include <iostream>
#include <iomanip>
#include <regex>
#include <thread>
#include <boost/filesystem.hpp>
#include "logger.hh"

using namespace nod;
using namespace boost::filesystem;

void NODDB::init() {
  if (d_init)
    return;
  
  if (d_cachedir.length()) {
    path p(d_cachedir);
    try {
      if (exists(p) && is_directory(p)) {
        for (auto& i : directory_iterator(p)) {
          std::string filename = i.path().string();
          std::ifstream myfile;
          std::regex hll_regex(".*\\." + hll_suffix + "$");
          std::regex current_regex(current_filename + "\\." + hll_suffix + "$");
          
          try {
            if (is_regular_file(i.path()) &&
                std::regex_match(i.path().filename().string(), hll_regex)) {
              myfile.open(filename, std::ios::in | std::ios::binary);
              hll::HyperLogLog temphll;
              time_t temptime=0;
              myfile.read((char*)&temptime, sizeof(temptime));
              temphll.restore(myfile);
              if (std::regex_match(i.path().filename().string(), current_regex)) {
                d_hll_master.merge(temphll);
                d_hll_current.swap(temphll);
                d_current_creation = temptime;
              }
              else {
                d_hll_master.merge(temphll);
              }
            }
          }
          catch (const std::runtime_error& e) {
            g_log<<Logger::Warning<<"NODDB init: Cannot parse file: " << filename << endl;
          }
        }
      }
    }
    catch (const filesystem_error& e) {
      throw PDNSException(std::string("NODDB init: ") + e.what());
    }
  }
  d_cached_cardinality = static_cast<int>(d_hll_master.estimate());
  d_init = true;
}

void NODDB::housekeepingThread()
{
  for (;;) {
    if (d_housekeeping == false)
      break;
    sleep(d_snapshot_interval);
    {
      std::lock_guard<std::mutex> lock(d_mutex);
      time_t now = time(0);
      if (((now - d_current_creation)/86400) >= d_rotatedays) {
        rotateCurrentInternal();
        pruneCacheFilesInternal();
      }
      else {
        snapshotCurrentInternal();
      }
    }
  }
}

void NODDB::setCacheDir(const std::string& cachedir)
{
  std::lock_guard<std::mutex> lock(d_mutex);
  path p(cachedir);
  if (!exists(p))
    throw PDNSException("NODDB setCacheDir specified non-existent directory: " + cachedir);
  else if (!is_directory(p))
    throw PDNSException("NODDB setCacheDir specified a file not a directory: " + cachedir);
  d_cachedir = cachedir;
}

bool NODDB::checkCardinality(const std::string& native_domain)
{
  if (!d_init)
    throw PDNSException("NODDB not initialized");

  std::lock_guard<std::mutex> lock(d_mutex);
  uint64_t orig_cardinality = d_cached_cardinality;
  d_hll_master.add(native_domain.c_str(), native_domain.length());
  d_hll_current.add(native_domain.c_str(), native_domain.length());
  uint64_t post_cardinality = d_cached_cardinality = static_cast<int>(d_hll_master.estimate());
  if (post_cardinality == orig_cardinality)
    return false;
  else
    return true;
}

bool NODDB::isNewDomain(const std::string& domain)
{
  DNSName dname(domain);
  return isNewDomain(dname);
}

bool NODDB::isNewDomain(const DNSName& dname)
{
  return checkCardinality(dname.toDNSStringLC());
}

bool NODDB::isNewDomainWithParent(const std::string& domain, std::string& observed)
{
  DNSName dname(domain);
  return isNewDomainWithParent(dname, observed);
}

bool NODDB::isNewDomainWithParent(const DNSName& dname, std::string& observed)
{
  bool ret = isNewDomain(dname);
  if (ret == true) {
    DNSName mdname = dname;
    while (mdname.chopOff()) {
      if (checkCardinality(mdname.toDNSStringLC()) == false) {
        observed = mdname.toString();
        break;
      }
    }
  }
  return ret;
}

// If isNewDomain is only called for domains we known might be new (e.g. cache miss)
// then we won't be updating the current HLL which should be a full record of all domains
// seen. Thus the need for this function which should be called if isNewDomain is not
// called.
void NODDB::addDomain(const DNSName& dname)
{
    std::string native_domain = dname.toDNSStringLC();
    std::lock_guard<std::mutex> lock(d_mutex);
    d_hll_current.add(native_domain.c_str(), native_domain.length());
}

void NODDB::addDomain(const std::string& domain)
{
  DNSName dname(domain);
  addDomain(dname);
}

bool NODDB::snapshotCurrent()
{
  std::lock_guard<std::mutex> lock(d_mutex);
  return snapshotCurrentInternal();
}

// This expected the mutex to be locked already
bool NODDB::snapshotCurrentInternal()
{    
  if (d_init && d_cachedir.length()) {
    path p(d_cachedir);
    path f(d_cachedir);
    f /= current_filename + "." + hll_suffix; // Append filename
    if (exists(p) && is_directory(p)) {
      try {
        std::ofstream ofile;
        ofile.open(f.string(), std::ios::out | std::ios::binary);
        ofile.write((char*)&d_current_creation, sizeof(d_current_creation));
        d_hll_current.dump(ofile);
        if (ofile.fail())
          throw std::runtime_error("Failed to write to file:" + f.string());
        return true;
      }
      catch (const std::runtime_error& e) {
        g_log<<Logger::Warning<<"NODDB snapshot: Cannot write file: " << e.what() << endl;
      }
    }
    else {
      g_log<<Logger::Warning<<"NODDB snapshot: Cannot write file: " << f.string() << endl;
    }
  }
  return false;
}

bool NODDB::rotateCurrent()
{
  std::lock_guard<std::mutex> lock(d_mutex);
  return rotateCurrentInternal();
}

// Lock the mutex before calling this
bool NODDB::rotateCurrentInternal()
{
  if (d_init && d_cachedir.length()) {
    path fold(d_cachedir), fnew(d_cachedir);
    {
      fold /= current_filename + "." + hll_suffix;
      time_t now = time(0);
      struct tm tm;
      localtime_r(&now, &tm);
      std::ostringstream oss;
      oss << std::put_time(&tm, "%d-%m-%Y-%H-%M-%S");
      fnew /= oss.str() + "." + hll_suffix;
    }
 
    if (snapshotCurrentInternal() && exists(fold)) {
      try {
        rename(fold, fnew);
        d_hll_current.clear();
        d_current_creation = time(0);
        return true;
      }
      catch (const filesystem_error& e) {
        g_log<<Logger::Warning<<"NODDB rotateCurrent: Cannot rotate file: " << e.what() << endl;
      }
    }
    else {
      g_log<<Logger::Warning<<"NODDB rotateCurrent: Current file doesn't exist or cannot write snapshot: " << fold.string() << endl;
    }
  }
  return false;
}

bool NODDB::removeCacheFiles()
{
  std::lock_guard<std::mutex> lock(d_mutex);
  if (d_init && d_cachedir.length()) {
    path p(d_cachedir);
    try {
      if (exists(p) && is_directory(p)) {
        for (auto& i : directory_iterator(p)) {
          std::string filename = i.path().string();
          std::regex hll_regex(".*\\." + hll_suffix + "$");
          if (is_regular_file(i.path()) &&
              std::regex_match(i.path().filename().string(), hll_regex)) {
            remove(i.path());
          }
        }
        return true;
      }
    }
    catch (const filesystem_error& e) {
      g_log<<Logger::Warning<<"NODDB removeCacheFiles: cannot remove files" << e.what() << endl;
    }
  }
  return false;
}

bool NODDB::pruneCacheFiles()
{
  std::lock_guard<std::mutex> lock(d_mutex);
  return pruneCacheFilesInternal();
}

// Lock mutex before calling this
bool NODDB::pruneCacheFilesInternal()
{
  if (d_init && d_cachedir.length()) {
    path p(d_cachedir);
    try {
      if (exists(p) && is_directory(p)) {
        std::vector<std::pair<path, time_t>> v;
        for (auto& i : directory_iterator(p)) {
          std::string filename = i.path().string();
          std::regex hll_regex(".*\\." + hll_suffix + "$");
          std::ifstream myfile;
          
          if (is_regular_file(i.path()) &&
              std::regex_match(i.path().filename().string(), hll_regex)) {
            myfile.open(filename, std::ios::in | std::ios::binary);
            time_t temptime=0;
            myfile.read((char*)&temptime, sizeof(temptime));
            v.push_back(std::make_pair(i.path(), temptime));
          }
        }
        if (v.size() > d_maxfiles) {
          std::sort(v.begin(), v.end(), [](const std::pair<path, time_t>& a, const std::pair<path, time_t>& b) {
              return a.second < b.second;});
          for (int i=0; i<v.size()-d_maxfiles; ++i) {
            path f = v[i].first;
            remove(f);
          }
        }
        return true;
      }
    }
    catch (const filesystem_error& e) {
      g_log<<Logger::Warning<<"NODDB pruneCacheFiles: error " << e.what() << endl;
    }
  }
  return false;  
}
