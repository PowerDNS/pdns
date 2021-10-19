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
#include "bpf-filter.hh"

#ifdef HAVE_EBPF

#include <sys/syscall.h>
#include <linux/bpf.h>

#include "ext/libbpf/libbpf.h"

#include "misc.hh"

static __u64 ptr_to_u64(void *ptr)
{
  return (__u64) (unsigned long) ptr;
}

int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
                   int max_entries)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_type = map_type;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;
  return syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

int bpf_update_elem(int fd, void *key, void *value, unsigned long long flags)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);
  attr.value = ptr_to_u64(value);
  attr.flags = flags;
  return syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_lookup_elem(int fd, void *key, void *value)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);
  attr.value = ptr_to_u64(value);
  return syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_delete_elem(int fd, void *key)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);
  return syscall(SYS_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

int bpf_get_next_key(int fd, void *key, void *next_key)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = fd;
  attr.key = ptr_to_u64(key);
  attr.next_key = ptr_to_u64(next_key);
  return syscall(SYS_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

int bpf_prog_load(enum bpf_prog_type prog_type,
		  const struct bpf_insn *insns, int prog_len,
		  const char *license, int kern_version)
{
  char log_buf[65535];
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.prog_type = prog_type;
  attr.insns = ptr_to_u64((void *) insns);
  attr.insn_cnt = prog_len / sizeof(struct bpf_insn);
  attr.license = ptr_to_u64((void *) license);
  attr.log_buf = ptr_to_u64(log_buf);
  attr.log_size = sizeof(log_buf);
  attr.log_level = 1;
  /* assign one field outside of struct init to make sure any
   * padding is zero initialized
   */
  attr.kern_version = kern_version;

  long res = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
  if (res == -1) {
    if (errno == ENOSPC) {
      /* not enough space in the log buffer */
      attr.log_level = 0;
      attr.log_size = 0;
      attr.log_buf = ptr_to_u64(nullptr);
      res = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
      if (res != -1) {
        return res;
      }
    }
    throw std::runtime_error("Error loading BPF program: (" + stringerror() + "):\n" + std::string(log_buf));
  }
  return res;
}

struct KeyV6
{
  uint8_t src[16];
};

struct QNameKey
{
  uint8_t qname[255];
};

struct QNameValue
{
  uint64_t counter;
  uint16_t qtype;
};

BPFFilter::BPFFilter(uint32_t maxV4Addresses, uint32_t maxV6Addresses, uint32_t maxQNames): d_maps(Maps()), d_maxV4(maxV4Addresses), d_maxV6(maxV6Addresses), d_maxQNames(maxQNames)
{
  auto maps = d_maps.lock();
  maps->d_v4map = FDWrapper(bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint64_t), (int) maxV4Addresses));
  if (maps->d_v4map.getHandle() == -1) {
    throw std::runtime_error("Error creating a BPF v4 map of size " + std::to_string(maxV4Addresses) + ": " + stringerror());
  }

  maps->d_v6map = FDWrapper(bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(struct KeyV6), sizeof(uint64_t), (int) maxV6Addresses));
  if (maps->d_v6map.getHandle() == -1) {
    throw std::runtime_error("Error creating a BPF v6 map of size " + std::to_string(maxV6Addresses) + ": " + stringerror());
  }

  maps->d_qnamemap = FDWrapper(bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(struct QNameKey), sizeof(struct QNameValue), (int) maxQNames));
  if (maps->d_qnamemap.getHandle() == -1) {
    throw std::runtime_error("Error creating a BPF qname map of size " + std::to_string(maxQNames) + ": " + stringerror());
  }

  maps->d_filtermap = FDWrapper(bpf_create_map(BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1));
  if (maps->d_filtermap.getHandle() == -1) {
    throw std::runtime_error("Error creating a BPF program map of size 1: " + stringerror());
  }

  struct bpf_insn main_filter[] = {
#include "bpf-filter.main.ebpf"
  };

  d_mainfilter = FDWrapper(bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
                                         main_filter,
                                         sizeof(main_filter),
                                         "GPL",
                                         0));
  if (d_mainfilter.getHandle() == -1) {
    throw std::runtime_error("Error loading BPF main filter: " + stringerror());
  }

  struct bpf_insn qname_filter[] = {
#include "bpf-filter.qname.ebpf"
  };

  d_qnamefilter = FDWrapper(bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
                                          qname_filter,
                                          sizeof(qname_filter),
                                          "GPL",
                                          0));
  if (d_qnamefilter.getHandle() == -1) {
    throw std::runtime_error("Error loading BPF qname filter: " + stringerror());
  }

  uint32_t key = 0;
  int qnamefd = d_qnamefilter.getHandle();
  int res = bpf_update_elem(maps->d_filtermap.getHandle(), &key, &qnamefd, BPF_ANY);
  if (res != 0) {
    throw std::runtime_error("Error updating BPF filters map: " + stringerror());
  }
}

void BPFFilter::addSocket(int sock)
{
  int fd = d_mainfilter.getHandle();
  int res = setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &fd, sizeof(fd));

  if (res != 0) {
    throw std::runtime_error("Error attaching BPF filter to this socket: " + stringerror());
  }
}

void BPFFilter::removeSocket(int sock)
{
  int fd = d_mainfilter.getHandle();
  int res = setsockopt(sock, SOL_SOCKET, SO_DETACH_BPF, &fd, sizeof(fd));

  if (res != 0) {
    throw std::runtime_error("Error detaching BPF filter from this socket: " + stringerror());
  }
}

void BPFFilter::block(const ComboAddress& addr)
{
  uint64_t counter = 0;
  int res = 0;
  if (addr.isIPv4()) {
    uint32_t key = htonl(addr.sin4.sin_addr.s_addr);
    auto maps = d_maps.lock();
    if (maps->d_v4Count >= d_maxV4) {
      throw std::runtime_error("Table full when trying to block " + addr.toString());
    }

    res = bpf_lookup_elem(maps->d_v4map.getHandle(), &key, &counter);
    if (res != -1) {
      throw std::runtime_error("Trying to block an already blocked address: " + addr.toString());
    }

    res = bpf_update_elem(maps->d_v4map.getHandle(), &key, &counter, BPF_NOEXIST);
    if (res == 0) {
      maps->d_v4Count++;
    }
  }
  else if (addr.isIPv6()) {
    uint8_t key[16];
    static_assert(sizeof(addr.sin6.sin6_addr.s6_addr) == sizeof(key), "POSIX mandates s6_addr to be an array of 16 uint8_t");
    for (size_t idx = 0; idx < sizeof(key); idx++) {
      key[idx] = addr.sin6.sin6_addr.s6_addr[idx];
    }

    auto maps = d_maps.lock();
    if (maps->d_v6Count >= d_maxV6) {
      throw std::runtime_error("Table full when trying to block " + addr.toString());
    }

    res = bpf_lookup_elem(maps->d_v6map.getHandle(), &key, &counter);
    if (res != -1) {
      throw std::runtime_error("Trying to block an already blocked address: " + addr.toString());
    }

    res = bpf_update_elem(maps->d_v6map.getHandle(), key, &counter, BPF_NOEXIST);
    if (res == 0) {
      maps->d_v6Count++;
    }
  }

  if (res != 0) {
    throw std::runtime_error("Error adding blocked address " + addr.toString() + ": " + stringerror());
  }
}

void BPFFilter::unblock(const ComboAddress& addr)
{
  int res = 0;
  if (addr.isIPv4()) {
    uint32_t key = htonl(addr.sin4.sin_addr.s_addr);
    auto maps = d_maps.lock();
    res = bpf_delete_elem(maps->d_v4map.getHandle(), &key);
    if (res == 0) {
      maps->d_v4Count--;
    }
  }
  else if (addr.isIPv6()) {
    uint8_t key[16];
    static_assert(sizeof(addr.sin6.sin6_addr.s6_addr) == sizeof(key), "POSIX mandates s6_addr to be an array of 16 uint8_t");
    for (size_t idx = 0; idx < sizeof(key); idx++) {
      key[idx] = addr.sin6.sin6_addr.s6_addr[idx];
    }

    auto maps = d_maps.lock();
    res = bpf_delete_elem(maps->d_v6map.getHandle(), key);
    if (res == 0) {
      maps->d_v6Count--;
    }
  }

  if (res != 0) {
    throw std::runtime_error("Error removing blocked address " + addr.toString() + ": " + stringerror());
  }
}

void BPFFilter::block(const DNSName& qname, uint16_t qtype)
{
  struct QNameKey key;
  struct QNameValue value;
  memset(&key, 0, sizeof(key));
  memset(&value, 0, sizeof(value));
  value.counter = 0;
  value.qtype = qtype;

  std::string keyStr = qname.toDNSStringLC();
  if (keyStr.size() > sizeof(key.qname)) {
    throw std::runtime_error("Invalid QName to block " + qname.toLogString());
  }
  memcpy(key.qname, keyStr.c_str(), keyStr.size());

  {
    auto maps = d_maps.lock();
    if (maps->d_qNamesCount >= d_maxQNames) {
      throw std::runtime_error("Table full when trying to block " + qname.toLogString());
    }

    int res = bpf_lookup_elem(maps->d_qnamemap.getHandle(), &key, &value);
    if (res != -1) {
      throw std::runtime_error("Trying to block an already blocked qname: " + qname.toLogString());
    }

    res = bpf_update_elem(maps->d_qnamemap.getHandle(), &key, &value, BPF_NOEXIST);
    if (res == 0) {
      maps->d_qNamesCount++;
    }

    if (res != 0) {
      throw std::runtime_error("Error adding blocked qname " + qname.toLogString() + ": " + stringerror());
    }
  }
}

void BPFFilter::unblock(const DNSName& qname, uint16_t qtype)
{
  struct QNameKey key = { { 0 } };
  std::string keyStr = qname.toDNSStringLC();
  (void) qtype;

  if (keyStr.size() > sizeof(key.qname)) {
    throw std::runtime_error("Invalid QName to block " + qname.toLogString());
  }
  memcpy(key.qname, keyStr.c_str(), keyStr.size());

  {
    auto maps = d_maps.lock();
    int res = bpf_delete_elem(maps->d_qnamemap.getHandle(), &key);
    if (res == 0) {
      maps->d_qNamesCount--;
    }
    else {
      throw std::runtime_error("Error removing qname address " + qname.toLogString() + ": " + stringerror());
    }
  }
}

std::vector<std::pair<ComboAddress, uint64_t> > BPFFilter::getAddrStats()
{
  std::vector<std::pair<ComboAddress, uint64_t> > result;
  {
    auto maps = d_maps.lock();
    result.reserve(maps->d_v4Count + maps->d_v6Count);
  }

  sockaddr_in v4Addr;
  memset(&v4Addr, 0, sizeof(v4Addr));
  v4Addr.sin_family = AF_INET;

  uint32_t v4Key = 0;
  uint32_t nextV4Key;
  uint64_t value;

  uint8_t v6Key[16];
  uint8_t nextV6Key[16];
  sockaddr_in6 v6Addr;
  memset(&v6Addr, 0, sizeof(v6Addr));
  v6Addr.sin6_family = AF_INET6;

  static_assert(sizeof(v6Addr.sin6_addr.s6_addr) == sizeof(v6Key), "POSIX mandates s6_addr to be an array of 16 uint8_t");
  memset(&v6Key, 0, sizeof(v6Key));

  auto maps = d_maps.lock();
  int res = bpf_get_next_key(maps->d_v4map.getHandle(), &v4Key, &nextV4Key);

  while (res == 0) {
    v4Key = nextV4Key;
    if (bpf_lookup_elem(maps->d_v4map.getHandle(), &v4Key, &value) == 0) {
      v4Addr.sin_addr.s_addr = ntohl(v4Key);
      result.emplace_back(ComboAddress(&v4Addr), value);
    }

    res = bpf_get_next_key(maps->d_v4map.getHandle(), &v4Key, &nextV4Key);
  }

  res = bpf_get_next_key(maps->d_v6map.getHandle(), &v6Key, &nextV6Key);

  while (res == 0) {
    if (bpf_lookup_elem(maps->d_v6map.getHandle(), &nextV6Key, &value) == 0) {
      memcpy(&v6Addr.sin6_addr.s6_addr, &nextV6Key, sizeof(nextV6Key));

      result.emplace_back(ComboAddress(&v6Addr), value);
    }

    res = bpf_get_next_key(maps->d_v6map.getHandle(), &nextV6Key, &nextV6Key);
  }
  return result;
}

std::vector<std::tuple<DNSName, uint16_t, uint64_t> > BPFFilter::getQNameStats()
{
  std::vector<std::tuple<DNSName, uint16_t, uint64_t> > result;

  struct QNameKey key = { { 0 } };
  struct QNameKey nextKey = { { 0 } };
  struct QNameValue value;

  auto maps = d_maps.lock();
  result.reserve(maps->d_qNamesCount);
  int res = bpf_get_next_key(maps->d_qnamemap.getHandle(), &key, &nextKey);

  while (res == 0) {
    if (bpf_lookup_elem(maps->d_qnamemap.getHandle(), &nextKey, &value) == 0) {
      nextKey.qname[sizeof(nextKey.qname) - 1 ] = '\0';
      result.push_back(std::make_tuple(DNSName((const char*) nextKey.qname, sizeof(nextKey.qname), 0, false), value.qtype, value.counter));
    }

    res = bpf_get_next_key(maps->d_qnamemap.getHandle(), &nextKey, &nextKey);
  }
  return result;
}

uint64_t BPFFilter::getHits(const ComboAddress& requestor)
{
  uint64_t counter = 0;
  if (requestor.isIPv4()) {
    uint32_t key = htonl(requestor.sin4.sin_addr.s_addr);

    auto maps = d_maps.lock();
    int res = bpf_lookup_elem(maps->d_v4map.getHandle(), &key, &counter);
    if (res == 0) {
      return counter;
    }
  }
  else if (requestor.isIPv6()) {
    uint8_t key[16];
    static_assert(sizeof(requestor.sin6.sin6_addr.s6_addr) == sizeof(key), "POSIX mandates s6_addr to be an array of 16 uint8_t");
    for (size_t idx = 0; idx < sizeof(key); idx++) {
      key[idx] = requestor.sin6.sin6_addr.s6_addr[idx];
    }

    auto maps = d_maps.lock();
    int res = bpf_lookup_elem(maps->d_v6map.getHandle(), &key, &counter);
    if (res == 0) {
      return counter;
    }
  }

  return 0;
}

#else

BPFFilter::BPFFilter(uint32_t maxV4Addresses, uint32_t maxV6Addresses, uint32_t maxQNames)
{
  (void) maxV4Addresses;
  (void) maxV6Addresses;
  (void) maxQNames;
}

void BPFFilter::addSocket(int sock)
{
  (void) sock;
  throw std::runtime_error("eBPF support not enabled");
}

void BPFFilter::removeSocket(int sock)
{
  (void) sock;
  throw std::runtime_error("eBPF support not enabled");
}

void BPFFilter::block(const ComboAddress& addr)
{
  (void) addr;
  throw std::runtime_error("eBPF support not enabled");
}

void BPFFilter::unblock(const ComboAddress& addr)
{
  (void) addr;
  throw std::runtime_error("eBPF support not enabled");
}

void BPFFilter::block(const DNSName& qname, uint16_t qtype)
{
  (void) qname;
  (void) qtype;
  throw std::runtime_error("eBPF support not enabled");
}

void BPFFilter::unblock(const DNSName& qname, uint16_t qtype)
{
  (void) qname;
  (void) qtype;
  throw std::runtime_error("eBPF support not enabled");
}

std::vector<std::pair<ComboAddress, uint64_t> > BPFFilter::getAddrStats()
{
  std::vector<std::pair<ComboAddress, uint64_t> > result;
  return result;
}

std::vector<std::tuple<DNSName, uint16_t, uint64_t> > BPFFilter::getQNameStats()
{
  std::vector<std::tuple<DNSName, uint16_t, uint64_t> > result;
  return result;
}

uint64_t BPFFilter::getHits(const ComboAddress& requestor)
{
  (void) requestor;
  return 0;
}
#endif /* HAVE_EBPF */
