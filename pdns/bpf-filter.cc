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

int bpf_pin_map(int fd, const std::string& path)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.bpf_fd = fd;
  attr.pathname = ptr_to_u64(const_cast<char*>(path.c_str()));
  return syscall(SYS_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
}

int bpf_load_pinned_map(const std::string& path)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.pathname = ptr_to_u64(const_cast<char*>(path.c_str()));
  return syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

void bpf_check_map_sizes(int fd, uint32_t expectedKeySize, uint32_t expectedValueSize)
{
  struct bpf_map_info info;
  uint32_t info_len = sizeof(info);
  memset(&info, 0, sizeof(info));

  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.info.bpf_fd = fd;
  attr.info.info_len = info_len;
  attr.info.info = ptr_to_u64(&info);

  int err = syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
  if (err != 0) {
    throw std::runtime_error("Error checking the size of eBPF map: " + stringerror());
  }
  if (info_len != sizeof(info)) {
    throw std::runtime_error("Error checking the size of eBPF map: invalid info size returned");
  }
  if (info.key_size != expectedKeySize) {
    throw std::runtime_error("Error checking the size of eBPF map: key size mismatch (" + std::to_string(info.key_size) + " VS " + std::to_string(expectedKeySize) + ")");
  }
  if (info.value_size != expectedValueSize) {
    throw std::runtime_error("Error checking the size of eBPF map: value size mismatch (" + std::to_string(info.value_size) + " VS " + std::to_string(expectedValueSize) + ")");
  }

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

struct QNameAndQTypeKey
{
  uint8_t qname[255];
  uint16_t qtype;
};

struct QNameValue
{
  uint64_t counter{0};
  uint16_t qtype{0};
};

struct CounterAndActionValue
{
  uint64_t counter{0};
  BPFFilter::MatchAction action{BPFFilter::MatchAction::Pass};
};

BPFFilter::Map::Map(const BPFFilter::MapConfiguration& config, BPFFilter::MapFormat format): d_config(config)
{
  if (d_config.d_type == BPFFilter::MapType::Filters) {
    /* special case, this is a map of eBPF programs */
    d_fd = FDWrapper(bpf_create_map(BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), d_config.d_maxItems));
    if (d_fd.getHandle() == -1) {
      throw std::runtime_error("Error creating a BPF program map of size " + std::to_string(d_config.d_maxItems) + ": " + stringerror());
    }
  }
  else {
    int keySize = 0;
    int valueSize = 0;
    if (format == MapFormat::Legacy) {
      switch (d_config.d_type) {
      case MapType::IPv4:
        keySize = sizeof(uint32_t);
        valueSize = sizeof(uint64_t);
        break;
      case MapType::IPv6:
        keySize = sizeof(KeyV6);
        valueSize = sizeof(uint64_t);
        break;
      case MapType::QNames:
        keySize = sizeof(QNameKey);
        valueSize = sizeof(QNameValue);
        break;
      default:
        throw std::runtime_error("Unsupported eBPF map type: " + std::to_string(static_cast<uint8_t>(d_config.d_type)));
      }
    }
    else {
      switch (d_config.d_type) {
      case MapType::IPv4:
        keySize = sizeof(uint32_t);
        valueSize = sizeof(CounterAndActionValue);
        break;
      case MapType::IPv6:
        keySize = sizeof(KeyV6);
        valueSize = sizeof(CounterAndActionValue);
        break;
      case MapType::QNames:
        keySize = sizeof(QNameAndQTypeKey);
        valueSize = sizeof(CounterAndActionValue);
        break;
      default:
        throw std::runtime_error("Unsupported eBPF map type: " + std::to_string(static_cast<uint8_t>(d_config.d_type)));
      }
    }

    if (!d_config.d_pinnedPath.empty()) {
      /* try to load */
      d_fd = FDWrapper(bpf_load_pinned_map(d_config.d_pinnedPath));
      if (d_fd.getHandle() != -1) {
        /* sanity checks: key and value size */
        bpf_check_map_sizes(d_fd.getHandle(), keySize, valueSize);

        if (d_config.d_type == MapType::IPv4) {
          uint32_t key = 0;
          int res = bpf_get_next_key(d_fd.getHandle(), &key, &key);
          while (res == 0) {
            ++d_count;
            res = bpf_get_next_key(d_fd.getHandle(), &key, &key);
          }
        }
        else if (d_config.d_type == MapType::IPv6) {
          KeyV6 key;
          memset(&key, 0, sizeof(key));
          int res = bpf_get_next_key(d_fd.getHandle(), &key, &key);
          while (res == 0) {
            ++d_count;
            res = bpf_get_next_key(d_fd.getHandle(), &key, &key);
          }
        }
        else if (d_config.d_type == MapType::QNames) {
          if (format == MapFormat::Legacy) {
            QNameKey key;
            memset(&key, 0, sizeof(key));
            int res = bpf_get_next_key(d_fd.getHandle(), &key, &key);
            while (res == 0) {
              ++d_count;
              res = bpf_get_next_key(d_fd.getHandle(), &key, &key);
            }
          }
          else {
            QNameAndQTypeKey key;
            memset(&key, 0, sizeof(key));
            int res = bpf_get_next_key(d_fd.getHandle(), &key, &key);
            while (res == 0) {
              ++d_count;
              res = bpf_get_next_key(d_fd.getHandle(), &key, &key);
            }
          }
        }
      }
    }

    if (d_fd.getHandle() == -1) {
      d_fd = FDWrapper(bpf_create_map(BPF_MAP_TYPE_HASH, keySize, valueSize, static_cast<int>(d_config.d_maxItems)));
      if (d_fd.getHandle() == -1) {
        throw std::runtime_error("Error creating a BPF map of size " + std::to_string(d_config.d_maxItems) + ": " + stringerror());
      }

      if (!d_config.d_pinnedPath.empty()) {
        if (bpf_pin_map(d_fd.getHandle(), d_config.d_pinnedPath) != 0) {
          throw std::runtime_error("Unable to pin map to path '" + d_config.d_pinnedPath + "': " + stringerror());
        }
      }
    }
  }
}

static FDWrapper loadProgram(const struct bpf_insn* filter, size_t filterSize)
{
  auto fd = FDWrapper(bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
                                    filter,
                                    filterSize,
                                    "GPL",
                                    0));
  if (fd.getHandle() == -1) {
    throw std::runtime_error("error loading BPF filter: " + stringerror());
  }
  return fd;
}


BPFFilter::BPFFilter(const BPFFilter::MapConfiguration& v4, const BPFFilter::MapConfiguration& v6, const BPFFilter::MapConfiguration& qnames, BPFFilter::MapFormat format, bool external): d_mapFormat(format), d_external(external)
{
  if (d_mapFormat != BPFFilter::MapFormat::Legacy && !d_external) {
    throw std::runtime_error("Unsupported eBPF map format, the current internal implemenation only supports the legacy format");
  }

  auto maps = d_maps.lock();

  maps->d_v4 = BPFFilter::Map(v4, d_mapFormat);
  maps->d_v6 = BPFFilter::Map(v6, d_mapFormat);
  maps->d_qnames = BPFFilter::Map(qnames, d_mapFormat);
  if (!external) {
    BPFFilter::MapConfiguration filters;
    filters.d_maxItems = 1;
    filters.d_type = BPFFilter::MapType::Filters;
    maps->d_filters = BPFFilter::Map(filters, d_mapFormat);

    const struct bpf_insn main_filter[] = {
#include "bpf-filter.main.ebpf"
    };

    const struct bpf_insn qname_filter[] = {
#include "bpf-filter.qname.ebpf"
    };

    try {
      d_mainfilter = loadProgram(main_filter,
                                 sizeof(main_filter));
    }
    catch (const std::exception& e) {
      throw std::runtime_error("Error load the main eBPF filter: " + std::string(e.what()));
    }

    try {
      d_qnamefilter = loadProgram(qname_filter,
                                  sizeof(qname_filter));
    }
    catch (const std::exception& e) {
      throw std::runtime_error("Error load the qname eBPF filter: " + std::string(e.what()));
    }

    uint32_t key = 0;
    int qnamefd = d_qnamefilter.getHandle();
    int res = bpf_update_elem(maps->d_filters.d_fd.getHandle(), &key, &qnamefd, BPF_ANY);
    if (res != 0) {
      throw std::runtime_error("Error updating BPF filters map: " + stringerror());
    }
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

void BPFFilter::block(const ComboAddress& addr, BPFFilter::MatchAction action)
{
  CounterAndActionValue value;
  value.counter = 0;
  value.action = action;

  int res = 0;
  if (addr.isIPv4()) {
    uint32_t key = htonl(addr.sin4.sin_addr.s_addr);
    auto maps = d_maps.lock();
    auto& map = maps->d_v4;
    if (map.d_count >= map.d_config.d_maxItems) {
      throw std::runtime_error("Table full when trying to block " + addr.toString());
    }

    res = bpf_lookup_elem(map.d_fd.getHandle(), &key, &value);
    if (res != -1) {
      throw std::runtime_error("Trying to block an already blocked address: " + addr.toString());
    }

    res = bpf_update_elem(map.d_fd.getHandle(), &key, &value, BPF_NOEXIST);
    if (res == 0) {
      ++map.d_count;
    }
  }
  else if (addr.isIPv6()) {
    uint8_t key[16];
    static_assert(sizeof(addr.sin6.sin6_addr.s6_addr) == sizeof(key), "POSIX mandates s6_addr to be an array of 16 uint8_t");
    for (size_t idx = 0; idx < sizeof(key); idx++) {
      key[idx] = addr.sin6.sin6_addr.s6_addr[idx];
    }

    auto maps = d_maps.lock();
    auto& map = maps->d_v6;
    if (map.d_count >= map.d_config.d_maxItems) {
      throw std::runtime_error("Table full when trying to block " + addr.toString());
    }

    res = bpf_lookup_elem(map.d_fd.getHandle(), &key, &value);
    if (res != -1) {
      throw std::runtime_error("Trying to block an already blocked address: " + addr.toString());
    }

    res = bpf_update_elem(map.d_fd.getHandle(), key, &value, BPF_NOEXIST);
    if (res == 0) {
      map.d_count++;
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
    auto& map = maps->d_v4;
    res = bpf_delete_elem(map.d_fd.getHandle(), &key);
    if (res == 0) {
      --map.d_count;
    }
  }
  else if (addr.isIPv6()) {
    uint8_t key[16];
    static_assert(sizeof(addr.sin6.sin6_addr.s6_addr) == sizeof(key), "POSIX mandates s6_addr to be an array of 16 uint8_t");
    for (size_t idx = 0; idx < sizeof(key); idx++) {
      key[idx] = addr.sin6.sin6_addr.s6_addr[idx];
    }

    auto maps = d_maps.lock();
    auto& map = maps->d_v6;
    res = bpf_delete_elem(map.d_fd.getHandle(), key);
    if (res == 0) {
      --map.d_count;
    }
  }

  if (res != 0) {
    throw std::runtime_error("Error removing blocked address " + addr.toString() + ": " + stringerror());
  }
}

void BPFFilter::block(const DNSName& qname, BPFFilter::MatchAction action, uint16_t qtype)
{
  CounterAndActionValue cadvalue;
  QNameValue qvalue;
  void* value = nullptr;

  if (d_external) {
    memset(&cadvalue, 0, sizeof(cadvalue));
    cadvalue.counter = 0;
    cadvalue.action = action;
    value = &cadvalue;
  }
  else {
    memset(&qvalue, 0, sizeof(qvalue));
    qvalue.counter = 0;
    qvalue.qtype = qtype;
    value = &qvalue;
  }

  QNameAndQTypeKey key;
  memset(&key, 0, sizeof(key));

  std::string keyStr = qname.toDNSStringLC();
  if (keyStr.size() > sizeof(key.qname)) {
    throw std::runtime_error("Invalid QName to block " + qname.toLogString());
  }
  memcpy(key.qname, keyStr.c_str(), keyStr.size());
  key.qtype = qtype;

  {
    auto maps = d_maps.lock();
    auto& map = maps->d_qnames;
    if (map.d_count >= map.d_config.d_maxItems) {
      throw std::runtime_error("Table full when trying to block " + qname.toLogString());
    }

    int res = bpf_lookup_elem(map.d_fd.getHandle(), &key, &value);
    if (res != -1) {
      throw std::runtime_error("Trying to block an already blocked qname: " + qname.toLogString());
    }

    res = bpf_update_elem(map.d_fd.getHandle(), &key, &value, BPF_NOEXIST);
    if (res == 0) {
      ++map.d_count;
    }

    if (res != 0) {
      throw std::runtime_error("Error adding blocked qname " + qname.toLogString() + ": " + stringerror());
    }
  }
}

void BPFFilter::unblock(const DNSName& qname, uint16_t qtype)
{
  QNameAndQTypeKey key;
  memset(&key, 0, sizeof(key));
  std::string keyStr = qname.toDNSStringLC();

  if (keyStr.size() > sizeof(key.qname)) {
    throw std::runtime_error("Invalid QName to block " + qname.toLogString());
  }
  memcpy(key.qname, keyStr.c_str(), keyStr.size());
  key.qtype = qtype;

  {
    auto maps = d_maps.lock();
    auto& map = maps->d_qnames;
    int res = bpf_delete_elem(map.d_fd.getHandle(), &key);
    if (res == 0) {
      --map.d_count;
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
    result.reserve(maps->d_v4.d_count + maps->d_v6.d_count);
  }

  sockaddr_in v4Addr;
  memset(&v4Addr, 0, sizeof(v4Addr));
  v4Addr.sin_family = AF_INET;

  uint32_t v4Key = 0;
  uint32_t nextV4Key;
  CounterAndActionValue value;

  uint8_t v6Key[16];
  uint8_t nextV6Key[16];
  sockaddr_in6 v6Addr;
  memset(&v6Addr, 0, sizeof(v6Addr));
  v6Addr.sin6_family = AF_INET6;

  static_assert(sizeof(v6Addr.sin6_addr.s6_addr) == sizeof(v6Key), "POSIX mandates s6_addr to be an array of 16 uint8_t");
  memset(&v6Key, 0, sizeof(v6Key));

  auto maps = d_maps.lock();

  {
    auto& map = maps->d_v4;
    int res = bpf_get_next_key(map.d_fd.getHandle(), &v4Key, &nextV4Key);

    while (res == 0) {
      v4Key = nextV4Key;
      if (bpf_lookup_elem(map.d_fd.getHandle(), &v4Key, &value) == 0) {
      v4Addr.sin_addr.s_addr = ntohl(v4Key);
      result.emplace_back(ComboAddress(&v4Addr), value.counter);
      }

      res = bpf_get_next_key(map.d_fd.getHandle(), &v4Key, &nextV4Key);
    }
  }

  {
    auto& map = maps->d_v6;
    int res = bpf_get_next_key(map.d_fd.getHandle(), &v6Key, &nextV6Key);

    while (res == 0) {
      if (bpf_lookup_elem(map.d_fd.getHandle(), &nextV6Key, &value) == 0) {
        memcpy(&v6Addr.sin6_addr.s6_addr, &nextV6Key, sizeof(nextV6Key));

        result.emplace_back(ComboAddress(&v6Addr), value.counter);
      }

      res = bpf_get_next_key(map.d_fd.getHandle(), &nextV6Key, &nextV6Key);
    }
  }

  return result;
}

std::vector<std::tuple<DNSName, uint16_t, uint64_t> > BPFFilter::getQNameStats()
{
  std::vector<std::tuple<DNSName, uint16_t, uint64_t> > result;

  if (d_mapFormat == MapFormat::Legacy) {
    QNameKey key = { { 0 } };
    QNameKey nextKey = { { 0 } };
    QNameValue value;

    auto maps = d_maps.lock();
    auto& map = maps->d_qnames;
    result.reserve(map.d_count);
    int res = bpf_get_next_key(map.d_fd.getHandle(), &key, &nextKey);

    while (res == 0) {
      if (bpf_lookup_elem(map.d_fd.getHandle(), &nextKey, &value) == 0) {
        nextKey.qname[sizeof(nextKey.qname) - 1 ] = '\0';
        result.push_back(std::make_tuple(DNSName(reinterpret_cast<const char*>(nextKey.qname), sizeof(nextKey.qname), 0, false), value.qtype, value.counter));
      }

      res = bpf_get_next_key(map.d_fd.getHandle(), &nextKey, &nextKey);
    }
  }
  else {
    QNameAndQTypeKey key;
    QNameAndQTypeKey nextKey;
    memset(&key, 0, sizeof(key));
    memset(&nextKey, 0, sizeof(nextKey));
    CounterAndActionValue value;

    auto maps = d_maps.lock();
    auto& map = maps->d_qnames;
    result.reserve(map.d_count);
    int res = bpf_get_next_key(map.d_fd.getHandle(), &key, &nextKey);

    while (res == 0) {
      if (bpf_lookup_elem(map.d_fd.getHandle(), &nextKey, &value) == 0) {
        nextKey.qname[sizeof(nextKey.qname) - 1 ] = '\0';
        result.push_back(std::make_tuple(DNSName(reinterpret_cast<const char*>(nextKey.qname), sizeof(nextKey.qname), 0, false), key.qtype, value.counter));
      }

      res = bpf_get_next_key(map.d_fd.getHandle(), &nextKey, &nextKey);
    }
  }

  return result;
}

uint64_t BPFFilter::getHits(const ComboAddress& requestor)
{
  CounterAndActionValue counter;

  if (requestor.isIPv4()) {
    uint32_t key = htonl(requestor.sin4.sin_addr.s_addr);

    auto maps = d_maps.lock();
    auto& map = maps->d_v4;
    int res = bpf_lookup_elem(map.d_fd.getHandle(), &key, &counter);
    if (res == 0) {
      return counter.counter;
    }
  }
  else if (requestor.isIPv6()) {
    uint8_t key[16];
    static_assert(sizeof(requestor.sin6.sin6_addr.s6_addr) == sizeof(key), "POSIX mandates s6_addr to be an array of 16 uint8_t");
    for (size_t idx = 0; idx < sizeof(key); idx++) {
      key[idx] = requestor.sin6.sin6_addr.s6_addr[idx];
    }

    auto maps = d_maps.lock();
    auto& map = maps->d_v6;
    int res = bpf_lookup_elem(map.d_fd.getHandle(), &key, &counter);
    if (res == 0) {
      return counter.counter;
    }
  }

  return 0;
}

#else

BPFFilter::BPFFilter(const BPFFilter::MapConfiguration&, const BPFFilter::MapConfiguration&, const BPFFilter::MapConfiguration&, BPFFilter::MapFormat, bool)
{
}

void BPFFilter::addSocket(int)
{
  throw std::runtime_error("eBPF support not enabled");
}

void BPFFilter::removeSocket(int)
{
  throw std::runtime_error("eBPF support not enabled");
}

void BPFFilter::block(const ComboAddress&, BPFFilter::MatchAction)
{
  throw std::runtime_error("eBPF support not enabled");
}

void BPFFilter::unblock(const ComboAddress&)
{
  throw std::runtime_error("eBPF support not enabled");
}

void BPFFilter::block(const DNSName&, BPFFilter::MatchAction, uint16_t)
{
  throw std::runtime_error("eBPF support not enabled");
}

void BPFFilter::unblock(const DNSName&, uint16_t)
{
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

uint64_t BPFFilter::getHits(const ComboAddress&)
{
  return 0;
}
#endif /* HAVE_EBPF */

bool BPFFilter::supportsMatchAction(MatchAction action) const
{
#ifdef HAVE_EBPF
  if (action == BPFFilter::MatchAction::Drop) {
    return true;
  }
  return d_mapFormat == BPFFilter::MapFormat::WithActions;
#endif /* HAVE_EBPF */
  return false;
}

bool BPFFilter::isExternal() const
{
#ifdef HAVE_EBPF
  return d_external;
#endif /* HAVE_EBPF */
  return false;
}
