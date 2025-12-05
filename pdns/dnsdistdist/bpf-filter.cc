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
#include "iputils.hh"
#include "dolog.hh"

#ifdef HAVE_EBPF

#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/bpf.h>

#include "ext/libbpf/libbpf.h"

#include "misc.hh"

static __u64 ptr_to_u64(const void* ptr)
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
  return (__u64)(unsigned long)ptr;
}

/* these can be static as they are not declared in libbpf.h: */
static int bpf_pin_map(int descriptor, const std::string& path)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.bpf_fd = descriptor;
  attr.pathname = ptr_to_u64(path.c_str());
  return syscall(SYS_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
}

static int bpf_load_pinned_map(const std::string& path)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.pathname = ptr_to_u64(path.c_str());
  return syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static void bpf_check_map_sizes(int descriptor, uint32_t expectedKeySize, uint32_t expectedValueSize)
{
  struct bpf_map_info info;
  uint32_t info_len = sizeof(info);
  memset(&info, 0, sizeof(info));

  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.info.bpf_fd = descriptor;
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

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
                          int max_entries, int map_flags)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_type = map_type;
  attr.key_size = key_size;
  attr.value_size = value_size;
  attr.max_entries = max_entries;
  attr.map_flags = map_flags;
  return syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_update_elem(int descriptor, void* key, void* value, unsigned long long flags)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = descriptor;
  attr.key = ptr_to_u64(key);
  attr.value = ptr_to_u64(value);
  attr.flags = flags;
  return syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_lookup_elem(int descriptor, void* key, void* value)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = descriptor;
  attr.key = ptr_to_u64(key);
  attr.value = ptr_to_u64(value);
  return syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int bpf_delete_elem(int descriptor, void* key)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = descriptor;
  attr.key = ptr_to_u64(key);
  return syscall(SYS_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

static int bpf_get_next_key(int descriptor, void* key, void* next_key)
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.map_fd = descriptor;
  attr.key = ptr_to_u64(key);
  attr.next_key = ptr_to_u64(next_key);
  return syscall(SYS_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

static int bpf_prog_load(enum bpf_prog_type prog_type,
                         const struct bpf_insn* insns, size_t prog_len,
                         const char* license, int kern_version)
{
  char log_buf[65535];
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.prog_type = prog_type;
  attr.insns = ptr_to_u64((void*)insns);
  attr.insn_cnt = static_cast<int>(prog_len / sizeof(struct bpf_insn));
  attr.license = ptr_to_u64((void*)license);
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

BPFFilter::Map::Map(BPFFilter::MapConfiguration config, BPFFilter::MapFormat format) :
  d_config(std::move(config))
{
  if (d_config.d_type == BPFFilter::MapType::Filters) {
    /* special case, this is a map of eBPF programs */
    d_fd = FDWrapper(bpf_create_map(BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), d_config.d_maxItems, 0));
    if (d_fd.getHandle() == -1) {
      throw std::runtime_error("Error creating a BPF program map of size " + std::to_string(d_config.d_maxItems) + ": " + stringerror());
    }
  }
  else {
    int keySize = 0;
    int valueSize = 0;
    int flags = 0;
    bpf_map_type type = BPF_MAP_TYPE_HASH;
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
        throw std::runtime_error("Unsupported eBPF map type: " + std::to_string(static_cast<uint8_t>(d_config.d_type)) + " for legacy eBPF, perhaps you are trying to use an external program instead?");
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
      case MapType::CIDR4:
        keySize = sizeof(CIDR4);
        valueSize = sizeof(CounterAndActionValue);
        flags = BPF_F_NO_PREALLOC;
        type = BPF_MAP_TYPE_LPM_TRIE;
        break;
      case MapType::CIDR6:
        keySize = sizeof(CIDR6);
        valueSize = sizeof(CounterAndActionValue);
        flags = BPF_F_NO_PREALLOC;
        type = BPF_MAP_TYPE_LPM_TRIE;
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
        switch (d_config.d_type) {
        case MapType::IPv4: {
          uint32_t key = 0;
          while (bpf_get_next_key(d_fd.getHandle(), &key, &key) == 0) {
            ++d_count;
          }
          break;
        }
        case MapType::IPv6: {
          KeyV6 key;
          memset(&key, 0, sizeof(key));
          while (bpf_get_next_key(d_fd.getHandle(), &key, &key) == 0) {
            ++d_count;
          }
          break;
        }
        case MapType::CIDR4: {
          CIDR4 key;
          memset(&key, 0, sizeof(key));
          while (bpf_get_next_key(d_fd.getHandle(), &key, &key) == 0) {
            ++d_count;
          }
          break;
        }
        case MapType::CIDR6: {
          CIDR6 key;
          memset(&key, 0, sizeof(key));
          while (bpf_get_next_key(d_fd.getHandle(), &key, &key) == 0) {
            ++d_count;
          }
          break;
        }
        case MapType::QNames: {
          if (format == MapFormat::Legacy) {
            QNameKey key;
            memset(&key, 0, sizeof(key));
            while (bpf_get_next_key(d_fd.getHandle(), &key, &key) == 0) {
              ++d_count;
            }
          }
          else {
            QNameAndQTypeKey key;
            memset(&key, 0, sizeof(key));
            while (bpf_get_next_key(d_fd.getHandle(), &key, &key) == 0) {
              ++d_count;
            }
          }
          break;
        }

        default:
          throw std::runtime_error("Unsupported eBPF map type: " + std::to_string(static_cast<uint8_t>(d_config.d_type)));
        }
      }
    }

    if (d_fd.getHandle() == -1) {
      d_fd = FDWrapper(bpf_create_map(type, keySize, valueSize, static_cast<int>(d_config.d_maxItems), flags));
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
  auto descriptor = FDWrapper(bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
                                            filter,
                                            filterSize,
                                            "GPL",
                                            0));
  if (descriptor.getHandle() == -1) {
    throw std::runtime_error("error loading BPF filter: " + stringerror());
  }
  return descriptor;
}

BPFFilter::BPFFilter(std::unordered_map<std::string, MapConfiguration>& configs, BPFFilter::MapFormat format, bool external) :
  d_mapFormat(format), d_external(external)
{
  if (d_mapFormat != BPFFilter::MapFormat::Legacy && !d_external) {
    throw std::runtime_error("Unsupported eBPF map format, the current internal implemenation only supports the legacy format");
  }

  struct rlimit old_limit{};
  if (getrlimit(RLIMIT_MEMLOCK, &old_limit) != 0) {
    throw std::runtime_error("Unable to get memory lock limit: " + stringerror());
  }

  const rlim_t new_limit_size = 1024 * 1024;

  /* Check if the current soft memlock limit is at least the limit */
  if (old_limit.rlim_cur < new_limit_size) {
    SLOG(infolog("The current limit of locked memory (soft: %d, hard: %d) is too low for eBPF, trying to raise it to %d", old_limit.rlim_cur, old_limit.rlim_max, new_limit_size),
         dnsdist::logging::getTopLogger()->info("The current limit of locked memory is too low for eBPF, trying to raise it", "soft", Logging::Loggable(old_limit.rlim_cur), "hard", Logging::Loggable(old_limit.rlim_max), "target", Logging::Loggable(new_limit_size)));

    struct rlimit new_limit{};
    new_limit.rlim_cur = new_limit_size;
    new_limit.rlim_max = new_limit_size;

    if (setrlimit(RLIMIT_MEMLOCK, &new_limit) != 0) {
      SLOG(warnlog("Unable to raise the maximum amount of locked memory for eBPF from %d to %d, consider raising RLIMIT_MEMLOCK or setting LimitMEMLOCK in the systemd unit: %d", old_limit.rlim_cur, new_limit.rlim_cur, stringerror()),
           dnsdist::logging::getTopLogger()->info(Logr::Warning, "Unable to raise the maximum amount of locked memory for eBPF, consider raising RLIMIT_MEMLOCK or setting LimitMEMLOCK in the systemd unit", "current", Logging::Loggable(old_limit.rlim_cur), "target", Logging::Loggable(new_limit_size)));
    }
  }

  auto maps = d_maps.lock();

  maps->d_v4 = BPFFilter::Map(configs["ipv4"], d_mapFormat);
  maps->d_v6 = BPFFilter::Map(configs["ipv6"], d_mapFormat);
  maps->d_qnames = BPFFilter::Map(configs["qnames"], d_mapFormat);

  if (d_mapFormat != BPFFilter::MapFormat::Legacy) {
    maps->d_cidr4 = BPFFilter::Map(configs["cidr4"], d_mapFormat);
    maps->d_cidr6 = BPFFilter::Map(configs["cidr6"], d_mapFormat);
  }

  if (!external) {
    BPFFilter::MapConfiguration filters;
    filters.d_maxItems = 1;
    filters.d_type = BPFFilter::MapType::Filters;
    maps->d_filters = BPFFilter::Map(std::move(filters), d_mapFormat);

    const struct bpf_insn main_filter[] = {
#include "bpf-filter.main.ebpf"
    };

    // ABANDON EVERY HOPE - SCARY CODE STARTS HERE

    // This EBF program is huge, and unfortunately not constant; this causes
    // the compiler to emit a lot of code (and eat a lot of memory to do so).
    // Therefore we include an incomplete but constant version of the program
    // and patch it locally, relying upon the fact that there is only one place
    // to change.
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
    struct bpf_insn qname_filter[] = {
#include "bpf-filter.qname.ebpf"
    };

    // The program above contains
    //   BPF_LD_MAP_FD(BPF_REG_1,0)
    // instead of
    //   BPF_LD_MAP_FD(BPF_REG_1,maps->d_qnames.d_fd.getHandle())
    // and this is the only use of BPF_LD_MAP_FD in the program.
    // We will search for that instruction, relying upon the fact that,
    // in that particular program, there is only one such instruction.
    {
      unsigned int pos{0};
      unsigned int limit{sizeof(qname_filter) / sizeof(struct bpf_insn)};
      for (; pos < limit; ++pos) {
        if (qname_filter[pos].code == (BPF_LD | BPF_DW | BPF_IMM)) { // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
          // We have found our instruction.
          break;
        }
      }
      // BPF_LD_MAP_FP actually is a sequence of two bpf instructions,
      // because it loads a 64-bit value. So it can't be the last
      // instruction either...
      if (pos >= limit - 1) {
        throw std::runtime_error("Assumption in the layout of the eBPF filter program no longer stands");
      }
      auto data = static_cast<__u64>(maps->d_qnames.d_fd.getHandle());
      qname_filter[pos].imm = static_cast<__s32>(data); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
      qname_filter[pos + 1].imm = static_cast<__s32>(data >> 32); // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
    }

    // SCARY CODE ENDS HERE

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
  int descriptor = d_mainfilter.getHandle();
  int res = setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &descriptor, sizeof(descriptor));

  if (res != 0) {
    throw std::runtime_error("Error attaching BPF filter to this socket: " + stringerror());
  }
}

void BPFFilter::removeSocket(int sock)
{
  int descriptor = d_mainfilter.getHandle();
  int res = setsockopt(sock, SOL_SOCKET, SO_DETACH_BPF, &descriptor, sizeof(descriptor));

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

void BPFFilter::addRangeRule(const Netmask& addr, bool force, BPFFilter::MatchAction action)
{
  CounterAndActionValue value;

  int res = 0;
  if (addr.isIPv4()) {
    CIDR4 key(addr);
    auto maps = d_maps.lock();
    auto& map = maps->d_cidr4;
    if (map.d_fd.getHandle() == -1) {
      throw std::runtime_error("Trying to use an unsupported map type, likely adding a range to a legacy eBPF program");
    }
    if (map.d_count >= map.d_config.d_maxItems) {
      throw std::runtime_error("Table full when trying to add this rule: " + addr.toString());
    }

    res = bpf_lookup_elem(map.d_fd.getHandle(), &key, &value);
    if (((res != -1 && value.action == action) || (res == -1 && value.action == BPFFilter::MatchAction::Pass)) && !force) {
      throw std::runtime_error("Trying to add a useless rule: " + addr.toString());
    }

    value.counter = 0;
    value.action = action;

    res = bpf_update_elem(map.d_fd.getHandle(), &key, &value, force ? BPF_ANY : BPF_NOEXIST);
    if (res == 0) {
      ++map.d_count;
    }
  }
  else if (addr.isIPv6()) {
    CIDR6 key(addr);

    auto maps = d_maps.lock();
    auto& map = maps->d_cidr6;
    if (map.d_fd.getHandle() == -1) {
      throw std::runtime_error("Trying to use an unsupported map type, likely adding a range to a legacy eBPF program");
    }
    if (map.d_count >= map.d_config.d_maxItems) {
      throw std::runtime_error("Table full when trying to add this rule: " + addr.toString());
    }

    res = bpf_lookup_elem(map.d_fd.getHandle(), &key, &value);
    if (((res != -1 && value.action == action) || (res == -1 && value.action == BPFFilter::MatchAction::Pass)) && !force) {
      throw std::runtime_error("Trying to add a useless rule: " + addr.toString());
    }

    value.counter = 0;
    value.action = action;

    res = bpf_update_elem(map.d_fd.getHandle(), &key, &value, BPF_NOEXIST);
    if (res == 0) {
      map.d_count++;
    }
  }

  if (res != 0) {
    throw std::runtime_error("Error adding this rule: " + addr.toString() + ": " + stringerror());
  }
}

void BPFFilter::rmRangeRule(const Netmask& addr)
{
  int res = 0;
  CounterAndActionValue value;
  value.counter = 0;
  value.action = MatchAction::Pass;
  if (addr.isIPv4()) {
    CIDR4 key(addr);
    auto maps = d_maps.lock();
    auto& map = maps->d_cidr4;
    if (map.d_fd.getHandle() == -1) {
      throw std::runtime_error("Trying to use an unsupported map type, likely adding a range to a legacy eBPF program");
    }
    res = bpf_delete_elem(map.d_fd.getHandle(), &key);
    if (res == 0) {
      --map.d_count;
    }
    else {
      throw std::runtime_error("Cannot remove '" + addr.toString() + "': No such rule");
    }
  }
  else if (addr.isIPv6()) {
    CIDR6 key(addr);

    auto maps = d_maps.lock();
    auto& map = maps->d_cidr6;
    if (map.d_fd.getHandle() == -1) {
      throw std::runtime_error("Trying to use an unsupported map type, likely adding a range to a legacy eBPF program");
    }
    res = bpf_delete_elem(map.d_fd.getHandle(), &key);
    if (res == 0) {
      --map.d_count;
    }
    else {
      throw std::runtime_error("Cannot remove '" + addr.toString() + "': No such rule");
    }
  }

  if (res != 0) {
    throw std::runtime_error("Error removing this rule: " + addr.toString() + ": " + stringerror());
  }
}

void BPFFilter::block(const DNSName& qname, BPFFilter::MatchAction action, uint16_t qtype)
{
  CounterAndActionValue cadvalue;
  QNameValue qvalue;
  void* value = nullptr;

  if (d_external) {
    cadvalue.counter = 0;
    cadvalue.action = action;
    value = &cadvalue;
  }
  else {
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

    int res = bpf_lookup_elem(map.d_fd.getHandle(), &key, value);
    if (res != -1) {
      throw std::runtime_error("Trying to block an already blocked qname: " + qname.toLogString());
    }
    res = bpf_update_elem(map.d_fd.getHandle(), &key, value, BPF_NOEXIST);
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

std::vector<std::pair<ComboAddress, uint64_t>> BPFFilter::getAddrStats()
{
  std::vector<std::pair<ComboAddress, uint64_t>> result;
  {
    auto maps = d_maps.lock();
    result.reserve(maps->d_v4.d_count + maps->d_v6.d_count);
  }

  sockaddr_in v4Addr{};
  memset(&v4Addr, 0, sizeof(v4Addr));
  v4Addr.sin_family = AF_INET;

  uint32_t v4Key = 0;
  uint32_t nextV4Key{};
  CounterAndActionValue value{};

  std::array<uint8_t, 16> v6Key{};
  std::array<uint8_t, 16> nextV6Key{};
  sockaddr_in6 v6Addr{};
  memset(&v6Addr, 0, sizeof(v6Addr));
  v6Addr.sin6_family = AF_INET6;

  static_assert(sizeof(v6Addr.sin6_addr.s6_addr) == v6Key.size(), "POSIX mandates s6_addr to be an array of 16 uint8_t");
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
    int res = bpf_get_next_key(map.d_fd.getHandle(), v6Key.data(), nextV6Key.data());

    while (res == 0) {
      if (bpf_lookup_elem(map.d_fd.getHandle(), nextV6Key.data(), &value) == 0) {
        memcpy(&v6Addr.sin6_addr.s6_addr, nextV6Key.data(), nextV6Key.size());

        result.emplace_back(ComboAddress(&v6Addr), value.counter);
      }

      res = bpf_get_next_key(map.d_fd.getHandle(), nextV6Key.data(), nextV6Key.data());
    }
  }

  return result;
}

std::vector<std::pair<Netmask, CounterAndActionValue>> BPFFilter::getRangeRule()
{
  CIDR4 cidr4[2];
  CIDR6 cidr6[2];
  std::vector<std::pair<Netmask, CounterAndActionValue>> result;

  sockaddr_in v4Addr;
  sockaddr_in6 v6Addr;
  CounterAndActionValue value;

  memset(cidr4, 0, sizeof(cidr4));
  memset(cidr6, 0, sizeof(cidr6));
  memset(&v4Addr, 0, sizeof(v4Addr));
  memset(&v6Addr, 0, sizeof(v6Addr));
  v4Addr.sin_family = AF_INET;
  v6Addr.sin6_family = AF_INET6;
  auto maps = d_maps.lock();
  result.reserve(maps->d_cidr4.d_count + maps->d_cidr6.d_count);
  {
    auto& map = maps->d_cidr4;
    int res = bpf_get_next_key(map.d_fd.getHandle(), &cidr4[0], &cidr4[1]);
    while (res == 0) {
      if (bpf_lookup_elem(map.d_fd.getHandle(), &cidr4[1], &value) == 0) {
        v4Addr.sin_addr.s_addr = cidr4[1].addr.s_addr;
        result.emplace_back(Netmask(&v4Addr, cidr4[1].cidr), value);
      }

      res = bpf_get_next_key(map.d_fd.getHandle(), &cidr4[1], &cidr4[1]);
    }
  }

  {
    auto& map = maps->d_cidr6;
    int res = bpf_get_next_key(map.d_fd.getHandle(), &cidr6[0], &cidr6[1]);
    while (res == 0) {
      if (bpf_lookup_elem(map.d_fd.getHandle(), &cidr6[1], &value) == 0) {
        v6Addr.sin6_addr = cidr6[1].addr;
        result.emplace_back(Netmask(&v6Addr, cidr6[1].cidr), value);
      }

      res = bpf_get_next_key(map.d_fd.getHandle(), &cidr6[1], &cidr6[1]);
    }
  }
  return result;
}

std::vector<std::tuple<DNSName, uint16_t, uint64_t>> BPFFilter::getQNameStats()
{
  std::vector<std::tuple<DNSName, uint16_t, uint64_t>> result;

  if (d_mapFormat == MapFormat::Legacy) {
    QNameKey key = {{0}};
    QNameKey nextKey = {{0}};
    QNameValue value;

    auto maps = d_maps.lock();
    auto& map = maps->d_qnames;
    result.reserve(map.d_count);
    int res = bpf_get_next_key(map.d_fd.getHandle(), &key, &nextKey);

    while (res == 0) {
      if (bpf_lookup_elem(map.d_fd.getHandle(), &nextKey, &value) == 0) {
        nextKey.qname[sizeof(nextKey.qname) - 1] = '\0';
        result.emplace_back(DNSName(reinterpret_cast<const char*>(nextKey.qname), sizeof(nextKey.qname), 0, false), value.qtype, value.counter);
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
        nextKey.qname[sizeof(nextKey.qname) - 1] = '\0';
        result.emplace_back(DNSName(reinterpret_cast<const char*>(nextKey.qname), sizeof(nextKey.qname), 0, false), key.qtype, value.counter);
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

BPFFilter::BPFFilter(std::unordered_map<std::string, MapConfiguration>& configs, BPFFilter::MapFormat format, bool external)
{
  (void)configs;
  (void)format;
  (void)external;
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

void BPFFilter::addRangeRule(const Netmask&, bool, BPFFilter::MatchAction)
{
  throw std::runtime_error("eBPF support not enabled");
}
void BPFFilter::rmRangeRule(const Netmask&)
{
  throw std::runtime_error("eBPF support not enabled");
}

std::vector<std::pair<Netmask, CounterAndActionValue>> BPFFilter::getRangeRule()
{
  std::vector<std::pair<Netmask, CounterAndActionValue>> result;
  return result;
}
std::vector<std::pair<ComboAddress, uint64_t>> BPFFilter::getAddrStats()
{
  std::vector<std::pair<ComboAddress, uint64_t>> result;
  return result;
}

std::vector<std::tuple<DNSName, uint16_t, uint64_t>> BPFFilter::getQNameStats()
{
  std::vector<std::tuple<DNSName, uint16_t, uint64_t>> result;
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
#else
  (void)action;
  return false;
#endif /* HAVE_EBPF */
}

bool BPFFilter::isExternal() const
{
#ifdef HAVE_EBPF
  return d_external;
#endif /* HAVE_EBPF */
  return false;
}
