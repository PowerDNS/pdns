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

#ifdef HAVE_XSK

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iterator>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdexcept>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
extern "C"
{
#include <xdp/libxdp.h>
}

#include "gettime.hh"
#include "xsk.hh"

/* we need to include the linux specific headers AFTER the regular
   ones, because it then detects that some types have already been
   defined (sockaddr_in6 for example) and does not attempt to
   re-define them, which otherwise breaks the C++ One Definition Rule
*/
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

#ifdef DEBUG_UMEM
namespace
{
struct UmemEntryStatus
{
  enum class Status : uint8_t
  {
    Free,
    FillQueue,
    Received,
    TXQueue
  };
  Status status{Status::Free};
};

LockGuarded<std::map<std::pair<void*, uint64_t>, UmemEntryStatus>> s_umems;

void checkUmemIntegrity(const char* function, int line, std::shared_ptr<LockGuarded<vector<uint64_t>>> vect, uint64_t offset, const std::set<UmemEntryStatus::Status>& validStatuses, UmemEntryStatus::Status newStatus)
{
  auto umems = s_umems.lock();
  auto& umemState = umems->at({vect.get(), offset});
  if (validStatuses.count(umemState.status) == 0) {
    std::cerr << "UMEM integrity check failed at " << function << ": " << line << ": status of " << (void*)vect.get() << ", " << offset << " is " << static_cast<int>(umemState.status) << ", expected: ";
    for (const auto status : validStatuses) {
      std::cerr << static_cast<int>(status) << " ";
    }
    std::cerr << std::endl;
    abort();
  }
  umemState.status = newStatus;
}
}
#endif /* DEBUG_UMEM */

constexpr bool XskSocket::isPowOfTwo(uint32_t value) noexcept
{
  return value != 0 && (value & (value - 1)) == 0;
}

int XskSocket::firstTimeout()
{
  if (waitForDelay.empty()) {
    return -1;
  }
  timespec now{};
  gettime(&now);
  const auto& firstTime = waitForDelay.top().getSendTime();
  const auto res = timeDifference(now, firstTime);
  if (res <= 0) {
    return 0;
  }
  return res;
}

XskSocket::XskSocket(size_t frameNum_, std::string ifName_, uint32_t queue_id, const std::string& xskMapPath) :
  frameNum(frameNum_), ifName(std::move(ifName_)), socket(nullptr, xsk_socket__delete), sharedEmptyFrameOffset(std::make_shared<LockGuarded<vector<uint64_t>>>())
{
  if (!isPowOfTwo(frameNum_) || !isPowOfTwo(frameSize)
      || !isPowOfTwo(fqCapacity) || !isPowOfTwo(cqCapacity) || !isPowOfTwo(rxCapacity) || !isPowOfTwo(txCapacity)) {
    throw std::runtime_error("The number of frame , the size of frame and the capacity of rings must is a pow of 2");
  }
  getMACFromIfName();

  memset(&cq, 0, sizeof(cq));
  memset(&fq, 0, sizeof(fq));
  memset(&tx, 0, sizeof(tx));
  memset(&rx, 0, sizeof(rx));

  xsk_umem_config umemCfg{};
  umemCfg.fill_size = fqCapacity;
  umemCfg.comp_size = cqCapacity;
  umemCfg.frame_size = frameSize;
  umemCfg.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;
  umemCfg.flags = 0;
  umem.umemInit(frameNum_ * frameSize, &cq, &fq, &umemCfg);

  {
    xsk_socket_config socketCfg{};
    socketCfg.rx_size = rxCapacity;
    socketCfg.tx_size = txCapacity;
    socketCfg.bind_flags = XDP_USE_NEED_WAKEUP;
    socketCfg.xdp_flags = XDP_FLAGS_SKB_MODE;
    socketCfg.libxdp_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    xsk_socket* tmp = nullptr;
    auto ret = xsk_socket__create(&tmp, ifName.c_str(), queue_id, umem.umem, &rx, &tx, &socketCfg);
    if (ret != 0) {
      throw std::runtime_error("Error creating a xsk socket of if_name " + ifName + ": " + stringerror(ret));
    }
    socket = std::unique_ptr<xsk_socket, decltype(&xsk_socket__delete)>(tmp, xsk_socket__delete);
  }

  uniqueEmptyFrameOffset.reserve(frameNum);
  {
    for (uint64_t idx = 0; idx < frameNum; idx++) {
      uniqueEmptyFrameOffset.push_back(idx * frameSize + XDP_PACKET_HEADROOM);
#ifdef DEBUG_UMEM
      {
        auto umems = s_umems.lock();
        (*umems)[{sharedEmptyFrameOffset.get(), idx * frameSize + XDP_PACKET_HEADROOM}] = UmemEntryStatus();
      }
#endif /* DEBUG_UMEM */
    }
  }

  fillFq(fqCapacity);

  const auto xskfd = xskFd();
  fds.push_back(pollfd{
    .fd = xskfd,
    .events = POLLIN,
    .revents = 0});

  const auto xskMapFd = FDWrapper(bpf_obj_get(xskMapPath.c_str()));

  if (xskMapFd.getHandle() < 0) {
    throw std::runtime_error("Error getting BPF map from path '" + xskMapPath + "'");
  }

  auto ret = bpf_map_update_elem(xskMapFd.getHandle(), &queue_id, &xskfd, 0);
  if (ret != 0) {
    throw std::runtime_error("Error inserting into xsk_map '" + xskMapPath + "': " + std::to_string(ret));
  }
}

// see xdp.h in contrib/
struct IPv4AndPort
{
  uint32_t addr;
  uint16_t port;
};
struct IPv6AndPort
{
  struct in6_addr addr;
  uint16_t port;
};

static FDWrapper getDestinationMap(const std::string& mapPath)
{
  auto destMapFd = FDWrapper(bpf_obj_get(mapPath.c_str()));
  if (destMapFd.getHandle() < 0) {
    throw std::runtime_error("Error getting the XSK destination addresses map path '" + mapPath + "'");
  }
  return destMapFd;
}

void XskSocket::clearDestinationMap(const std::string& mapPath, bool isV6)
{
  auto destMapFd = getDestinationMap(mapPath);
  if (!isV6) {
    IPv4AndPort prevKey{};
    IPv4AndPort key{};
    while (bpf_map_get_next_key(destMapFd.getHandle(), &prevKey, &key) == 0) {
      bpf_map_delete_elem(destMapFd.getHandle(), &key);
      prevKey = key;
    }
  }
  else {
    IPv6AndPort prevKey{};
    IPv6AndPort key{};
    while (bpf_map_get_next_key(destMapFd.getHandle(), &prevKey, &key) == 0) {
      bpf_map_delete_elem(destMapFd.getHandle(), &key);
      prevKey = key;
    }
  }
}

void XskSocket::addDestinationAddress(const std::string& mapPath, const ComboAddress& destination)
{
  auto destMapFd = getDestinationMap(mapPath);
  bool value = true;
  if (destination.isIPv4()) {
    IPv4AndPort key{};
    key.addr = destination.sin4.sin_addr.s_addr;
    key.port = destination.sin4.sin_port;
    auto ret = bpf_map_update_elem(destMapFd.getHandle(), &key, &value, 0);
    if (ret != 0) {
      throw std::runtime_error("Error inserting into xsk_map '" + mapPath + "': " + std::to_string(ret));
    }
  }
  else {
    IPv6AndPort key{};
    key.addr = destination.sin6.sin6_addr;
    key.port = destination.sin6.sin6_port;
    auto ret = bpf_map_update_elem(destMapFd.getHandle(), &key, &value, 0);
    if (ret != 0) {
      throw std::runtime_error("Error inserting into XSK destination addresses map '" + mapPath + "': " + std::to_string(ret));
    }
  }
}

void XskSocket::removeDestinationAddress(const std::string& mapPath, const ComboAddress& destination)
{
  auto destMapFd = getDestinationMap(mapPath);
  if (destination.isIPv4()) {
    IPv4AndPort key{};
    key.addr = destination.sin4.sin_addr.s_addr;
    key.port = destination.sin4.sin_port;
    bpf_map_delete_elem(destMapFd.getHandle(), &key);
  }
  else {
    IPv6AndPort key{};
    key.addr = destination.sin6.sin6_addr;
    key.port = destination.sin6.sin6_port;
    bpf_map_delete_elem(destMapFd.getHandle(), &key);
  }
}

void XskSocket::fillFq(uint32_t fillSize) noexcept
{
  if (uniqueEmptyFrameOffset.size() < fillSize) {
    auto frames = sharedEmptyFrameOffset->lock();
    const auto moveSize = std::min(static_cast<size_t>(fillSize), frames->size());
    if (moveSize > 0) {
      // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
      uniqueEmptyFrameOffset.insert(uniqueEmptyFrameOffset.end(), std::make_move_iterator(frames->end() - moveSize), std::make_move_iterator(frames->end()));
      frames->resize(frames->size() - moveSize);
    }
  }
  else if (uniqueEmptyFrameOffset.size() > (10 * fillSize)) {
    // if we have less than holdThreshold frames in the shared queue (which might be an issue
    // when the XskWorker needs empty frames), move frames from the unique container into the
    // shared one. This might not be optimal right now.
    auto frames = sharedEmptyFrameOffset->lock();
    if (frames->size() < holdThreshold) {
      const auto moveSize = std::min(holdThreshold - frames->size(), uniqueEmptyFrameOffset.size());
      if (moveSize > 0) {
        // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
        frames->insert(frames->end(), std::make_move_iterator(uniqueEmptyFrameOffset.end() - moveSize), std::make_move_iterator(uniqueEmptyFrameOffset.end()));
        uniqueEmptyFrameOffset.resize(uniqueEmptyFrameOffset.size() - moveSize);
      }
    }
  }

  fillSize = std::min(fillSize, static_cast<uint32_t>(uniqueEmptyFrameOffset.size()));
  if (fillSize == 0) {
    auto frames = sharedEmptyFrameOffset->lock();
    return;
  }

  uint32_t idx{0};
  auto toFill = xsk_ring_prod__reserve(&fq, fillSize, &idx);
  if (toFill == 0) {
    return;
  }
  uint32_t processed = 0;
  for (; processed < toFill; processed++) {
    *xsk_ring_prod__fill_addr(&fq, idx++) = uniqueEmptyFrameOffset.back();
#ifdef DEBUG_UMEM
    checkUmemIntegrity(__PRETTY_FUNCTION__, __LINE__, sharedEmptyFrameOffset, uniqueEmptyFrameOffset.back(), {UmemEntryStatus::Status::Free}, UmemEntryStatus::Status::FillQueue);
#endif /* DEBUG_UMEM */
    uniqueEmptyFrameOffset.pop_back();
  }

  xsk_ring_prod__submit(&fq, processed);
}

int XskSocket::wait(int timeout)
{
  auto waitAtMost = std::min(timeout, firstTimeout());
  return poll(fds.data(), fds.size(), waitAtMost);
}

[[nodiscard]] uint64_t XskSocket::frameOffset(const XskPacket& packet) const noexcept
{
  return packet.getFrameOffsetFrom(umem.bufBase);
}

[[nodiscard]] int XskSocket::xskFd() const noexcept
{
  return xsk_socket__fd(socket.get());
}

void XskSocket::send(std::vector<XskPacket>& packets)
{
  while (!packets.empty()) {
    auto packetSize = packets.size();
    if (packetSize > std::numeric_limits<uint32_t>::max()) {
      packetSize = std::numeric_limits<uint32_t>::max();
    }
    size_t toSend = std::min(static_cast<uint32_t>(packetSize), txCapacity);
    uint32_t idx{0};
    auto toFill = xsk_ring_prod__reserve(&tx, toSend, &idx);
    if (toFill == 0) {
      return;
    }

    size_t queued = 0;
    for (const auto& packet : packets) {
      if (queued == toFill) {
        break;
      }
      *xsk_ring_prod__tx_desc(&tx, idx++) = {
        .addr = frameOffset(packet),
        .len = packet.getFrameLen(),
        .options = 0};
#ifdef DEBUG_UMEM
      checkUmemIntegrity(__PRETTY_FUNCTION__, __LINE__, sharedEmptyFrameOffset, frameOffset(packet), {UmemEntryStatus::Status::Free, UmemEntryStatus::Status::Received}, UmemEntryStatus::Status::TXQueue);
#endif /* DEBUG_UMEM */
      queued++;
    }
    xsk_ring_prod__submit(&tx, toFill);
    packets.erase(packets.begin(), packets.begin() + toFill);
  }
}

std::vector<XskPacket> XskSocket::recv(uint32_t recvSizeMax, uint32_t* failedCount)
{
  uint32_t idx{0};
  std::vector<XskPacket> res;
  // how many descriptors to packets have been filled
  const auto recvSize = xsk_ring_cons__peek(&rx, recvSizeMax, &idx);
  if (recvSize == 0) {
    return res;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  const auto baseAddr = reinterpret_cast<uint64_t>(umem.bufBase);
  uint32_t failed = 0;
  uint32_t processed = 0;
  res.reserve(recvSize);
  for (; processed < recvSize; processed++) {
    try {
      const auto* desc = xsk_ring_cons__rx_desc(&rx, idx++);
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,performance-no-int-to-ptr)
      XskPacket packet = XskPacket(reinterpret_cast<uint8_t*>(desc->addr + baseAddr), desc->len, frameSize);
#ifdef DEBUG_UMEM
      checkUmemIntegrity(__PRETTY_FUNCTION__, __LINE__, sharedEmptyFrameOffset, frameOffset(packet), {UmemEntryStatus::Status::FillQueue}, UmemEntryStatus::Status::Received);
#endif /* DEBUG_UMEM */

      if (!packet.parse(false)) {
        ++failed;
        markAsFree(packet);
      }
      else {
        res.push_back(packet);
      }
    }
    catch (const std::exception& exp) {
      ++failed;
      ++processed;
      break;
    }
    catch (...) {
      ++failed;
      ++processed;
      break;
    }
  }

  // this releases the descriptor, but not the packet (umem entries)
  // which will only be made available again when pushed into the fill
  // queue
  xsk_ring_cons__release(&rx, processed);
  if (failedCount != nullptr) {
    *failedCount = failed;
  }

  return res;
}

void XskSocket::pickUpReadyPacket(std::vector<XskPacket>& packets)
{
  timespec now{};
  gettime(&now);
  while (!waitForDelay.empty() && timeDifference(now, waitForDelay.top().getSendTime()) <= 0) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    auto& top = const_cast<XskPacket&>(waitForDelay.top());
    packets.push_back(top);
    waitForDelay.pop();
  }
}

void XskSocket::recycle(size_t size) noexcept
{
  uint32_t idx{0};
  const auto completeSize = xsk_ring_cons__peek(&cq, size, &idx);
  if (completeSize == 0) {
    return;
  }
  uniqueEmptyFrameOffset.reserve(uniqueEmptyFrameOffset.size() + completeSize);
  uint32_t processed = 0;
  for (; processed < completeSize; ++processed) {
    uniqueEmptyFrameOffset.push_back(*xsk_ring_cons__comp_addr(&cq, idx++));
#ifdef DEBUG_UMEM
    checkUmemIntegrity(__PRETTY_FUNCTION__, __LINE__, sharedEmptyFrameOffset, uniqueEmptyFrameOffset.back(), {UmemEntryStatus::Status::Received, UmemEntryStatus::Status::TXQueue}, UmemEntryStatus::Status::Free);
#endif /* DEBUG_UMEM */
  }
  xsk_ring_cons__release(&cq, processed);
}

void XskSocket::XskUmem::umemInit(size_t memSize, xsk_ring_cons* completionQueue, xsk_ring_prod* fillQueue, xsk_umem_config* config)
{
  size = memSize;
  bufBase = static_cast<uint8_t*>(mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (bufBase == MAP_FAILED) {
    throw std::runtime_error("mmap failed");
  }
  auto ret = xsk_umem__create(&umem, bufBase, size, fillQueue, completionQueue, config);
  if (ret != 0) {
    munmap(bufBase, size);
    throw std::runtime_error("Error creating a umem of size " + std::to_string(size) + ": " + stringerror(ret));
  }
}

std::string XskSocket::getMetrics() const
{
  xdp_statistics stats{};
  socklen_t optlen = sizeof(stats);
  int err = getsockopt(xskFd(), SOL_XDP, XDP_STATISTICS, &stats, &optlen);
  if (err != 0) {
    return "";
  }
  if (optlen != sizeof(struct xdp_statistics)) {
    return "";
  }

  ostringstream ret;
  ret << "RX dropped: " << std::to_string(stats.rx_dropped) << std::endl;
  ret << "RX invalid descs: " << std::to_string(stats.rx_invalid_descs) << std::endl;
  ret << "TX invalid descs: " << std::to_string(stats.tx_invalid_descs) << std::endl;
  ret << "RX ring full: " << std::to_string(stats.rx_ring_full) << std::endl;
  ret << "RX fill ring empty descs: " << std::to_string(stats.rx_fill_ring_empty_descs) << std::endl;
  ret << "TX ring empty descs: " << std::to_string(stats.tx_ring_empty_descs) << std::endl;
  return ret.str();
}

[[nodiscard]] std::string XskSocket::getXDPMode() const
{
#ifdef HAVE_BPF_XDP_QUERY
  unsigned int itfIdx = if_nametoindex(ifName.c_str());
  if (itfIdx == 0) {
    return "unable to get interface index";
  }
  bpf_xdp_query_opts info{};
  info.sz = sizeof(info);
  int ret = bpf_xdp_query(static_cast<int>(itfIdx), 0, &info);
  if (ret != 0) {
    return {};
  }
  switch (info.attach_mode) {
  case XDP_ATTACHED_DRV:
  case XDP_ATTACHED_HW:
    return "native";
  case XDP_ATTACHED_SKB:
    return "emulated";
  default:
    return "unknown";
  }
#else /* HAVE_BPF_XDP_QUERY */
  return "undetected";
#endif /* HAVE_BPF_XDP_QUERY */
}

void XskSocket::markAsFree(const XskPacket& packet)
{
  auto offset = frameOffset(packet);
#ifdef DEBUG_UMEM
  checkUmemIntegrity(__PRETTY_FUNCTION__, __LINE__, sharedEmptyFrameOffset, offset, {UmemEntryStatus::Status::Received, UmemEntryStatus::Status::TXQueue}, UmemEntryStatus::Status::Free);
#endif /* DEBUG_UMEM */
  uniqueEmptyFrameOffset.push_back(offset);
}

XskSocket::XskUmem::~XskUmem()
{
  if (umem != nullptr) {
    xsk_umem__delete(umem);
  }
  if (bufBase != nullptr) {
    munmap(bufBase, size);
  }
}

[[nodiscard]] size_t XskPacket::getL4HeaderOffset() const noexcept
{
  return sizeof(ethhdr) + (v6 ? (sizeof(ipv6hdr)) : sizeof(iphdr));
}

[[nodiscard]] size_t XskPacket::getDataOffset() const noexcept
{
  return getL4HeaderOffset() + sizeof(udphdr);
}

[[nodiscard]] size_t XskPacket::getDataSize() const noexcept
{
  return frameLength - getDataOffset();
}

[[nodiscard]] ethhdr XskPacket::getEthernetHeader() const noexcept
{
  ethhdr ethHeader{};
  if (frameLength >= sizeof(ethHeader)) {
    memcpy(&ethHeader, frame, sizeof(ethHeader));
  }
  return ethHeader;
}

void XskPacket::setEthernetHeader(const ethhdr& ethHeader) noexcept
{
  if (frameLength < sizeof(ethHeader)) {
    frameLength = sizeof(ethHeader);
  }
  memcpy(frame, &ethHeader, sizeof(ethHeader));
}

[[nodiscard]] iphdr XskPacket::getIPv4Header() const noexcept
{
  iphdr ipv4Header{};
  assert(frameLength >= (sizeof(ethhdr) + sizeof(ipv4Header)));
  assert(!v6);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  memcpy(&ipv4Header, frame + sizeof(ethhdr), sizeof(ipv4Header));
  return ipv4Header;
}

void XskPacket::setIPv4Header(const iphdr& ipv4Header) noexcept
{
  assert(frameLength >= (sizeof(ethhdr) + sizeof(iphdr)));
  assert(!v6);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  memcpy(frame + sizeof(ethhdr), &ipv4Header, sizeof(ipv4Header));
}

[[nodiscard]] ipv6hdr XskPacket::getIPv6Header() const noexcept
{
  ipv6hdr ipv6Header{};
  assert(frameLength >= (sizeof(ethhdr) + sizeof(ipv6Header)));
  assert(v6);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  memcpy(&ipv6Header, frame + sizeof(ethhdr), sizeof(ipv6Header));
  return ipv6Header;
}

void XskPacket::setIPv6Header(const ipv6hdr& ipv6Header) noexcept
{
  assert(frameLength >= (sizeof(ethhdr) + sizeof(ipv6Header)));
  assert(v6);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  memcpy(frame + sizeof(ethhdr), &ipv6Header, sizeof(ipv6Header));
}

[[nodiscard]] udphdr XskPacket::getUDPHeader() const noexcept
{
  udphdr udpHeader{};
  assert(frameLength >= (sizeof(ethhdr) + (v6 ? sizeof(ipv6hdr) : sizeof(iphdr)) + sizeof(udpHeader)));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  memcpy(&udpHeader, frame + getL4HeaderOffset(), sizeof(udpHeader));
  return udpHeader;
}

void XskPacket::setUDPHeader(const udphdr& udpHeader) noexcept
{
  assert(frameLength >= (sizeof(ethhdr) + (v6 ? sizeof(ipv6hdr) : sizeof(iphdr)) + sizeof(udpHeader)));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  memcpy(frame + getL4HeaderOffset(), &udpHeader, sizeof(udpHeader));
}

bool XskPacket::parse(bool fromSetHeader)
{
  if (frameLength <= sizeof(ethhdr)) {
    return false;
  }

  auto ethHeader = getEthernetHeader();
  uint8_t l4Protocol{0};
  if (ethHeader.h_proto == htons(ETH_P_IP)) {
    if (frameLength < (sizeof(ethhdr) + sizeof(iphdr) + sizeof(udphdr))) {
      return false;
    }
    v6 = false;
    auto ipHeader = getIPv4Header();
    if (ipHeader.ihl != (static_cast<uint8_t>(sizeof(iphdr) / 4))) {
      // ip options is not supported now!
      return false;
    }
    // check ip.check == ipv4Checksum() is not needed!
    // We check it in BPF program
    // we don't, actually.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    from = makeComboAddressFromRaw(4, reinterpret_cast<const char*>(&ipHeader.saddr), sizeof(ipHeader.saddr));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    to = makeComboAddressFromRaw(4, reinterpret_cast<const char*>(&ipHeader.daddr), sizeof(ipHeader.daddr));
    l4Protocol = ipHeader.protocol;
    if (!fromSetHeader && (frameLength - sizeof(ethhdr)) != ntohs(ipHeader.tot_len)) {
      // too small, or too large (trailing data), go away
      return false;
    }
  }
  else if (ethHeader.h_proto == htons(ETH_P_IPV6)) {
    if (frameLength < (sizeof(ethhdr) + sizeof(ipv6hdr) + sizeof(udphdr))) {
      return false;
    }
    v6 = true;
    auto ipHeader = getIPv6Header();
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    from = makeComboAddressFromRaw(6, reinterpret_cast<const char*>(&ipHeader.saddr), sizeof(ipHeader.saddr));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    to = makeComboAddressFromRaw(6, reinterpret_cast<const char*>(&ipHeader.daddr), sizeof(ipHeader.daddr));
    l4Protocol = ipHeader.nexthdr;
    if (!fromSetHeader && (frameLength - (sizeof(ethhdr) + sizeof(ipv6hdr))) != ntohs(ipHeader.payload_len)) {
      return false;
    }
  }
  else {
    return false;
  }

  if (l4Protocol != IPPROTO_UDP) {
    return false;
  }

  // check udp.check == ipv4Checksum() is not needed!
  // We check it in BPF program
  // we don't, actually.
  auto udpHeader = getUDPHeader();
  if (!fromSetHeader) {
    // Because of XskPacket::setHeader
    if (getDataOffset() > frameLength) {
      return false;
    }

    if (getDataSize() + sizeof(udphdr) != ntohs(udpHeader.len)) {
      return false;
    }
  }

  from.setPort(ntohs(udpHeader.source));
  to.setPort(ntohs(udpHeader.dest));
  return true;
}

uint32_t XskPacket::getDataLen() const noexcept
{
  return getDataSize();
}

uint32_t XskPacket::getFrameLen() const noexcept
{
  return frameLength;
}

size_t XskPacket::getCapacity() const noexcept
{
  return frameSize - getDataOffset();
}

void XskPacket::changeDirectAndUpdateChecksum() noexcept
{
  auto ethHeader = getEthernetHeader();
  {
    std::array<uint8_t, ETH_ALEN> tmp{};
    static_assert(tmp.size() == sizeof(ethHeader.h_dest), "Size Error");
    static_assert(tmp.size() == sizeof(ethHeader.h_source), "Size Error");
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    memcpy(tmp.data(), ethHeader.h_dest, tmp.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    memcpy(ethHeader.h_dest, ethHeader.h_source, tmp.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    memcpy(ethHeader.h_source, tmp.data(), tmp.size());
  }
  if (ethHeader.h_proto == htons(ETH_P_IPV6)) {
    // IPV6
    auto ipv6 = getIPv6Header();
    std::swap(ipv6.daddr, ipv6.saddr);
    ipv6.nexthdr = IPPROTO_UDP;

    auto udp = getUDPHeader();
    std::swap(udp.dest, udp.source);
    udp.len = htons(getDataSize() + sizeof(udp));
    udp.check = 0;
    /* needed to get the correct checksum */
    setIPv6Header(ipv6);
    setUDPHeader(udp);
    // do not bother setting the UDP checksum: 0 is a valid value and most AF_XDP
    // implementations do the same
    // udp.check = tcp_udp_v6_checksum(&ipv6);
    rewriteIpv6Header(&ipv6, getFrameLen());
    setIPv6Header(ipv6);
    setUDPHeader(udp);
  }
  else if (ethHeader.h_proto == htons(ETH_P_IP)) {
    // IPV4
    auto ipv4 = getIPv4Header();
    std::swap(ipv4.daddr, ipv4.saddr);
    ipv4.protocol = IPPROTO_UDP;

    auto udp = getUDPHeader();
    std::swap(udp.dest, udp.source);
    udp.len = htons(getDataSize() + sizeof(udp));
    udp.check = 0;
    /* needed to get the correct checksum */
    setIPv4Header(ipv4);
    setUDPHeader(udp);
    // do not bother setting the UDP checksum: 0 is a valid value and most AF_XDP
    // implementations do the same
    // udp.check = tcp_udp_v4_checksum(&ipv4);
    rewriteIpv4Header(&ipv4, getFrameLen());
    setIPv4Header(ipv4);
    setUDPHeader(udp);
  }
  setEthernetHeader(ethHeader);
}

void XskPacket::rewriteIpv4Header(struct iphdr* ipv4header, size_t frameLen) noexcept
{
  ipv4header->version = 4;
  ipv4header->ihl = sizeof(iphdr) / 4;
  ipv4header->tos = 0;
  ipv4header->tot_len = htons(frameLen - sizeof(ethhdr));
  ipv4header->id = 0;
  ipv4header->frag_off = 0;
  ipv4header->ttl = DefaultTTL;
  ipv4header->check = 0;
  ipv4header->check = ipv4Checksum(ipv4header);
}

void XskPacket::rewriteIpv6Header(struct ipv6hdr* ipv6header, size_t frameLen) noexcept
{
  ipv6header->version = 6;
  ipv6header->priority = 0;
  ipv6header->payload_len = htons(frameLen - sizeof(ethhdr) - sizeof(ipv6hdr));
  ipv6header->hop_limit = DefaultTTL;
  memset(&ipv6header->flow_lbl, 0, sizeof(ipv6header->flow_lbl));
}

bool XskPacket::isIPV6() const noexcept
{
  return v6;
}

XskPacket::XskPacket(uint8_t* frame_, size_t dataSize, size_t frameSize_) :
  frame(frame_), frameLength(dataSize), frameSize(frameSize_ - XDP_PACKET_HEADROOM)
{
}

PacketBuffer XskPacket::clonePacketBuffer() const
{
  const auto size = getDataSize();
  PacketBuffer tmp(size);
  if (size > 0) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    memcpy(tmp.data(), frame + getDataOffset(), size);
  }
  return tmp;
}

bool XskPacket::setPayload(const PacketBuffer& buf)
{
  const auto bufSize = buf.size();
  const auto currentCapacity = getCapacity();
  if (bufSize == 0 || bufSize > currentCapacity) {
    return false;
  }
  flags |= UPDATE;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  memcpy(frame + getDataOffset(), buf.data(), bufSize);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  frameLength = getDataOffset() + bufSize;
  return true;
}

void XskPacket::addDelay(const int relativeMilliseconds) noexcept
{
  gettime(&sendTime);
  sendTime.tv_nsec += static_cast<int64_t>(relativeMilliseconds) * 1000000L;
  sendTime.tv_sec += sendTime.tv_nsec / 1000000000L;
  sendTime.tv_nsec %= 1000000000L;
}

bool operator<(const XskPacket& lhs, const XskPacket& rhs) noexcept
{
  return lhs.getSendTime() < rhs.getSendTime();
}

const ComboAddress& XskPacket::getFromAddr() const noexcept
{
  return from;
}

const ComboAddress& XskPacket::getToAddr() const noexcept
{
  return to;
}

void XskWorker::notify(int desc)
{
  uint64_t value = 1;
  ssize_t res = 0;
  while ((res = write(desc, &value, sizeof(value))) == EINTR) {
  }
  if (res != sizeof(value)) {
    throw runtime_error("Unable Wake Up XskSocket Failed");
  }
}

XskWorker::XskWorker(XskWorker::Type type, const std::shared_ptr<LockGuarded<std::vector<uint64_t>>>& frames) :
  d_sharedEmptyFrameOffset(frames), d_type(type), workerWaker(createEventfd()), xskSocketWaker(createEventfd())
{
}

void XskWorker::pushToProcessingQueue(XskPacket& packet)
{
  if (d_type == Type::OutgoingOnly) {
    throw std::runtime_error("Trying to push an incoming packet into an outgoing-only XSK Worker");
  }
  if (!d_incomingPacketsQueue.push(packet)) {
    markAsFree(packet);
  }
}

void XskWorker::pushToSendQueue(XskPacket& packet)
{
  if (!d_outgoingPacketsQueue.push(packet)) {
    markAsFree(packet);
  }
}

const void* XskPacket::getPayloadData() const
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  return frame + getDataOffset();
}

void XskPacket::setAddr(const ComboAddress& from_, MACAddr fromMAC, const ComboAddress& to_, MACAddr toMAC) noexcept
{
  auto ethHeader = getEthernetHeader();
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
  memcpy(ethHeader.h_dest, toMAC.data(), toMAC.size());
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
  memcpy(ethHeader.h_source, fromMAC.data(), fromMAC.size());
  setEthernetHeader(ethHeader);
  to = to_;
  from = from_;
  v6 = !to.isIPv4();
  flags = 0;
}

void XskPacket::rewrite() noexcept
{
  flags |= REWRITE;
  auto ethHeader = getEthernetHeader();
  if (!v6) {
    ethHeader.h_proto = htons(ETH_P_IP);

    auto ipHeader = getIPv4Header();
    ipHeader.daddr = to.sin4.sin_addr.s_addr;
    ipHeader.saddr = from.sin4.sin_addr.s_addr;
    ipHeader.protocol = IPPROTO_UDP;

    auto udpHeader = getUDPHeader();
    udpHeader.source = from.sin4.sin_port;
    udpHeader.dest = to.sin4.sin_port;
    udpHeader.len = htons(getDataSize() + sizeof(udpHeader));
    udpHeader.check = 0;
    /* needed to get the correct checksum */
    setIPv4Header(ipHeader);
    setUDPHeader(udpHeader);
    // do not bother setting the UDP checksum: 0 is a valid value and most AF_XDP
    // implementations do the same
    // udpHeader.check = tcp_udp_v4_checksum(&ipHeader);
    rewriteIpv4Header(&ipHeader, getFrameLen());
    setIPv4Header(ipHeader);
    setUDPHeader(udpHeader);
  }
  else {
    ethHeader.h_proto = htons(ETH_P_IPV6);

    auto ipHeader = getIPv6Header();
    memcpy(&ipHeader.daddr, &to.sin6.sin6_addr, sizeof(ipHeader.daddr));
    memcpy(&ipHeader.saddr, &from.sin6.sin6_addr, sizeof(ipHeader.saddr));
    ipHeader.nexthdr = IPPROTO_UDP;

    auto udpHeader = getUDPHeader();
    udpHeader.source = from.sin6.sin6_port;
    udpHeader.dest = to.sin6.sin6_port;
    udpHeader.len = htons(getDataSize() + sizeof(udpHeader));
    udpHeader.check = 0;
    /* needed to get the correct checksum */
    setIPv6Header(ipHeader);
    setUDPHeader(udpHeader);
    // do not bother setting the UDP checksum: 0 is a valid value and most AF_XDP
    // implementations do the same
    // udpHeader.check = tcp_udp_v6_checksum(&ipHeader);
    setIPv6Header(ipHeader);
    setUDPHeader(udpHeader);
  }

  setEthernetHeader(ethHeader);
}

[[nodiscard]] __be16 XskPacket::ipv4Checksum(const struct iphdr* ipHeader) noexcept
{
  auto partial = ip_checksum_partial(ipHeader, sizeof(iphdr), 0);
  return ip_checksum_fold(partial);
}

[[nodiscard]] __be16 XskPacket::tcp_udp_v4_checksum(const struct iphdr* ipHeader) const noexcept
{
  // ip options is not supported !!!
  const auto l4Length = static_cast<uint16_t>(getDataSize() + sizeof(udphdr));
  auto sum = tcp_udp_v4_header_checksum_partial(ipHeader->saddr, ipHeader->daddr, ipHeader->protocol, l4Length);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  sum = ip_checksum_partial(frame + getL4HeaderOffset(), l4Length, sum);
  return ip_checksum_fold(sum);
}

[[nodiscard]] __be16 XskPacket::tcp_udp_v6_checksum(const struct ipv6hdr* ipv6) const noexcept
{
  const auto l4Length = static_cast<uint16_t>(getDataSize() + sizeof(udphdr));
  uint64_t sum = tcp_udp_v6_header_checksum_partial(&ipv6->saddr, &ipv6->daddr, ipv6->nexthdr, l4Length);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  sum = ip_checksum_partial(frame + getL4HeaderOffset(), l4Length, sum);
  return ip_checksum_fold(sum);
}

[[nodiscard]] uint64_t XskPacket::ip_checksum_partial(const void* ptr, const size_t len, uint64_t sum) noexcept
{
  size_t position{0};
  /* Main loop: 32 bits at a time */
  for (position = 0; position < len; position += sizeof(uint32_t)) {
    uint32_t value{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    memcpy(&value, static_cast<const uint8_t*>(ptr) + position, sizeof(value));
    sum += value;
  }

  /* Handle un-32bit-aligned trailing bytes */
  if ((len - position) >= 2) {
    uint16_t value{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    memcpy(&value, static_cast<const uint8_t*>(ptr) + position, sizeof(value));
    sum += value;
    position += sizeof(value);
  }

  if ((len - position) > 0) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const auto* ptr8 = static_cast<const uint8_t*>(ptr) + position;
    sum += ntohs(*ptr8 << 8); /* RFC says pad last byte */
  }

  return sum;
}

[[nodiscard]] __be16 XskPacket::ip_checksum_fold(uint64_t sum) noexcept
{
  while ((sum & ~0xffffffffULL) != 0U) {
    sum = (sum >> 32) + (sum & 0xffffffffULL);
  }
  while ((sum & 0xffff0000ULL) != 0U) {
    sum = (sum >> 16) + (sum & 0xffffULL);
  }

  return static_cast<__be16>(~sum);
}

#ifndef __packed
#define packed_attribute __attribute__((packed))
#else
#define packed_attribute __packed
#endif

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
[[nodiscard]] uint64_t XskPacket::tcp_udp_v4_header_checksum_partial(__be32 src_ip, __be32 dst_ip, uint8_t protocol, uint16_t len) noexcept
{
  struct header
  {
    __be32 src_ip;
    __be32 dst_ip;
    __uint8_t mbz;
    __uint8_t protocol;
    __be16 length;
  };
  /* The IPv4 pseudo-header is defined in RFC 793, Section 3.1. */
  struct ipv4_pseudo_header_t
  {
    /* We use a union here to avoid aliasing issues with gcc -O2 */
    union
    {
      header packed_attribute fields;
      // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
      uint32_t words[3];
    };
  };
  ipv4_pseudo_header_t pseudo_header{};
  static_assert(sizeof(pseudo_header) == 12, "IPv4 pseudo-header size is incorrect");

  /* Fill in the pseudo-header. */
  pseudo_header.fields.src_ip = src_ip;
  pseudo_header.fields.dst_ip = dst_ip;
  pseudo_header.fields.mbz = 0;
  pseudo_header.fields.protocol = protocol;
  pseudo_header.fields.length = htons(len);
  return ip_checksum_partial(&pseudo_header, sizeof(pseudo_header), 0);
}

[[nodiscard]] uint64_t XskPacket::tcp_udp_v6_header_checksum_partial(const struct in6_addr* src_ip, const struct in6_addr* dst_ip, uint8_t protocol, uint32_t len) noexcept
{
  struct header
  {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __be32 length;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
    __uint8_t mbz[3];
    __uint8_t next_header;
  };
  /* The IPv6 pseudo-header is defined in RFC 2460, Section 8.1. */
  struct ipv6_pseudo_header_t
  {
    /* We use a union here to avoid aliasing issues with gcc -O2 */
    union
    {
      header packed_attribute fields;
      // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
      uint32_t words[10];
    };
  };
  ipv6_pseudo_header_t pseudo_header{};
  static_assert(sizeof(pseudo_header) == 40, "IPv6 pseudo-header size is incorrect");

  /* Fill in the pseudo-header. */
  pseudo_header.fields.src_ip = *src_ip;
  pseudo_header.fields.dst_ip = *dst_ip;
  pseudo_header.fields.length = htonl(len);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
  memset(pseudo_header.fields.mbz, 0, sizeof(pseudo_header.fields.mbz));
  pseudo_header.fields.next_header = protocol;
  return ip_checksum_partial(&pseudo_header, sizeof(pseudo_header), 0);
}

void XskPacket::setHeader(PacketBuffer& buf)
{
  memcpy(frame, buf.data(), buf.size());
  frameLength = buf.size();
  buf.clear();
  flags = 0;
  if (!parse(true)) {
    throw std::runtime_error("Error setting the XSK frame header");
  }
}

PacketBuffer XskPacket::cloneHeaderToPacketBuffer() const
{
  const auto size = getFrameLen() - getDataSize();
  PacketBuffer tmp(size);
  memcpy(tmp.data(), frame, size);
  return tmp;
}

int XskWorker::createEventfd()
{
  auto desc = ::eventfd(0, EFD_CLOEXEC);
  if (desc < 0) {
    throw runtime_error("Unable create eventfd");
  }
  return desc;
}

void XskWorker::waitForXskSocket() const noexcept
{
  uint64_t value = read(workerWaker, &value, sizeof(value));
}

void XskWorker::notifyXskSocket() const
{
  notify(xskSocketWaker);
}

std::shared_ptr<XskWorker> XskWorker::create(Type type, const std::shared_ptr<LockGuarded<std::vector<uint64_t>>>& frames)
{
  return std::make_shared<XskWorker>(type, frames);
}

void XskSocket::addWorker(std::shared_ptr<XskWorker> worker)
{
  const auto socketWaker = worker->xskSocketWaker.getHandle();
  worker->setUmemBufBase(umem.bufBase);
  d_workers.insert({socketWaker, std::move(worker)});
  fds.push_back(pollfd{
    .fd = socketWaker,
    .events = POLLIN,
    .revents = 0});
};

void XskSocket::addWorkerRoute(const std::shared_ptr<XskWorker>& worker, const ComboAddress& dest)
{
  d_workerRoutes.lock()->insert({dest, worker});
}

void XskSocket::removeWorkerRoute(const ComboAddress& dest)
{
  d_workerRoutes.lock()->erase(dest);
}

void XskWorker::setUmemBufBase(uint8_t* base)
{
  d_umemBufBase = base;
}

uint64_t XskWorker::frameOffset(const XskPacket& packet) const noexcept
{
  return packet.getFrameOffsetFrom(d_umemBufBase);
}

void XskWorker::notifyWorker() const
{
  notify(workerWaker);
}

bool XskWorker::hasIncomingFrames()
{
  if (d_type == Type::OutgoingOnly) {
    throw std::runtime_error("Looking for incoming packets in an outgoing-only XSK Worker");
  }

  return d_incomingPacketsQueue.read_available() != 0U;
}

void XskWorker::processIncomingFrames(const std::function<void(XskPacket packet)>& callback)
{
  if (d_type == Type::OutgoingOnly) {
    throw std::runtime_error("Looking for incoming packets in an outgoing-only XSK Worker");
  }

  d_incomingPacketsQueue.consume_all(callback);
}

void XskWorker::processOutgoingFrames(const std::function<void(XskPacket packet)>& callback)
{
  d_outgoingPacketsQueue.consume_all(callback);
}

void XskSocket::getMACFromIfName()
{
  ifreq ifr{};
  auto desc = FDWrapper(::socket(AF_INET, SOCK_DGRAM, 0));
  if (desc < 0) {
    throw std::runtime_error("Error creating a socket to get the MAC address of interface " + ifName);
  }

  if (ifName.size() >= IFNAMSIZ) {
    throw std::runtime_error("Unable to get MAC address for interface " + ifName + ": name too long");
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
  strncpy(ifr.ifr_name, ifName.c_str(), ifName.length() + 1);
  if (ioctl(desc.getHandle(), SIOCGIFHWADDR, &ifr) < 0 || ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
    throw std::runtime_error("Error getting MAC address for interface " + ifName);
  }
  static_assert(sizeof(ifr.ifr_hwaddr.sa_data) >= std::tuple_size<decltype(source)>{}, "The size of an ARPHRD_ETHER MAC address is smaller than expected");
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
  memcpy(source.data(), ifr.ifr_hwaddr.sa_data, source.size());
}

[[nodiscard]] int XskSocket::timeDifference(const timespec& lhs, const timespec& rhs) noexcept
{
  const auto res = lhs.tv_sec * 1000 + lhs.tv_nsec / 1000000L - (rhs.tv_sec * 1000 + rhs.tv_nsec / 1000000L);
  return static_cast<int>(res);
}

void XskWorker::cleanWorkerNotification() const noexcept
{
  uint64_t value = read(xskSocketWaker, &value, sizeof(value));
}

void XskWorker::cleanSocketNotification() const noexcept
{
  uint64_t value = read(workerWaker, &value, sizeof(value));
}

std::vector<pollfd> getPollFdsForWorker(XskWorker& info)
{
  std::vector<pollfd> fds;
  int timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
  if (timerfd < 0) {
    throw std::runtime_error("create_timerfd failed");
  }
  fds.push_back(pollfd{
    .fd = info.workerWaker,
    .events = POLLIN,
    .revents = 0,
  });
  fds.push_back(pollfd{
    .fd = timerfd,
    .events = POLLIN,
    .revents = 0,
  });
  return fds;
}

std::optional<XskPacket> XskWorker::getEmptyFrame()
{
  auto frames = d_sharedEmptyFrameOffset->lock();
  if (frames->empty()) {
    return std::nullopt;
  }
  auto offset = frames->back();
  frames->pop_back();
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  return XskPacket(offset + d_umemBufBase, 0, d_frameSize);
}

void XskWorker::markAsFree(const XskPacket& packet)
{
  auto offset = frameOffset(packet);
#ifdef DEBUG_UMEM
  checkUmemIntegrity(__PRETTY_FUNCTION__, __LINE__, d_sharedEmptyFrameOffset, offset, {UmemEntryStatus::Status::Received, UmemEntryStatus::Status::TXQueue}, UmemEntryStatus::Status::Free);
#endif /* DEBUG_UMEM */
  {
    auto frames = d_sharedEmptyFrameOffset->lock();
    frames->push_back(offset);
  }
}

uint32_t XskPacket::getFlags() const noexcept
{
  return flags;
}

void XskPacket::updatePacket() noexcept
{
  if ((flags & UPDATE) == 0U) {
    return;
  }
  if ((flags & REWRITE) == 0U) {
    changeDirectAndUpdateChecksum();
  }
}
#endif /* HAVE_XSK */
