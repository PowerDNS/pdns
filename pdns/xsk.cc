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
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
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

#ifdef DEBUG_UMEM
namespace {
struct UmemEntryStatus
{
  enum class Status: uint8_t { Free, FillQueue, Received, TXQueue };
  Status status{Status::Free};
};

LockGuarded<std::unordered_map<uint64_t, UmemEntryStatus>> s_umems;

void checkUmemIntegrity(const char* function, int line, uint64_t offset, const std::set<UmemEntryStatus::Status>& validStatuses, UmemEntryStatus::Status newStatus)
{
  auto umems = s_umems.lock();
  if (validStatuses.count(umems->at(offset).status) == 0) {
    std::cerr << "UMEM integrity check failed at " << function << ": " << line << ": status is " << static_cast<int>(umems->at(offset).status) << ", expected: ";
    for (const auto status : validStatuses) {
      std::cerr << static_cast<int>(status) << " ";
    }
    std::cerr << std::endl;
    abort();
  }
  (*umems)[offset].status = newStatus;
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
  timespec now;
  gettime(&now);
  const auto& firstTime = waitForDelay.top().getSendTime();
  const auto res = timeDifference(now, firstTime);
  if (res <= 0) {
    return 0;
  }
  return res;
}

XskSocket::XskSocket(size_t frameNum_, const std::string& ifName_, uint32_t queue_id, const std::string& xskMapPath, const std::string& poolName_) :
  frameNum(frameNum_), ifName(ifName_), poolName(poolName_), socket(nullptr, xsk_socket__delete), sharedEmptyFrameOffset(std::make_shared<LockGuarded<vector<uint64_t>>>())
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

  xsk_umem_config umemCfg;
  umemCfg.fill_size = fqCapacity;
  umemCfg.comp_size = cqCapacity;
  umemCfg.frame_size = frameSize;
  umemCfg.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;
  umemCfg.flags = 0;
  umem.umemInit(frameNum_ * frameSize, &cq, &fq, &umemCfg);

  {
    xsk_socket_config socketCfg;
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
    for (uint64_t i = 0; i < frameNum; i++) {
      //uniqueEmptyFrameOffset.push_back(i * frameSize);
      uniqueEmptyFrameOffset.push_back(i * frameSize + XDP_PACKET_HEADROOM);
#ifdef DEBUG_UMEM
      {
        auto umems = s_umems.lock();
        (*umems)[i * frameSize + XDP_PACKET_HEADROOM] = UmemEntryStatus();
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
  if (ret) {
    throw std::runtime_error("Error inserting into xsk_map '" + xskMapPath + "': " + std::to_string(ret));
  }
}

void XskSocket::fillFq(uint32_t fillSize) noexcept
{
  {
#warning why are we collecting frames from unique into shared here, even though we need unique ones?
    auto frames = sharedEmptyFrameOffset->lock();
    if (frames->size() < holdThreshold) {
      const auto moveSize = std::min(holdThreshold - frames->size(), uniqueEmptyFrameOffset.size());
      if (moveSize > 0) {
        frames->insert(frames->end(), std::make_move_iterator(uniqueEmptyFrameOffset.end() - moveSize), std::make_move_iterator(uniqueEmptyFrameOffset.end()));
        uniqueEmptyFrameOffset.resize(uniqueEmptyFrameOffset.size() - moveSize);
      }
    }
  }

  if (uniqueEmptyFrameOffset.size() < fillSize) {
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
    checkUmemIntegrity(__PRETTY_FUNCTION__, __LINE__, uniqueEmptyFrameOffset.back(), {UmemEntryStatus::Status::Free}, UmemEntryStatus::Status::FillQueue);
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

[[nodiscard]] int XskSocket::xskFd() const noexcept {
  return xsk_socket__fd(socket.get());
}

void XskSocket::send(std::vector<XskPacket>& packets)
{
  while (packets.size() > 0) {
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
      checkUmemIntegrity(__PRETTY_FUNCTION__, __LINE__, frameOffset(packet), {UmemEntryStatus::Status::Free, UmemEntryStatus::Status::Received}, UmemEntryStatus::Status::TXQueue);
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

  const auto baseAddr = reinterpret_cast<uint64_t>(umem.bufBase);
  uint32_t failed = 0;
  uint32_t processed = 0;
  res.reserve(recvSize);
  for (; processed < recvSize; processed++) {
    try {
      const auto* desc = xsk_ring_cons__rx_desc(&rx, idx++);
      XskPacket packet = XskPacket(reinterpret_cast<uint8_t*>(desc->addr + baseAddr), desc->len, frameSize);
#ifdef DEBUG_UMEM
      checkUmemIntegrity(__PRETTY_FUNCTION__, __LINE__, frameOffset(packet), {UmemEntryStatus::Status::Free, UmemEntryStatus::Status::FillQueue}, UmemEntryStatus::Status::Received);
#endif /* DEBUG_UMEM */

      if (!packet.parse(false)) {
        ++failed;
        markAsFree(std::move(packet));
      }
      else {
        res.push_back(std::move(packet));
      }
    }
    catch (const std::exception& exp) {
      std::cerr << "Exception while processing the XSK RX queue: " << exp.what() << std::endl;
      break;
    }
    catch (...) {
      std::cerr << "Exception while processing the XSK RX queue" << std::endl;
      break;
    }
  }

  // this releases the descriptor, but not the packet (umem entries)
  // which will only be made available again when pushed into the fill
  // queue
  xsk_ring_cons__release(&rx, processed);
  if (failedCount) {
    *failedCount = failed;
  }

  return res;
}

void XskSocket::pickUpReadyPacket(std::vector<XskPacket>& packets)
{
  timespec now;
  gettime(&now);
  while (!waitForDelay.empty() && timeDifference(now, waitForDelay.top().getSendTime()) <= 0) {
    auto& top = const_cast<XskPacket&>(waitForDelay.top());
    packets.push_back(std::move(top));
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
    checkUmemIntegrity(__PRETTY_FUNCTION__, __LINE__, uniqueEmptyFrameOffset.back(), {UmemEntryStatus::Status::Received, UmemEntryStatus::Status::TXQueue}, UmemEntryStatus::Status::Free);
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
  struct xdp_statistics stats;
  socklen_t optlen = sizeof(stats);
  int err = getsockopt(xskFd(), SOL_XDP, XDP_STATISTICS, &stats, &optlen);
  if (err) {
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

void XskSocket::markAsFree(XskPacket&& packet)
{
  auto offset = frameOffset(packet);
#ifdef DEBUG_UMEM
  checkUmemIntegrity(__PRETTY_FUNCTION__, __LINE__, offset, {UmemEntryStatus::Status::Received, UmemEntryStatus::Status::TXQueue}, UmemEntryStatus::Status::Free);
#endif /* DEBUG_UMEM */

  uniqueEmptyFrameOffset.push_back(offset);
}

XskSocket::XskUmem::~XskUmem()
{
  if (umem) {
    xsk_umem__delete(umem);
  }
  if (bufBase) {
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
  assert(frameLength >= sizeof(ethHeader));
  memcpy(&ethHeader, frame, sizeof(ethHeader));
  return ethHeader;
}

void XskPacket::setEthernetHeader(const ethhdr& ethHeader) noexcept
{
  assert(frameLength >= sizeof(ethHeader));
  memcpy(frame, &ethHeader, sizeof(ethHeader));
}

[[nodiscard]] iphdr XskPacket::getIPv4Header() const noexcept
{
  iphdr ipv4Header{};
  assert(frameLength >= (sizeof(ethhdr) + sizeof(ipv4Header)));
  assert(!v6);
  memcpy(&ipv4Header, frame + sizeof(ethhdr), sizeof(ipv4Header));
  return ipv4Header;
}

void XskPacket::setIPv4Header(const iphdr& ipv4Header) noexcept
{
  assert(frameLength >= (sizeof(ethhdr) + sizeof(iphdr)));
  assert(!v6);
  memcpy(frame + sizeof(ethhdr), &ipv4Header, sizeof(ipv4Header));
}

[[nodiscard]] ipv6hdr XskPacket::getIPv6Header() const noexcept
{
  ipv6hdr ipv6Header{};
  assert(frameLength >= (sizeof(ethhdr) + sizeof(ipv6Header)));
  assert(v6);
  memcpy(&ipv6Header, frame + sizeof(ethhdr), sizeof(ipv6Header));
  return ipv6Header;
}

void XskPacket::setIPv6Header(const ipv6hdr& ipv6Header) noexcept
{
  assert(frameLength >= (sizeof(ethhdr) + sizeof(ipv6Header)));
  assert(v6);
  memcpy(frame + sizeof(ethhdr), &ipv6Header, sizeof(ipv6Header));
}

[[nodiscard]] udphdr XskPacket::getUDPHeader() const noexcept
{
  udphdr udpHeader{};
  assert(frameLength >= (sizeof(ethhdr) + (v6 ? sizeof(ipv6hdr) : sizeof(iphdr)) + sizeof(udpHeader)));
  memcpy(&udpHeader, frame + getL4HeaderOffset(), sizeof(udpHeader));
  return udpHeader;
}

void XskPacket::setUDPHeader(const udphdr& udpHeader) noexcept
{
  assert(frameLength >= (sizeof(ethhdr) + (v6 ? sizeof(ipv6hdr) : sizeof(iphdr)) + sizeof(udpHeader)));
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
    from = makeComboAddressFromRaw(4, reinterpret_cast<const char*>(&ipHeader.saddr), sizeof(ipHeader.saddr));
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
    from = makeComboAddressFromRaw(6, reinterpret_cast<const char*>(&ipHeader.saddr), sizeof(ipHeader.saddr));
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
  return frameSize;
}

void XskPacket::changeDirectAndUpdateChecksum() noexcept
{
  auto ethHeader = getEthernetHeader();
  {
    uint8_t tmp[ETH_ALEN];
    static_assert(sizeof(tmp) == sizeof(ethHeader.h_dest), "Size Error");
    static_assert(sizeof(tmp) == sizeof(ethHeader.h_source), "Size Error");
    memcpy(tmp, ethHeader.h_dest, sizeof(tmp));
    memcpy(ethHeader.h_dest, ethHeader.h_source, sizeof(tmp));
    memcpy(ethHeader.h_source, tmp, sizeof(tmp));
  }
  if (ethHeader.h_proto == htons(ETH_P_IPV6)) {
    // IPV6
    auto ipv6 = getIPv6Header();
    std::swap(ipv6.daddr, ipv6.saddr);
    assert(ipv6.nexthdr == IPPROTO_UDP);

    auto udp = getUDPHeader();
    std::swap(udp.dest, udp.source);
    udp.len = htons(getDataSize() + sizeof(udp));
    udp.check = 0;
    /* needed to get the correct checksum */
    setIPv6Header(ipv6);
    setUDPHeader(udp);
    udp.check = tcp_udp_v6_checksum(&ipv6);
    rewriteIpv6Header(&ipv6, getFrameLen());
    setIPv6Header(ipv6);
    setUDPHeader(udp);
  }
  else {
    // IPV4
    auto ipv4 = getIPv4Header();
    std::swap(ipv4.daddr, ipv4.saddr);
    assert(ipv4.protocol == IPPROTO_UDP);

    auto udp = getUDPHeader();
    std::swap(udp.dest, udp.source);
    udp.len = htons(getDataSize() + sizeof(udp));
    udp.check = 0;
    /* needed to get the correct checksum */
    setIPv4Header(ipv4);
    setUDPHeader(udp);
    udp.check = tcp_udp_v4_checksum(&ipv4);
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

XskPacket::XskPacket(uint8_t* frame_, size_t dataSize, size_t frameSize) :
  frame(frame_), frameLength(dataSize), frameSize(frameSize - XDP_PACKET_HEADROOM)
{
}

PacketBuffer XskPacket::clonePacketBuffer() const
{
  const auto size = getDataSize();
  PacketBuffer tmp(size);
  memcpy(tmp.data(), frame + getDataOffset(), size);
  return tmp;
}

void XskPacket::cloneIntoPacketBuffer(PacketBuffer& buffer) const
{
  const auto size = getDataSize();
  buffer.resize(size);
  memcpy(buffer.data(), frame + getDataOffset(), size);
}

bool XskPacket::setPayload(const PacketBuffer& buf)
{
  const auto bufSize = buf.size();
  const auto currentCapacity = getCapacity();
  if (bufSize == 0 || bufSize > currentCapacity) {
    return false;
  }
  flags |= UPDATE;
  memcpy(frame + getDataOffset(), buf.data(), bufSize);
  frameLength = getDataOffset() + bufSize;
  return true;
}

void XskPacket::addDelay(const int relativeMilliseconds) noexcept
{
  gettime(&sendTime);
  sendTime.tv_nsec += static_cast<uint64_t>(relativeMilliseconds) * 1000000L;
  sendTime.tv_sec += sendTime.tv_nsec / 1000000000L;
  sendTime.tv_nsec %= 1000000000L;
}

bool operator<(const XskPacket& s1, const XskPacket& s2) noexcept
{
  return s1.getSendTime() < s2.getSendTime();
}

const ComboAddress& XskPacket::getFromAddr() const noexcept
{
  return from;
}

const ComboAddress& XskPacket::getToAddr() const noexcept
{
  return to;
}

void XskWorker::notify(int fd)
{
  uint64_t value = 1;
  ssize_t res = 0;
  while ((res = write(fd, &value, sizeof(value))) == EINTR) {
  }
  if (res != sizeof(value)) {
    throw runtime_error("Unable Wake Up XskSocket Failed");
  }
}

XskWorker::XskWorker() :
  workerWaker(createEventfd()), xskSocketWaker(createEventfd())
{
}

void XskWorker::pushToProcessingQueue(XskPacket&& packet)
{
#if defined(__SANITIZE_THREAD__)
  if (!incomingPacketsQueue.lock()->push(std::move(packet))) {
#else
  if (!incomingPacketsQueue.push(std::move(packet))) {
#endif
    markAsFree(std::move(packet));
  }
}

void XskWorker::pushToSendQueue(XskPacket&& packet)
{
#if defined(__SANITIZE_THREAD__)
  if (!outgoingPacketsQueue.lock()->push(std::move(packet))) {
#else
  if (!outgoingPacketsQueue.push(std::move(packet))) {
#endif
    markAsFree(std::move(packet));
  }
}

const void* XskPacket::getPayloadData() const
{
  return frame + getDataOffset();
}

void XskPacket::setAddr(const ComboAddress& from_, MACAddr fromMAC, const ComboAddress& to_, MACAddr toMAC) noexcept
{
  auto ethHeader = getEthernetHeader();
  memcpy(ethHeader.h_dest, &toMAC[0], sizeof(MACAddr));
  memcpy(ethHeader.h_source, &fromMAC[0], sizeof(MACAddr));
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

    auto udpHeader = getUDPHeader();
    ipHeader.protocol = IPPROTO_UDP;
    udpHeader.source = from.sin4.sin_port;
    udpHeader.dest = to.sin4.sin_port;
    udpHeader.len = htons(getDataSize());
    udpHeader.check = 0;
    /* needed to get the correct checksum */
    setIPv4Header(ipHeader);
    setUDPHeader(udpHeader);
    udpHeader.check = tcp_udp_v4_checksum(&ipHeader);
    rewriteIpv4Header(&ipHeader, getFrameLen());
    setIPv4Header(ipHeader);
    setUDPHeader(udpHeader);
  }
  else {
    ethHeader.h_proto = htons(ETH_P_IPV6);

    auto ipHeader = getIPv6Header();
    memcpy(&ipHeader.daddr, &to.sin6.sin6_addr, sizeof(ipHeader.daddr));
    memcpy(&ipHeader.saddr, &from.sin6.sin6_addr, sizeof(ipHeader.saddr));

    auto udpHeader = getUDPHeader();
    ipHeader.nexthdr = IPPROTO_UDP;
    udpHeader.source = from.sin6.sin6_port;
    udpHeader.dest = to.sin6.sin6_port;
    udpHeader.len = htons(getDataSize());
    udpHeader.check = 0;
    /* needed to get the correct checksum */
    setIPv6Header(ipHeader);
    setUDPHeader(udpHeader);
    udpHeader.check = tcp_udp_v6_checksum(&ipHeader);
    setIPv6Header(ipHeader);
    setUDPHeader(udpHeader);
  }

  setEthernetHeader(ethHeader);
}

[[nodiscard]] __be16 XskPacket::ipv4Checksum(const struct iphdr* ip) noexcept
{
  auto partial = ip_checksum_partial(ip, sizeof(iphdr), 0);
  return ip_checksum_fold(partial);
}

[[nodiscard]] __be16 XskPacket::tcp_udp_v4_checksum(const struct iphdr* ip) const noexcept
{
  // ip options is not supported !!!
  const auto l4Length = static_cast<uint16_t>(getDataSize() + sizeof(udphdr));
  auto sum = tcp_udp_v4_header_checksum_partial(ip->saddr, ip->daddr, ip->protocol, l4Length);
  sum = ip_checksum_partial(frame + getL4HeaderOffset(), l4Length, sum);
  return ip_checksum_fold(sum);
}

[[nodiscard]] __be16 XskPacket::tcp_udp_v6_checksum(const struct ipv6hdr* ipv6) const noexcept
{
  const auto l4Length = static_cast<uint16_t>(getDataSize() + sizeof(udphdr));
  uint64_t sum = tcp_udp_v6_header_checksum_partial(&ipv6->saddr, &ipv6->daddr, ipv6->nexthdr, l4Length);
  sum = ip_checksum_partial(frame + getL4HeaderOffset(), l4Length, sum);
  return ip_checksum_fold(sum);
}

[[nodiscard]] uint64_t XskPacket::ip_checksum_partial(const void* ptr, const size_t len, uint64_t sum) noexcept
{
  size_t position{0};
  /* Main loop: 32 bits at a time */
  for (position = 0; position < len; position += sizeof(uint32_t)) {
    uint32_t value{};
    memcpy(&value, reinterpret_cast<const uint8_t*>(ptr) + position, sizeof(value));
    sum += value;
  }

  /* Handle un-32bit-aligned trailing bytes */
  if ((len - position) >= 2) {
    uint16_t value{};
    memcpy(&value, reinterpret_cast<const uint8_t*>(ptr) + position, sizeof(value));
    sum += value;
    position += sizeof(value);
  }

  if ((len - position) > 0) {
    const auto* p8 = static_cast<const uint8_t*>(ptr) + position;
    sum += ntohs(*p8 << 8); /* RFC says pad last byte */
  }

  return sum;
}

[[nodiscard]] __be16 XskPacket::ip_checksum_fold(uint64_t sum) noexcept
{
  while (sum & ~0xffffffffULL) {
    sum = (sum >> 32) + (sum & 0xffffffffULL);
  }
  while (sum & 0xffff0000ULL) {
    sum = (sum >> 16) + (sum & 0xffffULL);
  }

  return static_cast<__be16>(~sum);
}

#ifndef __packed
#define __packed __attribute__((packed))
#endif

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
      header __packed fields;
      uint32_t words[3];
    };
  };
  struct ipv4_pseudo_header_t pseudo_header;
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
    __uint8_t mbz[3];
    __uint8_t next_header;
  };
  /* The IPv6 pseudo-header is defined in RFC 2460, Section 8.1. */
  struct ipv6_pseudo_header_t
  {
    /* We use a union here to avoid aliasing issues with gcc -O2 */
    union
    {
      header __packed fields;
      uint32_t words[10];
    };
  };
  struct ipv6_pseudo_header_t pseudo_header;
  static_assert(sizeof(pseudo_header) == 40, "IPv6 pseudo-header size is incorrect");

  /* Fill in the pseudo-header. */
  pseudo_header.fields.src_ip = *src_ip;
  pseudo_header.fields.dst_ip = *dst_ip;
  pseudo_header.fields.length = htonl(len);
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

PacketBuffer XskPacket::cloneHeadertoPacketBuffer() const
{
  const auto size = getFrameLen() - getDataSize();
  PacketBuffer tmp(size);
  memcpy(tmp.data(), frame, size);
  return tmp;
}

int XskWorker::createEventfd()
{
  auto fd = ::eventfd(0, EFD_CLOEXEC);
  if (fd < 0) {
    throw runtime_error("Unable create eventfd");
  }
  return fd;
}

void XskWorker::waitForXskSocket() noexcept
{
  uint64_t x = read(workerWaker, &x, sizeof(x));
}

void XskWorker::notifyXskSocket() noexcept
{
  notify(xskSocketWaker);
}

std::shared_ptr<XskWorker> XskWorker::create()
{
  return std::make_shared<XskWorker>();
}

void XskSocket::addWorker(std::shared_ptr<XskWorker> s, const ComboAddress& dest)
{
  extern std::atomic<bool> g_configurationDone;
  if (g_configurationDone) {
    throw runtime_error("Adding a server with xsk at runtime is not supported");
  }
  s->poolName = poolName;
  const auto socketWaker = s->xskSocketWaker.getHandle();
  const auto workerWaker = s->workerWaker.getHandle();
  const auto& socketWakerIdx = workers.get<0>();
  if (socketWakerIdx.contains(socketWaker)) {
    throw runtime_error("Server already exist");
  }
  s->umemBufBase = umem.bufBase;
  workers.insert(XskRouteInfo{
    .worker = std::move(s),
    .dest = dest,
    .xskSocketWaker = socketWaker,
    .workerWaker = workerWaker,
  });
  fds.push_back(pollfd{
    .fd = socketWaker,
    .events = POLLIN,
    .revents = 0});
};

uint64_t XskWorker::frameOffset(const XskPacket& packet) const noexcept
{
  return packet.getFrameOffsetFrom(umemBufBase);
}

void XskWorker::notifyWorker() noexcept
{
  notify(workerWaker);
}

void XskSocket::getMACFromIfName()
{
  ifreq ifr{};
  auto fd = FDWrapper(::socket(AF_INET, SOCK_DGRAM, 0));
  if (fd < 0) {
    throw std::runtime_error("Error creating a socket to get the MAC address of interface " + ifName);
  }

  if (ifName.size() >= IFNAMSIZ) {
    throw std::runtime_error("Unable to get MAC address for interface " + ifName + ": name too long");
  }

  strncpy(ifr.ifr_name, ifName.c_str(), ifName.length() + 1);
  if (ioctl(fd.getHandle(), SIOCGIFHWADDR, &ifr) < 0 || ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
    throw std::runtime_error("Error getting MAC address for interface " + ifName);
  }
  static_assert(sizeof(ifr.ifr_hwaddr.sa_data) >= std::tuple_size<decltype(source)>{}, "The size of an ARPHRD_ETHER MAC address is smaller than expected");
  memcpy(source.data(), ifr.ifr_hwaddr.sa_data, source.size());
}

[[nodiscard]] int XskSocket::timeDifference(const timespec& t1, const timespec& t2) noexcept
{
  const auto res = t1.tv_sec * 1000 + t1.tv_nsec / 1000000L - (t2.tv_sec * 1000 + t2.tv_nsec / 1000000L);
  return static_cast<int>(res);
}

void XskWorker::cleanWorkerNotification() noexcept
{
  uint64_t x = read(xskSocketWaker, &x, sizeof(x));
}

void XskWorker::cleanSocketNotification() noexcept
{
  uint64_t x = read(workerWaker, &x, sizeof(x));
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

void XskWorker::fillUniqueEmptyOffset()
{
  auto frames = sharedEmptyFrameOffset->lock();
  const auto moveSize = std::min(static_cast<size_t>(32), frames->size());
  if (moveSize > 0) {
    uniqueEmptyFrameOffset.insert(uniqueEmptyFrameOffset.end(), std::make_move_iterator(frames->end() - moveSize), std::make_move_iterator(frames->end()));
    frames->resize(frames->size() - moveSize);
  }
}

std::optional<XskPacket> XskWorker::getEmptyFrame()
{
  if (!uniqueEmptyFrameOffset.empty()) {
    auto offset = uniqueEmptyFrameOffset.back();
    uniqueEmptyFrameOffset.pop_back();
    return XskPacket(offset + umemBufBase, 0, frameSize);
  }
  fillUniqueEmptyOffset();
  if (!uniqueEmptyFrameOffset.empty()) {
    auto offset = uniqueEmptyFrameOffset.back();
    uniqueEmptyFrameOffset.pop_back();
    return XskPacket(offset + umemBufBase, 0, frameSize);
  }
  return std::nullopt;
}

void XskWorker::markAsFree(XskPacket&& packet)
{
  auto offset = frameOffset(packet);
#ifdef DEBUG_UMEM
  checkUmemIntegrity(__PRETTY_FUNCTION__, __LINE__, offset, {UmemEntryStatus::Status::Received, UmemEntryStatus::Status::TXQueue}, UmemEntryStatus::Status::Free);
#endif /* DEBUG_UMEM */
  uniqueEmptyFrameOffset.push_back(offset);
}

uint32_t XskPacket::getFlags() const noexcept
{
  return flags;
}

void XskPacket::updatePacket() noexcept
{
  if (!(flags & UPDATE)) {
    return;
  }
  if (!(flags & REWRITE)) {
    changeDirectAndUpdateChecksum();
  }
}
#endif /* HAVE_XSK */
