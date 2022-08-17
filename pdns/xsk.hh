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
#include "iputils.hh"
#include "misc.hh"
#include "noinitvector.hh"
#include "lock.hh"

#include <array>
#include <bits/types/struct_timespec.h>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/indexed_by.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <cstdint>
#include <cstring>
#include <linux/types.h>
#include <memory>
#include <queue>
#include <stdexcept>
#include <string>
#include <sys/poll.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#ifdef HAVE_XSK
#include <xdp/xsk.h>
#endif /* HAVE_XSK */

class XskPacket;
class XskWorker;
class XskSocket;

#ifdef HAVE_XSK
using XskPacketPtr = std::unique_ptr<XskPacket>;

// We use an XskSocket to manage an AF_XDP Socket corresponding to a NIC queue.
// The XDP program running in the kernel redirects the data to the XskSocket in userspace.
// XskSocket routes packets to multiple worker threads registered on XskSocket via XskSocket::addWorker based on the destination port number of the packet.
// The kernel and the worker thread holding XskWorker will wake up the XskSocket through XskFd and the Eventfd corresponding to each worker thread, respectively.
class XskSocket
{
  struct XskRouteInfo
  {
    std::shared_ptr<XskWorker> worker;
    ComboAddress dest;
    int xskSocketWaker;
    int workerWaker;
  };
  struct XskUmem
  {
    xsk_umem* umem{nullptr};
    uint8_t* bufBase{nullptr};
    size_t size;
    void umemInit(size_t memSize, xsk_ring_cons* cq, xsk_ring_prod* fq, xsk_umem_config* config);
    ~XskUmem();
    XskUmem() = default;
  };
  boost::multi_index_container<
    XskRouteInfo,
    boost::multi_index::indexed_by<
      boost::multi_index::hashed_unique<boost::multi_index::member<XskRouteInfo, int, &XskRouteInfo::xskSocketWaker>>,
      boost::multi_index::hashed_unique<boost::multi_index::member<XskRouteInfo, ComboAddress, &XskRouteInfo::dest>, ComboAddress::addressPortOnlyHash>>>
    workers;
  static constexpr size_t holdThreshold = 256;
  static constexpr size_t fillThreshold = 128;
  static constexpr size_t frameSize = 2048;
  const size_t frameNum;
  const uint32_t queueId;
  std::priority_queue<XskPacketPtr> waitForDelay;
  const std::string ifName;
  const std::string poolName;
  vector<pollfd> fds;
  vector<uint64_t> uniqueEmptyFrameOffset;
  xsk_ring_cons cq;
  xsk_ring_cons rx;
  xsk_ring_prod fq;
  xsk_ring_prod tx;
  std::unique_ptr<xsk_socket, void (*)(xsk_socket*)> socket;
  XskUmem umem;
  bpf_object* prog;

  static constexpr uint32_t fqCapacity = XSK_RING_PROD__DEFAULT_NUM_DESCS * 4;
  static constexpr uint32_t cqCapacity = XSK_RING_CONS__DEFAULT_NUM_DESCS * 4;
  static constexpr uint32_t rxCapacity = XSK_RING_CONS__DEFAULT_NUM_DESCS * 2;
  static constexpr uint32_t txCapacity = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;

  constexpr static bool isPowOfTwo(uint32_t value) noexcept;
  [[nodiscard]] static int timeDifference(const timespec& t1, const timespec& t2) noexcept;
  friend void XskRouter(std::shared_ptr<XskSocket> xsk);

  [[nodiscard]] uint64_t frameOffset(const XskPacket& packet) const noexcept;
  int firstTimeout();
  void fillFq(uint32_t fillSize = fillThreshold) noexcept;
  void recycle(size_t size) noexcept;
  void getMACFromIfName();
  void pickUpReadyPacket(std::vector<XskPacketPtr>& packets);

public:
  std::shared_ptr<LockGuarded<vector<uint64_t>>> sharedEmptyFrameOffset;
  XskSocket(size_t frameNum, const std::string& ifName, uint32_t queue_id, const std::string& xskMapPath, const std::string& poolName_);
  MACAddr source;
  [[nodiscard]] int xskFd() const noexcept;
  int wait(int timeout);
  void send(std::vector<XskPacketPtr>& packets);
  std::vector<XskPacketPtr> recv(uint32_t recvSizeMax, uint32_t* failedCount);
  void addWorker(std::shared_ptr<XskWorker> s, const ComboAddress& dest, bool isTCP);
};
class XskPacket
{
public:
  enum Flags : uint32_t
  {
    TCP = 1 << 0,
    UPDATE = 1 << 1,
    DELAY = 1 << 3,
    REWRITE = 1 << 4
  };

private:
  ComboAddress from;
  ComboAddress to;
  timespec sendTime;
  uint8_t* frame;
  uint8_t* l4Header;
  uint8_t* payload;
  uint8_t* payloadEnd;
  uint8_t* frameEnd;
  uint32_t flags{0};

  friend XskSocket;
  friend XskWorker;
  friend bool operator<(const XskPacketPtr& s1, const XskPacketPtr& s2) noexcept;

  constexpr static uint8_t DefaultTTL = 64;
  bool parse();
  void changeDirectAndUpdateChecksum() noexcept;

  // You must set ipHeader.check = 0 before call this method
  [[nodiscard]] __be16 ipv4Checksum() const noexcept;
  // You must set l4Header.check = 0 before call this method
  // ip options is not supported
  [[nodiscard]] __be16 tcp_udp_v4_checksum() const noexcept;
  // You must set l4Header.check = 0 before call this method
  [[nodiscard]] __be16 tcp_udp_v6_checksum() const noexcept;
  [[nodiscard]] static uint64_t ip_checksum_partial(const void* p, size_t len, uint64_t sum) noexcept;
  [[nodiscard]] static __be16 ip_checksum_fold(uint64_t sum) noexcept;
  [[nodiscard]] static uint64_t tcp_udp_v4_header_checksum_partial(__be32 src_ip, __be32 dst_ip, uint8_t protocol, uint16_t len) noexcept;
  [[nodiscard]] static uint64_t tcp_udp_v6_header_checksum_partial(const struct in6_addr* src_ip, const struct in6_addr* dst_ip, uint8_t protocol, uint32_t len) noexcept;
  void rewriteIpv4Header(void* ipv4header) noexcept;
  void rewriteIpv6Header(void* ipv6header) noexcept;

public:
  [[nodiscard]] const ComboAddress& getFromAddr() const noexcept;
  [[nodiscard]] const ComboAddress& getToAddr() const noexcept;
  [[nodiscard]] const void* payloadData() const;
  [[nodiscard]] bool isIPV6() const noexcept;
  [[nodiscard]] size_t capacity() const noexcept;
  [[nodiscard]] uint32_t dataLen() const noexcept;
  [[nodiscard]] uint32_t FrameLen() const noexcept;
  [[nodiscard]] PacketBuffer clonePacketBuffer() const;
  void cloneIntoPacketBuffer(PacketBuffer& buffer) const;
  [[nodiscard]] std::unique_ptr<PacketBuffer> cloneHeadertoPacketBuffer() const;
  [[nodiscard]] void* payloadData();
  void setAddr(const ComboAddress& from_, MACAddr fromMAC, const ComboAddress& to_, MACAddr toMAC, bool tcp = false) noexcept;
  bool setPayload(const PacketBuffer& buf);
  void rewrite() noexcept;
  void setHeader(const PacketBuffer& buf) noexcept;
  XskPacket() = default;
  XskPacket(void* frame, size_t dataSize, size_t frameSize);
  void addDelay(int relativeMilliseconds) noexcept;
  void updatePacket() noexcept;
  [[nodiscard]] uint32_t getFlags() const noexcept;
};
bool operator<(const XskPacketPtr& s1, const XskPacketPtr& s2) noexcept;

// XskWorker obtains XskPackets of specific ports in the NIC from XskSocket through cq.
// After finishing processing the packet, XskWorker puts the packet into sq so that XskSocket decides whether to send it through the network card according to XskPacket::flags.
// XskWorker wakes up XskSocket via xskSocketWaker after putting the packets in sq.
class XskWorker
{
  using XskPacketRing = boost::lockfree::spsc_queue<XskPacket*, boost::lockfree::capacity<512>>;

public:
  uint8_t* umemBufBase;
  std::shared_ptr<LockGuarded<vector<uint64_t>>> sharedEmptyFrameOffset;
  vector<uint64_t> uniqueEmptyFrameOffset;
  XskPacketRing cq;
  XskPacketRing sq;
  std::string poolName;
  size_t frameSize;
  FDWrapper workerWaker;
  FDWrapper xskSocketWaker;

  XskWorker();
  static int createEventfd();
  static void notify(int fd);
  static std::shared_ptr<XskWorker> create();
  void notifyWorker() noexcept;
  void notifyXskSocket() noexcept;
  void waitForXskSocket() noexcept;
  void cleanWorkerNotification() noexcept;
  void cleanSocketNotification() noexcept;
  [[nodiscard]] uint64_t frameOffset(const XskPacket& s) const noexcept;
  void fillUniqueEmptyOffset();
  void* getEmptyframe();
};
std::vector<pollfd> getPollFdsForWorker(XskWorker& info);
#else
class XskSocket
{
};
class XskPacket
{
};
class XskWorker
{
};

#endif /* HAVE_XSK */
