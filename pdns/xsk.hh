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

#ifdef HAVE_XSK
#include <array>
#include <bits/types/struct_timespec.h>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <memory>
#include <poll.h>
#include <queue>
#include <stdexcept>
#include <string>
//#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/udp.h>

#include <xdp/xsk.h>

#include "iputils.hh"
#include "lock.hh"
#include "misc.hh"
#include "noinitvector.hh"
#endif /* HAVE_XSK */

class XskPacket;
class XskWorker;
class XskSocket;

using MACAddr = std::array<uint8_t,6>;

#ifdef HAVE_XSK
using XskPacketPtr = std::unique_ptr<XskPacket>;

// We use an XskSocket to manage an AF_XDP Socket corresponding to a NIC queue.
// The XDP program running in the kernel redirects the data to the XskSocket in userspace.
// We allocate frames that are placed into the descriptors in the fill queue, allowing the kernel to put incoming packets into the frames and place descriptors into the rx queue.
// Once we have read the descriptors from the rx queue we release them, but we own the frames.
// After we are done with the frame, we place them into descriptors of either the fill queue (empty frames) or tx queues (packets to be sent).
// Once the kernel is done, it places descriptors referencing these frames into the cq where we can recycle them (packets destined to the tx queue or empty frame to the fill queue queue).

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
    size_t size{0};
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
  // number of frames to keep in sharedEmptyFrameOffset
  static constexpr size_t holdThreshold = 256;
  // number of frames to insert into the fill queue
  static constexpr size_t fillThreshold = 128;
  static constexpr size_t frameSize = 2048;
  // number of entries (frames) in the umem
  const size_t frameNum;
  // ID of the network queue
  const uint32_t queueId;
  // responses that have been delayed
  std::priority_queue<XskPacketPtr> waitForDelay;
  const std::string ifName;
  const std::string poolName;
  // AF_XDP socket then worker waker sockets
  vector<pollfd> fds;
  // list of frames, aka (indexes of) umem entries that can be reused to fill fq,
  // collected from packets that we could not route (unknown destination),
  // could not parse, were dropped during processing (!UPDATE), or
  // simply recycled from cq after being processed by the kernel
  vector<uint64_t> uniqueEmptyFrameOffset;
  // completion ring: queue where sent packets are stored by the kernel
  xsk_ring_cons cq;
  // rx ring: queue where the incoming packets are stored, read by XskRouter
  xsk_ring_cons rx;
  // fill ring: queue where umem entries available to be filled (put into rx) are stored
  xsk_ring_prod fq;
  // tx ring: queue where outgoing packets are stored
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
  [[nodiscard]] int firstTimeout();
  // pick ups available frames from uniqueEmptyFrameOffset
  // insert entries from uniqueEmptyFrameOffset into fq
  void fillFq(uint32_t fillSize = fillThreshold) noexcept;
  // picks up entries that have been processed (sent) from cq and push them into uniqueEmptyFrameOffset
  void recycle(size_t size) noexcept;
  void getMACFromIfName();
  // look at delayed packets, and send the ones that are ready
  void pickUpReadyPacket(std::vector<XskPacketPtr>& packets);

public:
  static constexpr size_t getFrameSize()
  {
    return frameSize;
  }
  // list of free umem entries that can be reused
  std::shared_ptr<LockGuarded<vector<uint64_t>>> sharedEmptyFrameOffset;
  XskSocket(size_t frameNum, const std::string& ifName, uint32_t queue_id, const std::string& xskMapPath, const std::string& poolName_);
  MACAddr source;
  [[nodiscard]] int xskFd() const noexcept;
  // wait until one event has occurred
  [[nodiscard]] int wait(int timeout);
  // add as many packets as possible to the rx queue for sending */
  void send(std::vector<XskPacketPtr>& packets);
  // look at incoming packets in rx, return them if parsing succeeeded
  [[nodiscard]] std::vector<XskPacketPtr> recv(uint32_t recvSizeMax, uint32_t* failedCount);
  void addWorker(std::shared_ptr<XskWorker> s, const ComboAddress& dest);
  [[nodiscard]] std::string getMetrics() const;
  void markAsFree(XskPacketPtr&& packet);
};

struct iphdr;
struct ipv6hdr;

class XskPacket
{
public:
  enum Flags : uint32_t
  {
    UPDATE = 1 << 0,
    DELAY = 1 << 1,
    REWRITE = 1 << 2
  };

private:
  ComboAddress from;
  ComboAddress to;
  timespec sendTime;
  uint8_t* frame{nullptr};
  size_t frameLength{0};
  size_t frameSize{0};
  uint32_t flags{0};
  bool v6{false};

  // You must set ipHeader.check = 0 before calling this method
  [[nodiscard]] static __be16 ipv4Checksum(const struct iphdr*) noexcept;
  [[nodiscard]] static uint64_t ip_checksum_partial(const void* p, size_t len, uint64_t sum) noexcept;
  [[nodiscard]] static __be16 ip_checksum_fold(uint64_t sum) noexcept;
  [[nodiscard]] static uint64_t tcp_udp_v4_header_checksum_partial(__be32 src_ip, __be32 dst_ip, uint8_t protocol, uint16_t len) noexcept;
  [[nodiscard]] static uint64_t tcp_udp_v6_header_checksum_partial(const struct in6_addr* src_ip, const struct in6_addr* dst_ip, uint8_t protocol, uint32_t len) noexcept;
  static void rewriteIpv4Header(struct iphdr* ipv4header, size_t frameLen) noexcept;
  static void rewriteIpv6Header(struct ipv6hdr* ipv6header, size_t frameLen) noexcept;

  // You must set l4Header.check = 0 before calling this method
  // ip options is not supported
  [[nodiscard]] __be16 tcp_udp_v4_checksum(const struct iphdr*) const noexcept;
  // You must set l4Header.check = 0 before calling this method
  [[nodiscard]] __be16 tcp_udp_v6_checksum(const struct ipv6hdr*) const noexcept;
    /* offset of the L4 (udphdr) header (after ethhdr and iphdr/ipv6hdr) */
  [[nodiscard]] size_t getL4HeaderOffset() const noexcept;
  /* offset of the data after the UDP header */
  [[nodiscard]] size_t getDataOffset() const noexcept;
  [[nodiscard]] size_t getDataSize() const noexcept;
  [[nodiscard]] ethhdr getEthernetHeader() const noexcept;
  void setEthernetHeader(const ethhdr& ethHeader) noexcept;
  [[nodiscard]] iphdr getIPv4Header() const noexcept;
  void setIPv4Header(const iphdr& ipv4Header) noexcept;
  [[nodiscard]] ipv6hdr getIPv6Header() const noexcept;
  void setIPv6Header(const ipv6hdr& ipv6Header) noexcept;
  [[nodiscard]] udphdr getUDPHeader() const noexcept;
  void setUDPHeader(const udphdr& udpHeader) noexcept;
  // parse IP and UDP payloads
  bool parse(bool fromSetHeader);
  void changeDirectAndUpdateChecksum() noexcept;

  friend XskSocket;
  friend XskWorker;
  friend bool operator<(const XskPacketPtr& s1, const XskPacketPtr& s2) noexcept;

  constexpr static uint8_t DefaultTTL = 64;

public:
  [[nodiscard]] const ComboAddress& getFromAddr() const noexcept;
  [[nodiscard]] const ComboAddress& getToAddr() const noexcept;
  [[nodiscard]] const void* getPayloadData() const;
  [[nodiscard]] bool isIPV6() const noexcept;
  [[nodiscard]] size_t getCapacity() const noexcept;
  [[nodiscard]] uint32_t getDataLen() const noexcept;
  [[nodiscard]] uint32_t getFrameLen() const noexcept;
  [[nodiscard]] PacketBuffer clonePacketBuffer() const;
  void cloneIntoPacketBuffer(PacketBuffer& buffer) const;
  [[nodiscard]] std::unique_ptr<PacketBuffer> cloneHeadertoPacketBuffer() const;
  void setAddr(const ComboAddress& from_, MACAddr fromMAC, const ComboAddress& to_, MACAddr toMAC) noexcept;
  bool setPayload(const PacketBuffer& buf);
  void rewrite() noexcept;
  void setHeader(const PacketBuffer& buf);
  XskPacket(uint8_t* frame, size_t dataSize, size_t frameSize);
  void addDelay(int relativeMilliseconds) noexcept;
  void updatePacket() noexcept;
  [[nodiscard]] uint32_t getFlags() const noexcept;
};
bool operator<(const XskPacketPtr& s1, const XskPacketPtr& s2) noexcept;

/* g++ defines __SANITIZE_THREAD__
   clang++ supports the nice __has_feature(thread_sanitizer),
   let's merge them */
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define __SANITIZE_THREAD__ 1
#endif
#endif

// XskWorker obtains XskPackets of specific ports in the NIC from XskSocket through cq.
// After finishing processing the packet, XskWorker puts the packet into sq so that XskSocket decides whether to send it through the network card according to XskPacket::flags.
// XskWorker wakes up XskSocket via xskSocketWaker after putting the packets in sq.
class XskWorker
{
#if defined(__SANITIZE_THREAD__)
  using XskPacketRing = LockGuarded<boost::lockfree::spsc_queue<XskPacket*, boost::lockfree::capacity<XSK_RING_CONS__DEFAULT_NUM_DESCS*2>>>;
#else
  using XskPacketRing = boost::lockfree::spsc_queue<XskPacket*, boost::lockfree::capacity<XSK_RING_CONS__DEFAULT_NUM_DESCS*2>>;
#endif

public:
  // queue of packets to be processed by this worker
  XskPacketRing incomingPacketsQueue;
  // queue of packets processed by this worker (to be sent, or discarded)
  XskPacketRing outgoingPacketsQueue;

  uint8_t* umemBufBase;
  // list of frames that are shared with the XskRouter
  std::shared_ptr<LockGuarded<vector<uint64_t>>> sharedEmptyFrameOffset;
  // list of frames that we own, used to generate new packets (health-check)
  vector<uint64_t> uniqueEmptyFrameOffset;
  std::string poolName;
  const size_t frameSize{XskSocket::getFrameSize()};
  FDWrapper workerWaker;
  FDWrapper xskSocketWaker;

  XskWorker();
  static int createEventfd();
  static void notify(int fd);
  static std::shared_ptr<XskWorker> create();
  void pushToProcessingQueue(XskPacketPtr&& packet);
  void pushToSendQueue(XskPacketPtr&& packet);
  void markAsFree(XskPacketPtr&& packet);
  // notify worker that at least one packet is available for processing
  void notifyWorker() noexcept;
  // notify the router that packets are ready to be sent
  void notifyXskSocket() noexcept;
  void waitForXskSocket() noexcept;
  void cleanWorkerNotification() noexcept;
  void cleanSocketNotification() noexcept;
  [[nodiscard]] uint64_t frameOffset(const XskPacket& s) const noexcept;
  // reap empty umem entry from sharedEmptyFrameOffset into uniqueEmptyFrameOffset
  void fillUniqueEmptyOffset();
  // look for an empty umem entry in uniqueEmptyFrameOffset
  // then sharedEmptyFrameOffset if needed
  XskPacketPtr getEmptyFrame();
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
