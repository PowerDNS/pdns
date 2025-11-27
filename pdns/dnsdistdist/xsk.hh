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
#include "config.h"

#ifdef HAVE_XSK
#include <array>
#include <bits/types/struct_timespec.h>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <cstdint>
#include <memory>
#include <poll.h>
#include <queue>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include <xdp/xsk.h>

#include "iputils.hh"
#include "lock.hh"
#include "misc.hh"
#include "noinitvector.hh"

class XskPacket;
class XskWorker;
class XskSocket;

using MACAddr = std::array<uint8_t, 6>;

// We use an XskSocket to manage an AF_XDP Socket corresponding to a NIC queue.
// The XDP program running in the kernel redirects the data to the XskSocket in userspace.
// We allocate frames that are placed into the descriptors in the fill queue, allowing the kernel to put incoming packets into the frames and place descriptors into the rx queue.
// Once we have read the descriptors from the rx queue we release them, but we own the frames.
// After we are done with the frame, we place them into descriptors of either the fill queue (empty frames) or tx queues (packets to be sent).
// Once the kernel is done, it places descriptors referencing these frames into the cq where we can recycle them (packets destined to the tx queue or empty frame to the fill queue).

// XskSocket routes packets to multiple worker threads registered on XskSocket via XskSocket::addWorker based on the destination port number of the packet.
// The kernel and the worker thread holding XskWorker will wake up the XskSocket through XskFd and the Eventfd corresponding to each worker thread, respectively.

class XskSocket
{
  struct XskUmem
  {
    xsk_umem* umem{nullptr};
    uint8_t* bufBase{nullptr};
    size_t size{0};
    void umemInit(size_t memSize, xsk_ring_cons* completionQueue, xsk_ring_prod* fillQueue, xsk_umem_config* config);
    ~XskUmem();
    XskUmem() = default;
  };
  using WorkerContainer = std::unordered_map<int, std::shared_ptr<XskWorker>>;
  WorkerContainer d_workers;
  using WorkerRoutesMap = std::unordered_map<ComboAddress, std::shared_ptr<XskWorker>, ComboAddress::addressPortOnlyHash>;
  // it might be better to move to a StateHolder for performance
  LockGuarded<WorkerRoutesMap> d_workerRoutes;
  // number of frames to keep in sharedEmptyFrameOffset
  static constexpr size_t holdThreshold = 256;
  // number of frames to insert into the fill queue
  static constexpr size_t fillThreshold = 128;
  static constexpr size_t frameSize = 2048;
  // number of entries (frames) in the umem
  const size_t frameNum;
  // responses that have been delayed
  std::priority_queue<XskPacket> waitForDelay;
  MACAddr source{};
  const std::string ifName;
  // AF_XDP socket then worker waker sockets
  vector<pollfd> fds;
  // list of frames, aka (indexes of) umem entries that can be reused to fill fq,
  // collected from packets that we could not route (unknown destination),
  // could not parse, were dropped during processing (!UPDATED), or
  // simply recycled from cq after being processed by the kernel
  vector<uint64_t> uniqueEmptyFrameOffset;
  // completion ring: queue where sent packets are stored by the kernel
  xsk_ring_cons cq{};
  // rx ring: queue where the incoming packets are stored, read by XskRouter
  xsk_ring_cons rx{};
  // fill ring: queue where umem entries available to be filled (put into rx) are stored
  xsk_ring_prod fq{};
  // tx ring: queue where outgoing packets are stored
  xsk_ring_prod tx{};
  std::unique_ptr<xsk_socket, void (*)(xsk_socket*)> socket;
  XskUmem umem;

  static constexpr uint32_t fqCapacity = XSK_RING_PROD__DEFAULT_NUM_DESCS * 4;
  static constexpr uint32_t cqCapacity = XSK_RING_CONS__DEFAULT_NUM_DESCS * 4;
  static constexpr uint32_t rxCapacity = XSK_RING_CONS__DEFAULT_NUM_DESCS * 2;
  static constexpr uint32_t txCapacity = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2;

  constexpr static bool isPowOfTwo(uint32_t value) noexcept;
  [[nodiscard]] static int timeDifference(const timespec& lhs, const timespec& rhs) noexcept;

  [[nodiscard]] uint64_t frameOffset(const XskPacket& packet) const noexcept;
  [[nodiscard]] int firstTimeout();
  void getMACFromIfName();

public:
  static void clearDestinationMap(const std::string& mapPath, bool isV6);
  static void addDestinationAddress(const std::string& mapPath, const ComboAddress& destination);
  static void removeDestinationAddress(const std::string& mapPath, const ComboAddress& destination);
  static constexpr size_t getFrameSize()
  {
    return frameSize;
  }
  // list of free umem entries that can be reused
  std::shared_ptr<LockGuarded<vector<uint64_t>>> sharedEmptyFrameOffset;
  XskSocket(size_t frameNum, std::string ifName, uint32_t queue_id, const std::string& xskMapPath);
  [[nodiscard]] int xskFd() const noexcept;
  // wait until one event has occurred
  [[nodiscard]] int wait(int timeout);
  // add as many packets as possible to the rx queue for sending */
  void send(std::vector<XskPacket>& packets);
  // look at incoming packets in rx, return them if parsing succeeeded
  void recv(std::vector<XskPacket>& packets, uint32_t recvSizeMax, uint32_t* failedCount);
  void addWorker(std::shared_ptr<XskWorker> worker);
  void addWorkerRoute(const std::shared_ptr<XskWorker>& worker, const ComboAddress& dest);
  void removeWorkerRoute(const ComboAddress& dest);
  [[nodiscard]] std::string getMetrics() const;
  [[nodiscard]] std::string getXDPMode() const;
  void markAsFree(const XskPacket& packet);
  [[nodiscard]] const std::shared_ptr<XskWorker>& getWorkerByDescriptor(int desc) const
  {
    return d_workers.at(desc);
  }
  [[nodiscard]] std::shared_ptr<XskWorker> getWorkerByDestination(const ComboAddress& destination)
  {
    auto routes = d_workerRoutes.lock();
    auto workerIt = routes->find(destination);
    if (workerIt == routes->end()) {
      return nullptr;
    }
    return workerIt->second;
  }
  [[nodiscard]] const std::vector<pollfd>& getDescriptors() const
  {
    return fds;
  }
  [[nodiscard]] MACAddr getSourceMACAddress() const
  {
    return source;
  }
  [[nodiscard]] const std::string& getInterfaceName() const
  {
    return ifName;
  }
  // pick ups available frames from uniqueEmptyFrameOffset
  // insert entries from uniqueEmptyFrameOffset into fq
  void fillFq(uint32_t fillSize = fillThreshold) noexcept;
  // picks up entries that have been processed (sent) from cq and push them into uniqueEmptyFrameOffset
  void recycle(size_t size) noexcept;
  // look at delayed packets, and send the ones that are ready
  void pickUpReadyPacket(std::vector<XskPacket>& packets);
  void pushDelayed(XskPacket& packet)
  {
    waitForDelay.push(packet);
  }
};

struct ethhdr;
struct iphdr;
struct ipv6hdr;
struct udphdr;

class XskPacket
{
public:
  enum Flags : uint32_t
  {
    /* Whether the payload or the headers have
       been updated (a packet that has not been
       updated after processing will be discarded) */
    UPDATED = 1 << 0,
    DELAY = 1 << 1,
    /* Whether the packet has been rewritten after
       the headers and/or payload have been updated.
    */
    REWRITTEN = 1 << 2,
  };

private:
  ComboAddress from;
  ComboAddress to;
  timespec sendTime{};
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
  /* Exchange the source and destination addresses (ethernet and IP) */
  void changeDirectAndUpdateChecksum() noexcept;

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
  [[nodiscard]] PacketBuffer cloneHeaderToPacketBuffer() const;
  void setAddr(const ComboAddress& from_, MACAddr fromMAC, const ComboAddress& to_, MACAddr toMAC) noexcept;
  bool setPayload(const PacketBuffer& buf);
  /* Rewrite the headers, usually called after setAddr() then setPayload() */
  void rewrite() noexcept;
  void setHeader(PacketBuffer& buf);
  XskPacket(uint8_t* frame, size_t dataSize, size_t frameSize);
  void addDelay(int relativeMilliseconds) noexcept;
  /* If the payload has been updated, and the headers have not been rewritten via rewrite() yet,
     exchange the source and destination addresses (ethernet and IP) and rewrite the headers.
     This is what you want except if the headers (including source or destination addresses)
     have been manually updated. */
  void updatePacket() noexcept;
  // parse IP and UDP payloads
  bool parse(bool fromSetHeader);
  [[nodiscard]] uint32_t getFlags() const noexcept;
  [[nodiscard]] timespec getSendTime() const noexcept
  {
    return sendTime;
  }
  [[nodiscard]] uint64_t getFrameOffsetFrom(const uint8_t* base) const noexcept
  {
    return frame - base;
  }
};
bool operator<(const XskPacket& lhs, const XskPacket& rhs) noexcept;

// XskWorker obtains XskPackets of specific ports in the NIC from XskSocket through cq.
// After finishing processing the packet, XskWorker puts the packet into sq so that XskSocket decides whether to send it through the network card according to XskPacket::flags.
// XskWorker wakes up XskSocket via xskSocketWaker after putting the packets in sq.
class XskWorker
{
public:
  enum class Type : uint8_t
  {
    OutgoingOnly,
    Bidirectional
  };

private:
  using XskPacketRing = boost::lockfree::spsc_queue<XskPacket, boost::lockfree::capacity<XSK_RING_CONS__DEFAULT_NUM_DESCS * 2>>;
  // queue of packets to be processed by this worker
  XskPacketRing d_incomingPacketsQueue;
  // queue of packets processed by this worker (to be sent, or discarded)
  XskPacketRing d_outgoingPacketsQueue;
  // list of frames that are shared with the XskRouter
  std::shared_ptr<LockGuarded<vector<uint64_t>>> d_sharedEmptyFrameOffset;
  uint8_t* d_umemBufBase{nullptr};
  const size_t d_frameSize{XskSocket::getFrameSize()};
  Type d_type;

public:
  FDWrapper workerWaker;
  FDWrapper xskSocketWaker;

  static int createEventfd();
  static void notify(int desc);
  static std::shared_ptr<XskWorker> create(Type type, const std::shared_ptr<LockGuarded<std::vector<uint64_t>>>& frames);

  XskWorker(Type type, const std::shared_ptr<LockGuarded<std::vector<uint64_t>>>& frames);
  void setUmemBufBase(uint8_t* base);
  void pushToProcessingQueue(XskPacket& packet);
  void pushToSendQueue(XskPacket& packet);
  bool hasIncomingFrames();
  void processIncomingFrames(const std::function<void(XskPacket packet)>& callback);
  void processOutgoingFrames(const std::function<void(XskPacket packet)>& callback);
  void markAsFree(const XskPacket& packet);
  // notify worker that at least one packet is available for processing
  void notifyWorker() const;
  // notify the router that packets are ready to be sent
  void notifyXskSocket() const;
  void waitForXskSocket() const noexcept;
  void cleanWorkerNotification() const noexcept;
  void cleanSocketNotification() const noexcept;
  [[nodiscard]] uint64_t frameOffset(const XskPacket& packet) const noexcept;
  // get an empty umem entry from sharedEmptyFrameOffset
  std::optional<XskPacket> getEmptyFrame();
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
