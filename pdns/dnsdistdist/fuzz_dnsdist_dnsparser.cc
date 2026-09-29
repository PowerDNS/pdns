#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include "dnsdist-dnsparser.hh"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < sizeof(dnsheader) || size > std::numeric_limits<uint16_t>::max()) {
    return 0;
  }

  const PacketBuffer packet(data, data + size);
  const std::string_view view(reinterpret_cast<const char*>(packet.data()), packet.size());

  try {
    const dnsdist::DNSPacketOverlay overlay(view);
    for (const auto& record : overlay.d_records) {
      dnsdist::RecordParsers::parseAddressRecord(view, record);
      dnsdist::RecordParsers::parseCNAMERecord(view, record);
    }
  }
  catch (const std::exception&) {
  }
  catch (const PDNSException&) {
  }

  try {
    unsigned int consumed = 0;
    const DNSName original(view.data(), view.size(), sizeof(dnsheader), false, nullptr, nullptr, &consumed);
    const DNSName replacement(std::string(1 + data[0] % 63, 'a' + data[1] % 26) + ".example.");
    PacketBuffer rewritten(packet);
    if (dnsdist::changeNameInDNSPacket(rewritten, original, replacement)) {
      const dnsdist::DNSPacketOverlay overlay(std::string_view(reinterpret_cast<const char*>(rewritten.data()), rewritten.size()));
      (void)overlay;
    }
  }
  catch (const std::exception&) {
  }
  catch (const PDNSException&) {
  }

  try {
    const uint32_t first = (static_cast<uint32_t>(data[0]) << 8) | data[1];
    const uint32_t second = (static_cast<uint32_t>(data[2]) << 8) | data[3];
    PacketBuffer restricted(packet);
    dnsdist::PacketMangling::restrictDNSPacketTTLs(restricted, std::min(first, second), std::max(first, second));
    dnsdist::PacketMangling::restrictDNSPacketTTLs(restricted, 0, second, {QType::A, QType::AAAA});
  }
  catch (const std::exception&) {
  }
  catch (const PDNSException&) {
  }

  PacketBuffer edited(packet);
  dnsdist::PacketMangling::editDNSHeaderFromPacket(edited, [](dnsheader& header) {
    header.rd = !header.rd;
    header.cd = !header.cd;
    return true;
  });

  return 0;
}