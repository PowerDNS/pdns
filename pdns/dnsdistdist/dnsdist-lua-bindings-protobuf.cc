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
#include "dnsdist.hh"
#include "dnsdist-lua.hh"

#include "dnsdist-protobuf.hh"
#include "dnstap.hh"
#include "fstrm_logger.hh"
#include "remote_logger.hh"

#ifdef HAVE_LIBCRYPTO
#include "ipcipher.hh"
#endif /* HAVE_LIBCRYPTO */

void setupLuaBindingsProtoBuf(bool client)
{
#ifdef HAVE_LIBCRYPTO
  g_lua.registerFunction<ComboAddress(ComboAddress::*)(const std::string& key)>("ipencrypt", [](const ComboAddress& ca, const std::string& key) {
      return encryptCA(ca, key);
    });
  g_lua.registerFunction<ComboAddress(ComboAddress::*)(const std::string& key)>("ipdecrypt", [](const ComboAddress& ca, const std::string& key) {
      return decryptCA(ca, key);
    });

  g_lua.writeFunction("makeIPCipherKey", [](const std::string& password) {
      return makeIPCipherKey(password);
    });
#endif /* HAVE_LIBCRYPTO */

  /* ProtobufMessage */
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(std::string)>("setTag", [](DNSDistProtoBufMessage& message, const std::string& strValue) {
      message.addTag(strValue);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(vector<pair<int, string>>)>("setTagArray", [](DNSDistProtoBufMessage& message, const vector<pair<int, string>>&tags) {
      for (const auto& tag : tags) {
        message.addTag(tag.second);
      }
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(boost::optional <time_t> sec, boost::optional <uint32_t> uSec)>("setProtobufResponseType",
                                        [](DNSDistProtoBufMessage& message, boost::optional <time_t> sec, boost::optional <uint32_t> uSec) {
      message.setType(DNSProtoBufMessage::Response);
      message.setQueryTime(sec?*sec:0, uSec?*uSec:0);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const std::string& strQueryName, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& strBlob)>("addResponseRR", [](DNSDistProtoBufMessage& message,
                                                            const std::string& strQueryName, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& strBlob) {
      message.addRR(DNSName(strQueryName), uType, uClass, uTTL, strBlob);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const Netmask&)>("setEDNSSubnet", [](DNSDistProtoBufMessage& message, const Netmask& subnet) { message.setEDNSSubnet(subnet); });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const DNSName&, uint16_t, uint16_t)>("setQuestion", [](DNSDistProtoBufMessage& message, const DNSName& qname, uint16_t qtype, uint16_t qclass) { message.setQuestion(qname, qtype, qclass); });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(size_t)>("setBytes", [](DNSDistProtoBufMessage& message, size_t bytes) { message.setBytes(bytes); });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(time_t, uint32_t)>("setTime", [](DNSDistProtoBufMessage& message, time_t sec, uint32_t usec) { message.setTime(sec, usec); });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(time_t, uint32_t)>("setQueryTime", [](DNSDistProtoBufMessage& message, time_t sec, uint32_t usec) { message.setQueryTime(sec, usec); });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(uint8_t)>("setResponseCode", [](DNSDistProtoBufMessage& message, uint8_t rcode) { message.setResponseCode(rcode); });
  g_lua.registerFunction<std::string(DNSDistProtoBufMessage::*)()>("toDebugString", [](const DNSDistProtoBufMessage& message) { return message.toDebugString(); });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const ComboAddress&)>("setRequestor", [](DNSDistProtoBufMessage& message, const ComboAddress& addr) {
      message.setRequestor(addr);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const std::string&)>("setRequestorFromString", [](DNSDistProtoBufMessage& message, const std::string& str) {
      message.setRequestor(str);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const ComboAddress&)>("setResponder", [](DNSDistProtoBufMessage& message, const ComboAddress& addr) {
      message.setResponder(addr);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const std::string&)>("setResponderFromString", [](DNSDistProtoBufMessage& message, const std::string& str) {
      message.setResponder(str);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const std::string&)>("setServerIdentity", [](DNSDistProtoBufMessage& message, const std::string& str) {
      message.setServerIdentity(str);
    });

  g_lua.registerFunction<std::string(DnstapMessage::*)()>("toDebugString", [](const DnstapMessage& message) { return message.toDebugString(); });
  g_lua.registerFunction<void(DnstapMessage::*)(const std::string&)>("setExtra", [](DnstapMessage& message, const std::string& str) {
      message.setExtra(str);
    });

  /* RemoteLogger */
  g_lua.writeFunction("newRemoteLogger", [client](const std::string& remote, boost::optional<uint16_t> timeout, boost::optional<uint64_t> maxQueuedEntries, boost::optional<uint8_t> reconnectWaitTime) {
      if (client) {
        return std::shared_ptr<RemoteLoggerInterface>(nullptr);
      }
      return std::shared_ptr<RemoteLoggerInterface>(new RemoteLogger(ComboAddress(remote), timeout ? *timeout : 2, maxQueuedEntries ? (*maxQueuedEntries*100) : 10000, reconnectWaitTime ? *reconnectWaitTime : 1, client));
    });

  g_lua.writeFunction("newFrameStreamUnixLogger", [client](const std::string& address) {
#ifdef HAVE_FSTRM
      if (client) {
        return std::shared_ptr<RemoteLoggerInterface>(nullptr);
      }
      return std::shared_ptr<RemoteLoggerInterface>(new FrameStreamLogger(AF_UNIX, address, !client));
#else
      throw std::runtime_error("fstrm support is required to build an AF_UNIX FrameStreamLogger");
#endif /* HAVE_FSTRM */
    });

  g_lua.writeFunction("newFrameStreamTcpLogger", [client](const std::string& address) {
#if defined(HAVE_FSTRM) && defined(HAVE_FSTRM_TCP_WRITER_INIT)
      if (client) {
        return std::shared_ptr<RemoteLoggerInterface>(nullptr);
      }
      return std::shared_ptr<RemoteLoggerInterface>(new FrameStreamLogger(AF_INET, address, !client));
#else
      throw std::runtime_error("fstrm with TCP support is required to build an AF_INET FrameStreamLogger");
#endif /* HAVE_FSTRM */
    });

  g_lua.registerFunction<std::string(std::shared_ptr<RemoteLoggerInterface>::*)()>("toString", [](const std::shared_ptr<RemoteLoggerInterface>& logger) {
      if (logger) {
        return logger->toString();
      }
      return std::string();
  });
}
