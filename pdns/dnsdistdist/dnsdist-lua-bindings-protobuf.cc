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

#ifndef DISABLE_PROTOBUF
#include "dnsdist-protobuf.hh"
#include "dnstap.hh"
#include "fstrm_logger.hh"
#include "ipcipher.hh"
#include "remote_logger.hh"
#include "remote_logger_pool.hh"

#ifdef HAVE_FSTRM
static void parseFSTRMOptions(boost::optional<LuaAssociativeTable<unsigned int>>& params, LuaAssociativeTable<unsigned int>& options)
{
  if (!params) {
    return;
  }

  static std::vector<std::string> const potentialOptions = {"bufferHint", "flushTimeout", "inputQueueSize", "outputQueueSize", "queueNotifyThreshold", "reopenInterval", "connectionCount"};

  for (const auto& potentialOption : potentialOptions) {
    getOptionalValue<unsigned int>(params, potentialOption, options[potentialOption]);
  }
}
#endif /* HAVE_FSTRM */

void setupLuaBindingsProtoBuf(LuaContext& luaCtx, bool client, bool configCheck)
{
#ifdef HAVE_IPCIPHER
  luaCtx.registerFunction<ComboAddress (ComboAddress::*)(const std::string& key) const>("ipencrypt", [](const ComboAddress& ca, const std::string& key) {
    return encryptCA(ca, key);
  });
  luaCtx.registerFunction<ComboAddress (ComboAddress::*)(const std::string& key) const>("ipdecrypt", [](const ComboAddress& ca, const std::string& key) {
    return decryptCA(ca, key);
  });

  luaCtx.writeFunction("makeIPCipherKey", [](const std::string& password) {
    return makeIPCipherKey(password);
  });
#endif /* HAVE_IPCIPHER */

  /* ProtobufMessage */
  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(std::string)>("setTag", [](DNSDistProtoBufMessage& message, const std::string& strValue) {
    message.addTag(strValue);
  });
  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(LuaArray<std::string>)>("setTagArray", [](DNSDistProtoBufMessage& message, const LuaArray<std::string>& tags) {
    for (const auto& tag : tags) {
      message.addTag(tag.second);
    }
  });

  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(boost::optional<time_t> sec, boost::optional<uint32_t> uSec)>("setProtobufResponseType",
                                                                                                                         [](DNSDistProtoBufMessage& message, boost::optional<time_t> sec, boost::optional<uint32_t> uSec) {
                                                                                                                           message.setType(pdns::ProtoZero::Message::MessageType::DNSResponseType);
                                                                                                                           message.setQueryTime(sec ? *sec : 0, uSec ? *uSec : 0);
                                                                                                                         });

  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(const std::string& strQueryName, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& strBlob)>("addResponseRR", [](DNSDistProtoBufMessage& message, const std::string& strQueryName, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& strBlob) {
    message.addRR(DNSName(strQueryName), uType, uClass, uTTL, strBlob);
  });
  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(const Netmask&)>("setEDNSSubnet", [](DNSDistProtoBufMessage& message, const Netmask& subnet) { message.setEDNSSubnet(subnet); });
  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(const DNSName&, uint16_t, uint16_t)>("setQuestion", [](DNSDistProtoBufMessage& message, const DNSName& qname, uint16_t qtype, uint16_t qclass) { message.setQuestion(qname, qtype, qclass); });
  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(size_t)>("setBytes", [](DNSDistProtoBufMessage& message, size_t bytes) { message.setBytes(bytes); });
  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(time_t, uint32_t)>("setTime", [](DNSDistProtoBufMessage& message, time_t sec, uint32_t usec) { message.setTime(sec, usec); });
  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(time_t, uint32_t)>("setQueryTime", [](DNSDistProtoBufMessage& message, time_t sec, uint32_t usec) { message.setQueryTime(sec, usec); });
  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(uint8_t)>("setResponseCode", [](DNSDistProtoBufMessage& message, uint8_t rcode) { message.setResponseCode(rcode); });

  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(const ComboAddress&, boost::optional<uint16_t>)>("setRequestor", [](DNSDistProtoBufMessage& message, const ComboAddress& addr, boost::optional<uint16_t> port) {
    message.setRequestor(addr);
    if (port) {
      message.setRequestorPort(*port);
    }
  });
  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(const std::string&, boost::optional<uint16_t>)>("setRequestorFromString", [](DNSDistProtoBufMessage& message, const std::string& str, boost::optional<uint16_t> port) {
    message.setRequestor(ComboAddress(str));
    if (port) {
      message.setRequestorPort(*port);
    }
  });
  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(const ComboAddress&, boost::optional<uint16_t>)>("setResponder", [](DNSDistProtoBufMessage& message, const ComboAddress& addr, boost::optional<uint16_t> port) {
    message.setResponder(addr);
    if (port) {
      message.setResponderPort(*port);
    }
  });
  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(const std::string&, boost::optional<uint16_t>)>("setResponderFromString", [](DNSDistProtoBufMessage& message, const std::string& str, boost::optional<uint16_t> port) {
    message.setResponder(ComboAddress(str));
    if (port) {
      message.setResponderPort(*port);
    }
  });
  luaCtx.registerFunction<void (DNSDistProtoBufMessage::*)(const std::string&)>("setServerIdentity", [](DNSDistProtoBufMessage& message, const std::string& str) {
    message.setServerIdentity(str);
  });

  luaCtx.registerFunction<void (DnstapMessage::*)(const std::string&)>("setExtra", [](DnstapMessage& message, const std::string& str) {
    message.setExtra(str);
  });

  /* RemoteLogger */
  luaCtx.writeFunction("newRemoteLogger", [client, configCheck](const std::string& remote, boost::optional<uint16_t> timeout, boost::optional<uint64_t> maxQueuedEntries, boost::optional<uint8_t> reconnectWaitTime, boost::optional<uint64_t> connectionCount) {
    if (client || configCheck) {
      return std::shared_ptr<RemoteLoggerInterface>(nullptr);
    }
    auto count = connectionCount ? *connectionCount : 1;
    if (count > 1) {
      std::vector<std::shared_ptr<RemoteLoggerInterface>> loggers;
      for (uint64_t i = 0; i < count; i++) {
        loggers.emplace_back(new RemoteLogger(ComboAddress(remote), timeout ? *timeout : 2, maxQueuedEntries ? (*maxQueuedEntries * 100) : 10000, reconnectWaitTime ? *reconnectWaitTime : 1, client));
      }
      return std::shared_ptr<RemoteLoggerInterface>(new RemoteLoggerPool(std::move(loggers)));
    }
    else {
      return std::shared_ptr<RemoteLoggerInterface>(new RemoteLogger(ComboAddress(remote), timeout ? *timeout : 2, maxQueuedEntries ? (*maxQueuedEntries * 100) : 10000, reconnectWaitTime ? *reconnectWaitTime : 1, client));
    }
  });

  luaCtx.writeFunction("newFrameStreamUnixLogger", [client, configCheck]([[maybe_unused]] const std::string& address, [[maybe_unused]] boost::optional<LuaAssociativeTable<unsigned int>> params) {
#ifdef HAVE_FSTRM
    if (client || configCheck) {
      return std::shared_ptr<RemoteLoggerInterface>(nullptr);
    }

    LuaAssociativeTable<unsigned int> options;
    parseFSTRMOptions(params, options);
    checkAllParametersConsumed("newFrameStreamUnixLogger", params);
    auto connectionCount = options.find("connectionCount");
    auto count = connectionCount == options.end() ? 1 : connectionCount->second;
    options.erase(connectionCount);
    if (count > 1) {
      std::vector<std::shared_ptr<RemoteLoggerInterface>> loggers;
      for (uint64_t i = 0; i < count; i++) {
        loggers.emplace_back(new FrameStreamLogger(AF_UNIX, address, !client, options));
      }
      return std::shared_ptr<RemoteLoggerInterface>(new RemoteLoggerPool(std::move(loggers)));
    }
    else {
      return std::shared_ptr<RemoteLoggerInterface>(new FrameStreamLogger(AF_UNIX, address, !client, options));
    }
#else
    throw std::runtime_error("fstrm support is required to build an AF_UNIX FrameStreamLogger");
#endif /* HAVE_FSTRM */
  });

  luaCtx.writeFunction("newFrameStreamTcpLogger", [client, configCheck]([[maybe_unused]] const std::string& address, [[maybe_unused]] boost::optional<LuaAssociativeTable<unsigned int>> params) {
#if defined(HAVE_FSTRM) && defined(HAVE_FSTRM_TCP_WRITER_INIT)
    if (client || configCheck) {
      return std::shared_ptr<RemoteLoggerInterface>(nullptr);
    }

    LuaAssociativeTable<unsigned int> options;
    parseFSTRMOptions(params, options);
    checkAllParametersConsumed("newFrameStreamTcpLogger", params);
    auto connectionCount = options.find("connectionCount");
    auto count = connectionCount == options.end() ? 1 : connectionCount->second;
    options.erase(connectionCount);
    if (count > 1) {
      std::vector<std::shared_ptr<RemoteLoggerInterface>> loggers;
      for (uint64_t i = 0; i < count; i++) {
        loggers.emplace_back(new FrameStreamLogger(AF_INET, address, !client, options));
      }
      return std::shared_ptr<RemoteLoggerInterface>(new RemoteLoggerPool(std::move(loggers)));
    }
    else {
      return std::shared_ptr<RemoteLoggerInterface>(new FrameStreamLogger(AF_INET, address, !client, options));
    }
#else
    throw std::runtime_error("fstrm with TCP support is required to build an AF_INET FrameStreamLogger");
#endif /* HAVE_FSTRM */
  });

  luaCtx.registerFunction<std::string (std::shared_ptr<RemoteLoggerInterface>::*)() const>("toString", [](const std::shared_ptr<RemoteLoggerInterface>& logger) {
    if (logger) {
      return logger->toString();
    }
    return std::string();
  });
}
#else /* DISABLE_PROTOBUF */
void setupLuaBindingsProtoBuf(LuaContext&, bool, bool)
{
}
#endif /* DISABLE_PROTOBUF */
