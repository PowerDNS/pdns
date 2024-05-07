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
#include "dnsdist.hh"
#include "dnsdist-lua.hh"
#include "ednsoptions.hh"

#undef BADSIG // signal.h SIG_ERR

void setupLuaVars(LuaContext& luaCtx)
{
  luaCtx.writeVariable("DNSAction", LuaAssociativeTable<int>{{"Drop", (int)DNSAction::Action::Drop}, {"Nxdomain", (int)DNSAction::Action::Nxdomain}, {"Refused", (int)DNSAction::Action::Refused}, {"Spoof", (int)DNSAction::Action::Spoof}, {"SpoofPacket", (int)DNSAction::Action::SpoofPacket}, {"SpoofRaw", (int)DNSAction::Action::SpoofRaw}, {"Allow", (int)DNSAction::Action::Allow}, {"HeaderModify", (int)DNSAction::Action::HeaderModify}, {"Pool", (int)DNSAction::Action::Pool}, {"None", (int)DNSAction::Action::None}, {"NoOp", (int)DNSAction::Action::NoOp}, {"Delay", (int)DNSAction::Action::Delay}, {"Truncate", (int)DNSAction::Action::Truncate}, {"ServFail", (int)DNSAction::Action::ServFail}, {"NoRecurse", (int)DNSAction::Action::NoRecurse}, {"SetTag", (int)DNSAction::Action::SetTag}});

  luaCtx.writeVariable("DNSResponseAction", LuaAssociativeTable<int>{{"Allow", (int)DNSResponseAction::Action::Allow}, {"Delay", (int)DNSResponseAction::Action::Delay}, {"Drop", (int)DNSResponseAction::Action::Drop}, {"HeaderModify", (int)DNSResponseAction::Action::HeaderModify}, {"ServFail", (int)DNSResponseAction::Action::ServFail}, {"Truncate", (int)DNSResponseAction::Action::Truncate}, {"None", (int)DNSResponseAction::Action::None}});

  luaCtx.writeVariable("DNSClass", LuaAssociativeTable<int>{{"IN", QClass::IN}, {"CHAOS", QClass::CHAOS}, {"NONE", QClass::NONE}, {"ANY", QClass::ANY}});

  luaCtx.writeVariable("DNSOpcode", LuaAssociativeTable<int>{{"Query", Opcode::Query}, {"IQuery", Opcode::IQuery}, {"Status", Opcode::Status}, {"Notify", Opcode::Notify}, {"Update", Opcode::Update}});

  luaCtx.writeVariable("DNSSection", LuaAssociativeTable<int>{{"Question", 0}, {"Answer", 1}, {"Authority", 2}, {"Additional", 3}});

  luaCtx.writeVariable("EDNSOptionCode", LuaAssociativeTable<int>{{"NSID", EDNSOptionCode::NSID}, {"DAU", EDNSOptionCode::DAU}, {"DHU", EDNSOptionCode::DHU}, {"N3U", EDNSOptionCode::N3U}, {"ECS", EDNSOptionCode::ECS}, {"EXPIRE", EDNSOptionCode::EXPIRE}, {"COOKIE", EDNSOptionCode::COOKIE}, {"TCPKEEPALIVE", EDNSOptionCode::TCPKEEPALIVE}, {"PADDING", EDNSOptionCode::PADDING}, {"CHAIN", EDNSOptionCode::CHAIN}, {"KEYTAG", EDNSOptionCode::KEYTAG}});

  luaCtx.writeVariable("DNSRCode", LuaAssociativeTable<int>{{"NOERROR", RCode::NoError}, {"FORMERR", RCode::FormErr}, {"SERVFAIL", RCode::ServFail}, {"NXDOMAIN", RCode::NXDomain}, {"NOTIMP", RCode::NotImp}, {"REFUSED", RCode::Refused}, {"YXDOMAIN", RCode::YXDomain}, {"YXRRSET", RCode::YXRRSet}, {"NXRRSET", RCode::NXRRSet}, {"NOTAUTH", RCode::NotAuth}, {"NOTZONE", RCode::NotZone}, {"BADVERS", ERCode::BADVERS}, {"BADSIG", ERCode::BADSIG}, {"BADKEY", ERCode::BADKEY}, {"BADTIME", ERCode::BADTIME}, {"BADMODE", ERCode::BADMODE}, {"BADNAME", ERCode::BADNAME}, {"BADALG", ERCode::BADALG}, {"BADTRUNC", ERCode::BADTRUNC}, {"BADCOOKIE", ERCode::BADCOOKIE}});

  LuaAssociativeTable<int> dnsqtypes;
  for (const auto& name : QType::names) {
    dnsqtypes[name.first] = name.second;
  }
  luaCtx.writeVariable("DNSQType", dnsqtypes);

#ifdef HAVE_DNSCRYPT
  luaCtx.writeVariable("DNSCryptExchangeVersion", LuaAssociativeTable<int>{
                                                    {"VERSION1", DNSCryptExchangeVersion::VERSION1},
                                                    {"VERSION2", DNSCryptExchangeVersion::VERSION2},
                                                  });
#endif
}
