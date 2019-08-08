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
#include "ednsoptions.hh"

#undef BADSIG  // signal.h SIG_ERR

void setupLuaVars()
{
  g_lua.writeVariable("DNSAction", std::unordered_map<string,int>{
      {"Drop", (int)DNSAction::Action::Drop},
      {"Nxdomain", (int)DNSAction::Action::Nxdomain},
      {"Refused", (int)DNSAction::Action::Refused},
      {"Spoof", (int)DNSAction::Action::Spoof},
      {"Allow", (int)DNSAction::Action::Allow},
      {"HeaderModify", (int)DNSAction::Action::HeaderModify},
      {"Pool", (int)DNSAction::Action::Pool},
      {"None",(int)DNSAction::Action::None},
      {"NoOp",(int)DNSAction::Action::NoOp},
      {"Delay", (int)DNSAction::Action::Delay},
      {"Truncate", (int)DNSAction::Action::Truncate},
      {"ServFail", (int)DNSAction::Action::ServFail},
      {"NoRecurse", (int)DNSAction::Action::NoRecurse}
    });

  g_lua.writeVariable("DNSResponseAction", std::unordered_map<string,int>{
      {"Allow",        (int)DNSResponseAction::Action::Allow        },
      {"Delay",        (int)DNSResponseAction::Action::Delay        },
      {"Drop",         (int)DNSResponseAction::Action::Drop         },
      {"HeaderModify", (int)DNSResponseAction::Action::HeaderModify },
      {"ServFail",     (int)DNSResponseAction::Action::ServFail     },
      {"None",         (int)DNSResponseAction::Action::None         }
    });

  g_lua.writeVariable("DNSClass", std::unordered_map<string,int>{
      {"IN",    QClass::IN    },
      {"CHAOS", QClass::CHAOS },
      {"NONE",  QClass::NONE  },
      {"ANY",   QClass::ANY   }
    });

  g_lua.writeVariable("DNSOpcode", std::unordered_map<string,int>{
      {"Query",  Opcode::Query  },
      {"IQuery", Opcode::IQuery },
      {"Status", Opcode::Status },
      {"Notify", Opcode::Notify },
      {"Update", Opcode::Update }
    });

  g_lua.writeVariable("DNSSection", std::unordered_map<string,int>{
      {"Question",  0 },
      {"Answer",    1 },
      {"Authority", 2 },
      {"Additional",3 }
    });

  g_lua.writeVariable("EDNSOptionCode", std::unordered_map<string,int>{
      {"NSID",         EDNSOptionCode::NSID },
      {"DAU",          EDNSOptionCode::DAU },
      {"DHU",          EDNSOptionCode::DHU },
      {"N3U",          EDNSOptionCode::N3U },
      {"ECS",          EDNSOptionCode::ECS },
      {"EXPIRE",       EDNSOptionCode::EXPIRE },
      {"COOKIE",       EDNSOptionCode::COOKIE },
      {"TCPKEEPALIVE", EDNSOptionCode::TCPKEEPALIVE },
      {"PADDING",      EDNSOptionCode::PADDING },
      {"CHAIN",        EDNSOptionCode::CHAIN },
      {"KEYTAG",       EDNSOptionCode::KEYTAG }
    });

  g_lua.writeVariable("DNSRCode", std::unordered_map<string, int>{
      {"NOERROR",  RCode::NoError  },
      {"FORMERR",  RCode::FormErr  },
      {"SERVFAIL", RCode::ServFail },
      {"NXDOMAIN", RCode::NXDomain },
      {"NOTIMP",   RCode::NotImp   },
      {"REFUSED",  RCode::Refused  },
      {"YXDOMAIN", RCode::YXDomain },
      {"YXRRSET",  RCode::YXRRSet  },
      {"NXRRSET",  RCode::NXRRSet  },
      {"NOTAUTH",  RCode::NotAuth  },
      {"NOTZONE",  RCode::NotZone  },
      {"BADVERS",  ERCode::BADVERS },
      {"BADSIG",   ERCode::BADSIG  },
      {"BADKEY",   ERCode::BADKEY  },
      {"BADTIME",  ERCode::BADTIME   },
      {"BADMODE",  ERCode::BADMODE   },
      {"BADNAME",  ERCode::BADNAME   },
      {"BADALG",   ERCode::BADALG    },
      {"BADTRUNC", ERCode::BADTRUNC  },
      {"BADCOOKIE",ERCode::BADCOOKIE }
  });

  vector<pair<string, int> > dd;
  for(const auto& n : QType::names)
    dd.push_back({n.first, n.second});
  g_lua.writeVariable("DNSQType", dd);

  g_lua.executeCode(R"LUA(
    local tables = {
      DNSQType = DNSQType,
      DNSRCode = DNSRCode
    }
    local function index (table, key)
      for tname,t in pairs(tables)
      do
        local val = t[key]
        if val then
          warnlog(string.format("access to dnsdist.%s is deprecated, please use %s.%s", key, tname, key))
          return val
        end
      end
    end

    dnsdist = {}
    setmetatable(dnsdist, { __index = index })
    )LUA"
  );

#ifdef HAVE_DNSCRYPT
    g_lua.writeVariable("DNSCryptExchangeVersion", std::unordered_map<string,int>{
        { "VERSION1", DNSCryptExchangeVersion::VERSION1 },
        { "VERSION2", DNSCryptExchangeVersion::VERSION2 },
    });
#endif
}
