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
      {"Delay", (int)DNSAction::Action::Delay},
      {"Truncate", (int)DNSAction::Action::Truncate},
      {"ServFail", (int)DNSAction::Action::ServFail}
    });

  g_lua.writeVariable("DNSResponseAction", std::unordered_map<string,int>{
      {"Allow",        (int)DNSResponseAction::Action::Allow        },
      {"Delay",        (int)DNSResponseAction::Action::Delay        },
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

  vector<pair<string, int> > rcodes = {{"NOERROR",  RCode::NoError  },
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
                                       {"BADCOOKIE",ERCode::BADCOOKIE },
  };
  vector<pair<string, int> > dd;
  for(const auto& n : QType::names)
    dd.push_back({n.first, n.second});
  for(const auto& n : rcodes)
    dd.push_back({n.first, n.second});
  g_lua.writeVariable("dnsdist", dd);
}
