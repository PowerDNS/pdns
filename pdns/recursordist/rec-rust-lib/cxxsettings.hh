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

#include <string>
#include "rust/cxx.h"
#include "rust/lib.rs.h"
#include "sholder.hh"
#include "logging.hh"
#include "rec-lua-conf.hh"

namespace pdns::settings::rec
{
enum YamlSettingsStatus : uint8_t
{
  OK,
  CannotOpen,
  PresentButFailed,
};

void defineOldStyleSettings();
void oldStyleSettingsToBridgeStruct(pdns::rust::settings::rec::Recursorsettings& settings);
void oldStyleForwardsFileToBridgeStruct(const std::string& filename, ::rust::Vec<pdns::rust::settings::rec::ForwardZone>& vec);
void oldStyleAllowFileToBridgeStruct(const std::string& filename, ::rust::Vec<::rust::String>& vec);
bool oldKVToBridgeStruct(string& key, const string& value, ::rust::String& section, ::rust::String& fieldname, ::rust::String& type_name, pdns::rust::settings::rec::Value& rustvalue);
std::string oldStyleSettingsFileToYaml(const string& fname, bool mainFile);
std::string defaultsToYaml(bool postProcess = true);
YamlSettingsStatus readYamlSettings(const std::string& configname, const std::string& includeDirOnCommandLine, rust::settings::rec::Recursorsettings& settings, std::string& msg, Logr::log_t log);
void processAPIDir(const string& includeDirOnCommandLine, pdns::rust::settings::rec::Recursorsettings& settings, Logr::log_t log);
void bridgeStructToOldStyleSettings(const pdns::rust::settings::rec::Recursorsettings& settings);
void readYamlForwardZonesFile(const std::string& filename, ::rust::Vec<pdns::rust::settings::rec::ForwardZone>& vec, Logr::log_t log);
void readYamlAllowFromFile(const std::string& filename, ::rust::Vec<::rust::String>& vec, Logr::log_t log);
void readYamlAllowNotifyForFile(const std::string& filename, ::rust::Vec<::rust::String>& vec, Logr::log_t log);
void setArgsForZoneRelatedSettings(pdns::rust::settings::rec::Recursorsettings& settings);
void setArgsForACLRelatedSettings(pdns::rust::settings::rec::Recursorsettings& settings);
void fromLuaConfigToBridgeStruct(LuaConfigItems& luaConfig, const ProxyMapping& proxyMapping, pdns::rust::settings::rec::Recursorsettings& settings);
void fromBridgeStructToLuaConfig(const pdns::rust::settings::rec::Recursorsettings& settings, LuaConfigItems& luaConfig, ProxyMapping& proxyMapping, OpenTelemetryTraceConditions& conditions);
bool luaItemSet(const pdns::rust::settings::rec::Recursorsettings& settings);
YamlSettingsStatus tryReadYAML(const string& yamlconfigname, bool setGlobals, bool& yamlSettings, bool& luaSettingsInYAML, rust::settings::rec::Recursorsettings& settings, Logr::log_t startupLog, Logr::Priority level = Logr::Debug);
}
