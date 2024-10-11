#pragma once

#include <memory>
#include <string>

struct DNSRule;

#include "dnsdist-rust-lib/rust/cxx.h"

namespace dnsdist::rust::settings
{

struct DNSSelector
{
  std::shared_ptr<DNSRule> d_rule;
  std::string d_name;
};

struct MaxQPSIPRuleConfig;
struct AndSelectorConfig;
struct NetmaskGroupSelectorConfig;
struct TCPSelectorConfig;

std::shared_ptr<DNSSelector> getSelectorByName(const ::rust::String& name);
const std::string& getNameFromSelector(const DNSSelector& selector);

std::shared_ptr<DNSSelector> getMaxIPQPSSelector(const MaxQPSIPRuleConfig& config);
std::shared_ptr<DNSSelector> getAllSelector();
std::shared_ptr<DNSSelector> getTCPSelector(const TCPSelectorConfig& config);
std::shared_ptr<DNSSelector> getAndSelector(const AndSelectorConfig& config);
std::shared_ptr<DNSSelector> getNetmaskGroupSelector(const NetmaskGroupSelectorConfig& config);
}
