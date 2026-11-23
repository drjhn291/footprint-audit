#pragma once

#include "../core/Models.hpp"
#include <string>

namespace network
{

class DomainScanner
{
  public:
    static core::DomainAuditResult AuditDomain(const std::string &domain);
    static std::string ResolveHostToIp(const std::string &host);
};

} // namespace network