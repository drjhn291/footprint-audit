#pragma once
#include "../core/Models.hpp"
#include <string>

namespace network
{

class BreachScanner
{
  public:
    static core::EmailAuditResult AuditEmail(const std::string &email);
    static int CheckPasswordPwnedCount(const std::string &password);
};

} // namespace network