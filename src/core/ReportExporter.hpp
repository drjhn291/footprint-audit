#pragma once
#include "Models.hpp"
#include <string>
#include <vector>

namespace core
{

class ReportExporter
{
  public:
    static bool ExportJson(const std::string &filepath, const std::string &mode, const std::string &target,
                           const std::vector<UsernameFinding> &user_findings, const EmailAuditResult &email_res,
                           const DomainAuditResult &domain_res);

    static bool ExportHtml(const std::string &filepath, const std::string &mode, const std::string &target,
                           const std::vector<UsernameFinding> &user_findings, const EmailAuditResult &email_res,
                           const DomainAuditResult &domain_res);
};

} // namespace core