#pragma once

#include "../../core/SslAuditor.hpp"
#include <atomic>
#include <mutex>
#include <string>

namespace ui::views
{

class SslView
{
  public:
    void Render(std::atomic<bool> &isScanning, std::string &statusText);
    void SetTargetAndScan(const std::string &domain, std::atomic<bool> &isScanning, std::string &statusText);

  private:
    char m_domainInput[256] = "github.com";
    std::mutex m_mutex;
    core::SslAuditResult m_result;
    bool m_hasRun = false;
};

} // namespace ui::views