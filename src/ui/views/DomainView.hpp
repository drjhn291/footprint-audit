#pragma once

#include "../../core/Models.hpp"
#include <atomic>
#include <mutex>
#include <string>

namespace ui::views
{

class DomainView
{
  public:
    void Render(std::atomic<bool> &is_scanning, std::string &status_text, core::PivotAction &pivot);

  private:
    char m_domain_buf[160]{};
    char m_sub_filter[128]{};
    std::mutex m_mutex;
    core::DomainAuditResult m_result;
};

} // namespace ui::views