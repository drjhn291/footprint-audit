#pragma once

#include "../../core/Models.hpp"
#include <atomic>
#include <mutex>
#include <string>

namespace ui::views
{

class EmailView
{
  public:
    void Render(std::atomic<bool> &is_scanning, std::string &status_text, core::PivotAction &pivot);

  private:
    char m_email_buf[160]{};
    std::mutex m_mutex;
    core::EmailAuditResult m_result;
};

} // namespace ui::views