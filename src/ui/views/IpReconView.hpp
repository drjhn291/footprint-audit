#pragma once

#include "../../core/Models.hpp"
#include <atomic>
#include <mutex>
#include <string>

namespace ui::views
{

class IpReconView
{
  public:
    void Render(std::atomic<bool> &is_scanning, std::string &status_text, core::PivotAction &pivot);

  private:
    char m_target_buf[160]{};
    std::mutex m_mutex;
    core::IpReconResult m_result;
};

} // namespace ui::views