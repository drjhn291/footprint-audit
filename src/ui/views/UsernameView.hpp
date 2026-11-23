#pragma once

#include "../../core/Models.hpp"
#include "../TextureCache.hpp"
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

namespace ui::views
{

class UsernameView
{
  public:
    void Render(std::vector<core::PlatformRule> &rules, TextureCache &icons, std::atomic<bool> &is_scanning,
                std::string &status_text, core::PivotAction &pivot);

  private:
    char m_usernameBuf[128]{};
    char m_filterBuf[128]{};
    int m_selectedCategory = 0;
    bool m_checkVariants = false;
    bool m_includeNsfw = false;
    int m_activeTargetTotal = 0;
    std::atomic<int> m_progress{0};
    std::atomic<bool> m_cancel{false};
    std::mutex m_mutex;
    std::vector<core::UsernameFinding> m_findings;
    bool m_hasScanned = false;
};

} // namespace ui::views