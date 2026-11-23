#pragma once
#include <atomic>
#include <mutex>
#include <string>

namespace ui::views
{

class PasswordView
{
  public:
    void Render(std::atomic<bool> &is_scanning, std::string &status_text);

  private:
    char m_pass_buf[128] = "";
    bool m_show_plain = false;
    std::mutex m_mutex;
    int m_pwned_count = -2;
};

} // namespace ui::views