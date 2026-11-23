#pragma once

#include "../core/Models.hpp"
#include <atomic>
#include <string>
#include <vector>

namespace network
{

class UsernameScanner
{
  public:
    static std::vector<core::UsernameFinding> Scan(const std::string &username,
                                                   const std::vector<core::PlatformRule> &rules,
                                                   std::atomic<int> &progress_current, std::atomic<bool> &cancel_flag,
                                                   bool check_variants = false, bool include_nsfw = false);
};

} // namespace network