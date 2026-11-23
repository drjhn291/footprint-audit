#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace core
{

struct HistoryEntry
{
    std::string module;
    std::string target;
    std::string summary;
    std::string timestamp;
};

class HistoryManager
{
  public:
    static void Add(const std::string &module, const std::string &target, const std::string &summary);
    static std::vector<HistoryEntry> GetByModule(const std::string &module, size_t maxItems = 8);
    static void ClearModule(const std::string &module);
};

} // namespace core