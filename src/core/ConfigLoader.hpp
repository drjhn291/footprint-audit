#pragma once

#include "Models.hpp"
#include <string>
#include <vector>

namespace core
{

class ConfigLoader
{
  public:
    static std::vector<PlatformRule> LoadPlatforms(const std::string &json_path);
    static size_t AppendRulesFile(const std::string &rules_json_path, std::vector<PlatformRule> &rules);
};

} // namespace core