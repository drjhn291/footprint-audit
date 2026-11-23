#pragma once

#include "../core/Models.hpp"
#include <string>

namespace network
{

class IpReconScanner
{
  public:
    static core::IpReconResult ReconTarget(const std::string &target);
};

} // namespace network