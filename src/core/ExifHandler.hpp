#pragma once

#include "Models.hpp"
#include <string>

namespace core
{

class ExifHandler
{
  public:
    static ExifInspectResult InspectFile(const std::string &filepath);
    static bool StripMetadata(const std::string &input_path, std::string &output_path, std::string &error_msg);
};

}