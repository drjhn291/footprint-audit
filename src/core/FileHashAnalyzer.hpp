#pragma once

#include <cstdint>
#include <string>

namespace core
{

struct FileAnalysisResult
{
    bool success = false;
    std::string filePath;
    std::string fileName;
    std::string errorMessage;

    uint64_t fileSizeBytes = 0;
    std::string humanSize;
    std::string magicType;

    std::string md5;
    std::string sha1;
    std::string sha256;

    double shannonEntropy = 0.0;
    std::string entropyVerdict;
};

class FileHashAnalyzer
{
  public:
    static FileAnalysisResult Analyze(const std::string &utf8Path);
};

} // namespace core