#pragma once

#include "../../core/FileHashAnalyzer.hpp"
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

namespace ui::views
{

struct VtEngineDetection
{
    std::string engine;
    std::string category;
    std::string result;
    std::string version;
};

struct VtFileReport
{
    bool queried = false;
    bool found = false;
    bool success = false;
    std::string errorMessage;
    std::string threatLabel;
    int malicious = 0;
    int suspicious = 0;
    int undetected = 0;
    int harmless = 0;
    int totalEngines = 0;
    int reputation = 0;
    int timesSubmitted = 0;
    std::vector<VtEngineDetection> engines;
};

class FileAnalyzerView
{
  public:
    FileAnalyzerView();

    void Render(std::string &statusText);
    void LoadFile(const std::string &filepath, std::string &statusText);

  private:
    void StartVirusTotalScan(bool uploadIfMissing, std::string &statusText);
    void LoadApiKey();
    void SaveApiKey() const;
    void ClearApiKey();
    bool ImportApiKeyFromFile(const std::string &filepath);

    decltype(core::FileHashAnalyzer::Analyze(std::string{})) m_result{};
    bool m_hasFile = false;

    char m_vtApiKey[128]{};
    bool m_showApiKey = false;
    bool m_onlyDetections = false;
    char m_engineFilter[64]{};

    std::atomic<bool> m_vtScanning{false};
    std::mutex m_vtMutex;
    std::string m_vtStatus;
    VtFileReport m_vtReport;
};

} // namespace ui::views