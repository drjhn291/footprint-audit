#include "FileAnalyzerView.hpp"

#include <windows.h>

#include <commdlg.h>
#include <shellapi.h>

#include "../../core/HtmlReportExporter.hpp"
#include "../../network/HttpClient.hpp"
#include "../Components.hpp"
#include "../Theme.hpp"
#include "imgui.h"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <thread>

#pragma comment(lib, "comdlg32.lib")

namespace ui::views
{

namespace
{

constexpr std::uintmax_t kMaxDirectUploadBytes = 32ULL * 1024ULL * 1024ULL;
constexpr std::uintmax_t kMaxLargeUploadBytes = 650ULL * 1024ULL * 1024ULL;

std::filesystem::path GetVtKeyFilePath()
{
    char *localAppData = nullptr;
    size_t len = 0;
    if (_dupenv_s(&localAppData, &len, "LOCALAPPDATA") == 0 && localAppData != nullptr)
    {
        std::filesystem::path dir = std::filesystem::path(localAppData) / "FootprintAudit";
        free(localAppData);
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        return dir / "vt_apikey.txt";
    }
    return "vt_apikey.txt";
}

std::string TrimWhitespace(std::string s)
{
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
    return s;
}

std::string OpenFileDialog(const char *filter)
{
    char fileBuf[MAX_PATH]{};
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameA(&ofn))
    {
        return fileBuf;
    }
    return {};
}

std::string ToLowerStr(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

int CategoryPriority(const std::string &cat)
{
    if (cat == "malicious")
        return 0;
    if (cat == "suspicious")
        return 1;
    if (cat == "undetected")
        return 2;
    if (cat == "harmless")
        return 3;
    return 4;
}

VtFileReport ParseVtFileJson(const std::string &body)
{
    VtFileReport rep;
    rep.queried = true;

    auto j = nlohmann::json::parse(body, nullptr, false);
    if (j.is_discarded() || !j.contains("data") || !j["data"].contains("attributes"))
    {
        rep.errorMessage = "Invalid JSON response from VirusTotal.";
        return rep;
    }

    const auto &attr = j["data"]["attributes"];
    rep.found = true;
    rep.success = true;

    if (attr.contains("reputation") && attr["reputation"].is_number_integer())
        rep.reputation = attr["reputation"].get<int>();

    if (attr.contains("times_submitted") && attr["times_submitted"].is_number_integer())
        rep.timesSubmitted = attr["times_submitted"].get<int>();

    if (attr.contains("popular_threat_classification") && attr["popular_threat_classification"].is_object())
    {
        const auto &ptc = attr["popular_threat_classification"];
        if (ptc.contains("suggested_threat_label") && ptc["suggested_threat_label"].is_string())
            rep.threatLabel = ptc["suggested_threat_label"].get<std::string>();
    }

    if (attr.contains("last_analysis_stats") && attr["last_analysis_stats"].is_object())
    {
        const auto &st = attr["last_analysis_stats"];
        rep.malicious = st.value("malicious", 0);
        rep.suspicious = st.value("suspicious", 0);
        rep.undetected = st.value("undetected", 0);
        rep.harmless = st.value("harmless", 0);
        rep.totalEngines = rep.malicious + rep.suspicious + rep.undetected + rep.harmless;
    }

    if (attr.contains("last_analysis_results") && attr["last_analysis_results"].is_object())
    {
        for (const auto &[engName, engVal] : attr["last_analysis_results"].items())
        {
            if (!engVal.is_object())
                continue;
            VtEngineDetection det;
            det.engine = engName;
            det.category = engVal.value("category", "unknown");
            if (engVal.contains("result") && engVal["result"].is_string())
                det.result = engVal["result"].get<std::string>();
            else
                det.result = (det.category == "undetected" || det.category == "harmless") ? "Clean" : "-";

            if (engVal.contains("engine_version") && engVal["engine_version"].is_string())
                det.version = engVal["engine_version"].get<std::string>();

            rep.engines.push_back(std::move(det));
        }

        if (rep.totalEngines == 0)
            rep.totalEngines = static_cast<int>(rep.engines.size());

        std::sort(rep.engines.begin(), rep.engines.end(), [](const VtEngineDetection &a, const VtEngineDetection &b) {
            int pa = CategoryPriority(a.category);
            int pb = CategoryPriority(b.category);
            if (pa != pb)
                return pa < pb;
            return a.engine < b.engine;
        });
    }

    return rep;
}

std::string BuildMultipartFilePayload(const std::string &boundary, const std::string &fileName,
                                      const std::string &fileBytes)
{
    std::string body;
    body.reserve(fileBytes.size() + 512);
    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"file\"; filename=\"" + fileName + "\"\r\n";
    body += "Content-Type: application/octet-stream\r\n\r\n";
    body.append(fileBytes.data(), fileBytes.size());
    body += "\r\n--" + boundary + "--\r\n";
    return body;
}

} // namespace

FileAnalyzerView::FileAnalyzerView()
{
    LoadApiKey();
}

void FileAnalyzerView::LoadApiKey()
{
    char *envKey = nullptr;
    size_t envLen = 0;
    if (_dupenv_s(&envKey, &envLen, "VT_API_KEY") == 0 && envKey != nullptr)
    {
        std::string trimmed = TrimWhitespace(envKey);
        free(envKey);
        if (!trimmed.empty())
        {
            strncpy_s(m_vtApiKey, sizeof(m_vtApiKey), trimmed.c_str(), _TRUNCATE);
            return;
        }
    }

    std::ifstream in(GetVtKeyFilePath());
    if (!in.is_open())
        return;

    std::string line;
    while (std::getline(in, line))
    {
        std::string trimmed = TrimWhitespace(line);
        if (!trimmed.empty())
        {
            strncpy_s(m_vtApiKey, sizeof(m_vtApiKey), trimmed.c_str(), _TRUNCATE);
            break;
        }
    }
}

void FileAnalyzerView::SaveApiKey() const
{
    std::string trimmed = TrimWhitespace(m_vtApiKey);
    if (trimmed.empty())
        return;

    std::ofstream out(GetVtKeyFilePath(), std::ios::trunc);
    if (out.is_open())
    {
        out << trimmed;
    }
}

void FileAnalyzerView::ClearApiKey()
{
    m_vtApiKey[0] = '\0';
    std::error_code ec;
    std::filesystem::remove(GetVtKeyFilePath(), ec);
}

bool FileAnalyzerView::ImportApiKeyFromFile(const std::string &filepath)
{
    std::ifstream in(filepath);
    if (!in.is_open())
        return false;

    std::string line;
    while (std::getline(in, line))
    {
        std::string trimmed = TrimWhitespace(line);
        if (!trimmed.empty())
        {
            strncpy_s(m_vtApiKey, sizeof(m_vtApiKey), trimmed.c_str(), _TRUNCATE);
            SaveApiKey();
            return true;
        }
    }
    return false;
}

void FileAnalyzerView::LoadFile(const std::string &filepath, std::string &statusText)
{
    m_result = core::FileHashAnalyzer::Analyze(filepath);
    m_hasFile = true;
    {
        std::lock_guard<std::mutex> lock(m_vtMutex);
        m_vtReport = VtFileReport{};
        m_vtStatus.clear();
    }

    if (m_result.success)
    {
        statusText = "Hashed " + m_result.fileName + " (" + m_result.humanSize + ") locally via Windows CNG.";
    }
    else
    {
        statusText = "File analysis failed: " + m_result.errorMessage;
    }
}

void FileAnalyzerView::StartVirusTotalScan(bool uploadIfMissing, std::string &statusText)
{
    if (m_vtScanning.load() || !m_hasFile || !m_result.success)
        return;

    std::string apiKey = TrimWhitespace(m_vtApiKey);
    if (apiKey.empty())
    {
        std::lock_guard<std::mutex> lock(m_vtMutex);
        m_vtStatus = "Paste or import your free VirusTotal API Key first.";
        statusText = m_vtStatus;
        return;
    }

    SaveApiKey();
    m_vtScanning = true;
    {
        std::lock_guard<std::mutex> lock(m_vtMutex);
        m_vtStatus = "Querying VirusTotal API v3 for SHA-256...";
    }
    statusText = "Querying VirusTotal API v3 for " + m_result.fileName + "...";

    std::string sha256 = m_result.sha256;
    std::string filePath = m_result.filePath;
    std::string fileName = m_result.fileName;

    std::thread([this, apiKey, sha256, filePath, fileName, uploadIfMissing, &statusText]() {
        std::map<std::string, std::string> headers = {{"x-apikey", apiKey}, {"Accept", "application/json"}};
        std::string lookupUrl = "https://www.virustotal.com/api/v3/files/" + sha256;

        network::HttpResponse resp = network::HttpClient::Request("GET", lookupUrl, headers, "", true, 15000);

        if (resp.status == 200)
        {
            VtFileReport parsed = ParseVtFileJson(resp.body);
            std::lock_guard<std::mutex> lock(m_vtMutex);
            m_vtReport = std::move(parsed);
            m_vtStatus = "VirusTotal report loaded: " + std::to_string(m_vtReport.malicious) + " / " +
                         std::to_string(m_vtReport.totalEngines) + " malicious detections.";
            statusText = m_vtStatus;
            m_vtScanning = false;
            return;
        }

        if (resp.status == 404 && !uploadIfMissing)
        {
            std::lock_guard<std::mutex> lock(m_vtMutex);
            m_vtReport = VtFileReport{};
            m_vtReport.queried = true;
            m_vtReport.found = false;
            m_vtReport.errorMessage =
                "Hash not in VirusTotal yet. Click 'Upload & Scan File' to submit it (max 650 MB).";
            m_vtStatus = m_vtReport.errorMessage;
            statusText = m_vtStatus;
            m_vtScanning = false;
            return;
        }

        if (resp.status == 404 && uploadIfMissing)
        {
            std::error_code ec;
            auto fsize = std::filesystem::file_size(filePath, ec);
            if (ec || fsize == 0 || fsize > kMaxLargeUploadBytes)
            {
                std::lock_guard<std::mutex> lock(m_vtMutex);
                m_vtReport.queried = true;
                m_vtReport.errorMessage = "File must be between 1 byte and 650 MB for VirusTotal API upload.";
                m_vtStatus = m_vtReport.errorMessage;
                statusText = m_vtStatus;
                m_vtScanning = false;
                return;
            }

            std::string uploadUrl = "https://www.virustotal.com/api/v3/files";
            if (fsize > kMaxDirectUploadBytes)
            {
                {
                    std::lock_guard<std::mutex> lock(m_vtMutex);
                    m_vtStatus = "File > 32 MB: requesting large-file upload URL from VirusTotal...";
                }
                network::HttpResponse urlResp = network::HttpClient::Request(
                    "GET", "https://www.virustotal.com/api/v3/files/upload_url", headers, "", true, 15000);

                if (urlResp.status != 200)
                {
                    std::lock_guard<std::mutex> lock(m_vtMutex);
                    m_vtReport.queried = true;
                    m_vtReport.errorMessage =
                        "Could not get large-file upload URL (HTTP " + std::to_string(urlResp.status) + ").";
                    m_vtStatus = m_vtReport.errorMessage;
                    statusText = m_vtStatus;
                    m_vtScanning = false;
                    return;
                }

                auto urlJson = nlohmann::json::parse(urlResp.body, nullptr, false);
                if (urlJson.is_discarded() || !urlJson.contains("data") || !urlJson["data"].is_string())
                {
                    std::lock_guard<std::mutex> lock(m_vtMutex);
                    m_vtReport.queried = true;
                    m_vtReport.errorMessage = "Invalid upload_url response from VirusTotal.";
                    m_vtStatus = m_vtReport.errorMessage;
                    statusText = m_vtStatus;
                    m_vtScanning = false;
                    return;
                }
                uploadUrl = urlJson["data"].get<std::string>();
            }

            {
                std::lock_guard<std::mutex> lock(m_vtMutex);
                m_vtStatus = (fsize > kMaxDirectUploadBytes) ? "Uploading large file (>32 MB) to VirusTotal..."
                                                             : "Uploading file to VirusTotal sandbox...";
            }

            std::ifstream in(filePath, std::ios::binary);
            std::string fileBytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            in.close();

            const std::string boundary = "----FootprintAuditVTBoundary987654321";
            std::string payload = BuildMultipartFilePayload(boundary, fileName, fileBytes);
            std::map<std::string, std::string> upHeaders = {
                {"x-apikey", apiKey},
                {"Accept", "application/json"},
                {"Content-Type", "multipart/form-data; boundary=" + boundary}};

            int uploadTimeoutMs = (fsize > kMaxDirectUploadBytes) ? 180000 : 60000;
            network::HttpResponse upResp =
                network::HttpClient::Request("POST", uploadUrl, upHeaders, payload, true, uploadTimeoutMs);

            if (upResp.status != 200)
            {
                std::lock_guard<std::mutex> lock(m_vtMutex);
                m_vtReport.queried = true;
                m_vtReport.errorMessage = "Upload failed (HTTP " + std::to_string(upResp.status) + ").";
                m_vtStatus = m_vtReport.errorMessage;
                statusText = m_vtStatus;
                m_vtScanning = false;
                return;
            }

            auto upJson = nlohmann::json::parse(upResp.body, nullptr, false);
            std::string analysisId;
            if (!upJson.is_discarded() && upJson.contains("data") && upJson["data"].contains("id"))
                analysisId = upJson["data"]["id"].get<std::string>();

            if (analysisId.empty())
            {
                std::lock_guard<std::mutex> lock(m_vtMutex);
                m_vtReport.queried = true;
                m_vtReport.errorMessage = "VirusTotal did not return an analysis ID.";
                m_vtStatus = m_vtReport.errorMessage;
                m_vtScanning = false;
                return;
            }

            bool completed = false;
            for (int attempt = 0; attempt < 25; ++attempt)
            {
                {
                    std::lock_guard<std::mutex> lock(m_vtMutex);
                    m_vtStatus = "Scanning across 70+ AV engines (" + std::to_string((attempt + 1) * 3) + "s)...";
                }
                std::this_thread::sleep_for(std::chrono::seconds(3));

                network::HttpResponse pollResp = network::HttpClient::Request(
                    "GET", "https://www.virustotal.com/api/v3/analyses/" + analysisId, headers, "", true, 15000);

                if (pollResp.status == 200)
                {
                    auto pJson = nlohmann::json::parse(pollResp.body, nullptr, false);
                    if (!pJson.is_discarded() && pJson.contains("data") && pJson["data"].contains("attributes"))
                    {
                        std::string st = pJson["data"]["attributes"].value("status", "");
                        if (st == "completed")
                        {
                            completed = true;
                            break;
                        }
                    }
                }
            }

            if (!completed)
            {
                std::lock_guard<std::mutex> lock(m_vtMutex);
                m_vtReport.queried = true;
                m_vtReport.errorMessage =
                    "VirusTotal analysis queued. Click 'Scan on VirusTotal' again in ~20 seconds.";
                m_vtStatus = m_vtReport.errorMessage;
                statusText = m_vtStatus;
                m_vtScanning = false;
                return;
            }

            network::HttpResponse finalResp = network::HttpClient::Request("GET", lookupUrl, headers, "", true, 15000);
            if (finalResp.status == 200)
            {
                VtFileReport parsed = ParseVtFileJson(finalResp.body);
                std::lock_guard<std::mutex> lock(m_vtMutex);
                m_vtReport = std::move(parsed);
                m_vtStatus = "VirusTotal scan complete: " + std::to_string(m_vtReport.malicious) + " / " +
                             std::to_string(m_vtReport.totalEngines) + " malicious detections.";
                statusText = m_vtStatus;
                m_vtScanning = false;
                return;
            }
        }

        std::lock_guard<std::mutex> lock(m_vtMutex);
        m_vtReport.queried = true;
        if (resp.status == 401 || resp.status == 403)
            m_vtReport.errorMessage = "Invalid VirusTotal API Key (HTTP " + std::to_string(resp.status) + ").";
        else if (resp.status == 429)
            m_vtReport.errorMessage = "VirusTotal rate limit reached (4 lookups/min on free key).";
        else
            m_vtReport.errorMessage = "VirusTotal API error (HTTP " + std::to_string(resp.status) + ").";

        m_vtStatus = m_vtReport.errorMessage;
        statusText = m_vtStatus;
        m_vtScanning = false;
    }).detach();
}

void FileAnalyzerView::Render(std::string &statusText)
{
    Components::SectionHeader(
        "Local File Hash, Entropy & VirusTotal Scanner",
        "Computes SHA-256/SHA-1/MD5 offline via Windows CNG, scans via VirusTotal API v3 & exports HTML reports.");

    bool scanning = m_vtScanning.load();
    bool hasKey = std::strlen(m_vtApiKey) > 0;

    ImGui::BeginDisabled(scanning);
    ImGui::SetNextItemWidth(265.0f);
    ImGuiInputTextFlags keyFlags = m_showApiKey ? ImGuiInputTextFlags_None : ImGuiInputTextFlags_Password;
    if (ImGui::InputTextWithHint("##vt_apikey", "Paste VirusTotal API Key...", m_vtApiKey, sizeof(m_vtApiKey),
                                 keyFlags))
    {
        SaveApiKey();
    }
    ImGui::SameLine();
    ImGui::Checkbox("Show", &m_showApiKey);

    ImGui::SameLine();
    if (ImGui::Button("Import Key (.txt)...", ImVec2(148.0f, 0.0f)))
    {
        std::string keyFile = OpenFileDialog("Text / Key Files (*.txt;*.key)\0*.txt;*.key\0All Files (*.*)\0*.*\0");
        if (!keyFile.empty())
        {
            if (ImportApiKeyFromFile(keyFile))
                statusText = "VirusTotal API Key imported and saved locally in AppData.";
            else
                statusText = "Selected file was empty or unreadable.";
        }
    }

    if (hasKey)
    {
        ImGui::SameLine();
        if (ImGui::Button("Clear Key", ImVec2(88.0f, 0.0f)))
        {
            ClearApiKey();
            statusText = "Removed saved VirusTotal API Key from local storage.";
        }
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (hasKey)
    {
        Components::StatusBadge("Key Saved Locally", ImVec4(0.20f, 0.88f, 0.56f, 1.0f));
    }
    else
    {
        if (ImGui::SmallButton("Get Free API Key ->"))
        {
            ShellExecuteA(nullptr, "open", "https://www.virustotal.com/gui/my-apikey", nullptr, nullptr, SW_SHOWNORMAL);
        }
    }

    ImGui::Spacing();

    ImGui::BeginDisabled(scanning);
    if (ImGui::Button("Select Any File...", ImVec2(165.0f, 0.0f)))
    {
        std::string chosen = OpenFileDialog(
            "All Files (*.*)\0*.*\0Executables & Archives (*.exe;*.dll;*.zip;*.pdf)\0*.exe;*.dll;*.zip;*.pdf\0");
        if (!chosen.empty())
        {
            LoadFile(chosen, statusText);
        }
    }
    ImGui::EndDisabled();

    if (m_hasFile && m_result.success)
    {
        ImGui::SameLine();
        ImGui::BeginDisabled(scanning);
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.14f, 0.48f, 0.86f, 1.00f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.18f, 0.56f, 0.96f, 1.00f));
        if (ImGui::Button(scanning ? "Scanning VT..." : "Scan on VirusTotal", ImVec2(165.0f, 0.0f)))
        {
            StartVirusTotalScan(false, statusText);
        }
        ImGui::PopStyleColor(2);

        bool canUpload = false;
        {
            std::lock_guard<std::mutex> lock(m_vtMutex);
            canUpload = m_vtReport.queried && !m_vtReport.found;
        }
        if (canUpload)
        {
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.84f, 0.46f, 0.12f, 1.00f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.94f, 0.54f, 0.18f, 1.00f));
            if (ImGui::Button("Upload & Scan File", ImVec2(155.0f, 0.0f)))
            {
                StartVirusTotalScan(true, statusText);
            }
            ImGui::PopStyleColor(2);
        }
        ImGui::EndDisabled();

        ImGui::SameLine();
        if (ImGui::Button("VT Web ->", ImVec2(92.0f, 0.0f)))
        {
            std::string url = "https://www.virustotal.com/gui/file/" + m_result.sha256;
            ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        }

        ImGui::SameLine();
        if (ImGui::Button("Export HTML Report", ImVec2(165.0f, 0.0f)))
        {
            std::lock_guard<std::mutex> lock(m_vtMutex);
            char entBuf[32]{};
            std::snprintf(entBuf, sizeof(entBuf), "%.3f / 8.000", m_result.shannonEntropy);

            core::ExecutiveReportData rep;
            rep.moduleName = "File Hash, Entropy & VirusTotal Audit";
            rep.target = m_result.fileName;

            if (m_vtReport.success)
            {
                if (m_vtReport.malicious > 0)
                {
                    rep.riskBadge = "MALICIOUS (" + std::to_string(m_vtReport.malicious) + "/" +
                                    std::to_string(m_vtReport.totalEngines) + ")";
                    rep.riskColorHex = "#f87171";
                }
                else if (m_vtReport.suspicious > 0)
                {
                    rep.riskBadge = "SUSPICIOUS (" + std::to_string(m_vtReport.suspicious) + "/" +
                                    std::to_string(m_vtReport.totalEngines) + ")";
                    rep.riskColorHex = "#fbbf24";
                }
                else
                {
                    rep.riskBadge = "CLEAN (0/" + std::to_string(m_vtReport.totalEngines) + " ENGINES)";
                    rep.riskColorHex = "#34d399";
                }
            }
            else
            {
                rep.riskBadge = m_result.entropyVerdict;
                rep.riskColorHex = (m_result.shannonEntropy >= 7.5) ? "#fbbf24" : "#34d399";
            }

            std::string vtKpi = m_vtReport.success ? (std::to_string(m_vtReport.malicious) + " / " +
                                                      std::to_string(m_vtReport.totalEngines) + " Detections")
                                                   : "Not Queried";

            rep.kpis = {{"File Size", m_result.humanSize},
                        {"Shannon Entropy", entBuf},
                        {"Magic Signature", m_result.magicType},
                        {"VirusTotal", vtKpi}};

            rep.details = {{"Full Path", m_result.filePath},
                           {"SHA-256", m_result.sha256},
                           {"SHA-1", m_result.sha1},
                           {"MD5", m_result.md5},
                           {"Entropy Assessment", m_result.entropyVerdict},
                           {"VirusTotal Web Link", "https://www.virustotal.com/gui/file/" + m_result.sha256}};

            if (m_vtReport.success)
            {
                if (!m_vtReport.threatLabel.empty())
                    rep.details.push_back({"Threat Classification", m_vtReport.threatLabel});
                rep.details.push_back({"VT Reputation Score", std::to_string(m_vtReport.reputation)});
                rep.details.push_back({"Times Submitted", std::to_string(m_vtReport.timesSubmitted)});

                core::ReportTable vtTable;
                vtTable.title = "VirusTotal Antivirus Engine Results";
                vtTable.headers = {"Antivirus Engine", "Category", "Detection / Verdict", "Engine Version"};
                for (const auto &eng : m_vtReport.engines)
                {
                    vtTable.rows.push_back({eng.engine, eng.category, eng.result, eng.version});
                }
                rep.tables.push_back(std::move(vtTable));
            }

            std::string saved = core::HtmlReportExporter::ExportAndOpen(rep, true);
            statusText = "Exported executive HTML report: " + saved;
        }
    }

    ImGui::Spacing();

    if (!m_hasFile)
    {
        Components::EmptyState("pass", "No File Loaded for Cryptographic & VirusTotal Audit",
                               "Click 'Select Any File...' above to compute offline hashes, packing entropy & scan on "
                               "VirusTotal.");
        return;
    }

    if (!m_result.success)
    {
        Components::StatusBadge(m_result.errorMessage.c_str(), ImVec4(0.96f, 0.35f, 0.38f, 1.0f));
        return;
    }

    VtFileReport vtSnap;
    std::string vtStatusSnap;
    {
        std::lock_guard<std::mutex> lock(m_vtMutex);
        vtSnap = m_vtReport;
        vtStatusSnap = m_vtStatus;
    }

    float cardW = (ImGui::GetContentRegionAvail().x - 36.0f) / 4.0f;
    Components::MetricCard("fh_size", "FILE SIZE", m_result.humanSize.c_str(), ImVec4(0.16f, 0.84f, 0.96f, 1.00f),
                           cardW);
    ImGui::SameLine();

    char entStr[32]{};
    std::snprintf(entStr, sizeof(entStr), "%.3f bits", m_result.shannonEntropy);
    ImVec4 entCol =
        (m_result.shannonEntropy >= 7.5) ? ImVec4(0.98f, 0.75f, 0.18f, 1.00f) : ImVec4(0.20f, 0.88f, 0.56f, 1.00f);
    Components::MetricCard("fh_ent", "SHANNON ENTROPY", entStr, entCol, cardW);
    ImGui::SameLine();

    Components::MetricCard("fh_magic", "DETECTED FORMAT", m_result.magicType.c_str(),
                           ImVec4(0.66f, 0.55f, 0.98f, 1.00f), cardW);
    ImGui::SameLine();

    std::string vtVal = "-";
    ImVec4 vtCol(0.55f, 0.65f, 0.80f, 1.00f);
    if (vtSnap.success)
    {
        vtVal = std::to_string(vtSnap.malicious) + " / " + std::to_string(vtSnap.totalEngines);
        if (vtSnap.malicious > 0)
            vtCol = ImVec4(0.96f, 0.32f, 0.36f, 1.00f);
        else if (vtSnap.suspicious > 0)
            vtCol = ImVec4(0.98f, 0.75f, 0.18f, 1.00f);
        else
            vtCol = ImVec4(0.20f, 0.88f, 0.56f, 1.00f);
    }
    Components::MetricCard("fh_vt", "VIRUSTOTAL", vtVal.c_str(), vtCol, cardW);

    ImGui::Spacing();

    ImGui::BeginChild("FileHashPanel", ImVec2(0.0f, 0.0f), true);
    ImGui::PushFont(Theme::BoldFont());
    ImGui::TextColored(ImVec4(0.20f, 0.84f, 0.96f, 1.00f), "Cryptographic Digests & Packing Analysis");
    ImGui::PopFont();
    ImGui::Spacing();

    Components::StatusBadge(m_result.entropyVerdict.c_str(), entCol);
    if (!vtStatusSnap.empty())
    {
        ImGui::SameLine();
        ImVec4 stCol = vtSnap.success ? vtCol : ImVec4(0.98f, 0.75f, 0.18f, 1.00f);
        Components::StatusBadge(vtStatusSnap.c_str(), stCol);
    }
    ImGui::Spacing();

    ImGui::PushFont(Theme::MonoFont());
    ImGui::TextDisabled("File Path:");
    ImGui::SameLine(120.0f);
    ImGui::TextWrapped("%s", m_result.filePath.c_str());

    ImGui::Spacing();
    ImGui::TextDisabled("SHA-256  :");
    ImGui::SameLine(120.0f);
    ImGui::TextColored(ImVec4(0.20f, 0.88f, 0.56f, 1.0f), "%s", m_result.sha256.c_str());
    ImGui::SameLine();
    Components::CopyButton("copy_sha256", m_result.sha256);

    ImGui::Spacing();
    ImGui::TextDisabled("SHA-1    :");
    ImGui::SameLine(120.0f);
    ImGui::TextUnformatted(m_result.sha1.c_str());
    ImGui::SameLine();
    Components::CopyButton("copy_sha1", m_result.sha1);

    ImGui::Spacing();
    ImGui::TextDisabled("MD5      :");
    ImGui::SameLine(120.0f);
    ImGui::TextUnformatted(m_result.md5.c_str());
    ImGui::SameLine();
    Components::CopyButton("copy_md5", m_result.md5);
    ImGui::PopFont();

    if (vtSnap.success)
    {
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::PushFont(Theme::BoldFont());
        ImGui::TextColored(ImVec4(0.20f, 0.84f, 0.96f, 1.00f), "VirusTotal Antivirus Engine Breakdown");
        ImGui::PopFont();

        if (!vtSnap.threatLabel.empty())
        {
            ImGui::SameLine();
            Components::StatusBadge(vtSnap.threatLabel.c_str(), ImVec4(0.96f, 0.32f, 0.36f, 1.00f));
        }

        ImGui::SameLine();
        ImGui::TextDisabled("  |  Reputation: %d  |  Submissions: %d", vtSnap.reputation, vtSnap.timesSubmitted);

        ImGui::Spacing();
        ImGui::SetNextItemWidth(220.0f);
        ImGui::InputTextWithHint("##vt_eng_filter", "Filter AV engine...", m_engineFilter, sizeof(m_engineFilter));
        ImGui::SameLine();
        ImGui::Checkbox("Show Detections Only", &m_onlyDetections);

        ImGui::Spacing();
        if (ImGui::BeginTable("VtEnginesTable", 4,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_Resizable,
                              ImVec2(0.0f, 0.0f)))
        {
            ImGui::TableSetupColumn("Antivirus Engine", ImGuiTableColumnFlags_WidthFixed, 190.0f);
            ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 120.0f);
            ImGui::TableSetupColumn("Detection / Verdict", ImGuiTableColumnFlags_WidthStretch, 1.0f);
            ImGui::TableSetupColumn("Version", ImGuiTableColumnFlags_WidthFixed, 130.0f);
            ImGui::TableHeadersRow();

            std::string filterLow = ToLowerStr(m_engineFilter);
            for (const auto &eng : vtSnap.engines)
            {
                bool isThreat = (eng.category == "malicious" || eng.category == "suspicious");
                if (m_onlyDetections && !isThreat)
                    continue;
                if (!filterLow.empty() && ToLowerStr(eng.engine).find(filterLow) == std::string::npos &&
                    ToLowerStr(eng.result).find(filterLow) == std::string::npos)
                {
                    continue;
                }

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushFont(Theme::BoldFont());
                ImGui::TextUnformatted(eng.engine.c_str());
                ImGui::PopFont();

                ImGui::TableSetColumnIndex(1);
                ImVec4 catCol = ImVec4(0.20f, 0.88f, 0.56f, 1.0f);
                if (eng.category == "malicious")
                    catCol = ImVec4(0.96f, 0.32f, 0.36f, 1.0f);
                else if (eng.category == "suspicious")
                    catCol = ImVec4(0.98f, 0.75f, 0.18f, 1.0f);
                else if (eng.category != "undetected" && eng.category != "harmless")
                    catCol = ImVec4(0.55f, 0.65f, 0.80f, 1.0f);

                ImGui::PushFont(Theme::MonoFont());
                ImGui::TextColored(catCol, "%s", eng.category.c_str());

                ImGui::TableSetColumnIndex(2);
                if (isThreat)
                    ImGui::TextColored(catCol, "%s", eng.result.c_str());
                else
                    ImGui::TextDisabled("%s", eng.result.c_str());

                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("%s", eng.version.c_str());
                ImGui::PopFont();
            }
            ImGui::EndTable();
        }
    }

    ImGui::EndChild();
}

} // namespace ui::views