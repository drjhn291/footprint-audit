#include "UsernameView.hpp"
#include "../../core/ConfigLoader.hpp"
#include "../../core/HistoryManager.hpp"
#include "../../core/HtmlReportExporter.hpp"
#include "../../core/ReportExporter.hpp"
#include "../../network/UsernameScanner.hpp"
#include "../Components.hpp"
#include "../Theme.hpp"
#include "imgui.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <thread>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <commdlg.h>
#include <shellapi.h>

#pragma comment(lib, "comdlg32.lib")

namespace ui::views
{

namespace
{

std::string ToLowerCase(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // namespace

void UsernameView::Render(std::vector<core::PlatformRule> &rules, TextureCache &icons, std::atomic<bool> &is_scanning,
                          std::string &status_text, core::PivotAction &pivot)
{
    Components::SectionHeader("Username Footprint Scanner",
                              "Multi-vector handle detection (probe endpoints, response signatures & regex validation) "
                              "with direct profile links.");

    bool trigger_pivot = false;
    if (pivot.pending && pivot.target_tab == 0)
    {
        strncpy_s(m_usernameBuf, sizeof(m_usernameBuf), pivot.payload.c_str(), _TRUNCATE);
        pivot.pending = false;
        if (!is_scanning.load() && strlen(m_usernameBuf) > 0)
        {
            trigger_pivot = true;
        }
    }

    size_t available_sites = 0;
    for (const auto &r : rules)
    {
        if (!r.is_nsfw || m_includeNsfw)
            available_sites++;
    }

    ImGui::SetNextItemWidth(250.0f);
    bool enter_pressed = ImGui::InputTextWithHint("##user_input", "Enter username (drjhn291)...", m_usernameBuf,
                                                  sizeof(m_usernameBuf), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();

    ImGui::BeginDisabled(is_scanning.load() || strlen(m_usernameBuf) == 0);
    if (ImGui::Button("Scan Username", ImVec2(134.0f, 0.0f)) || (enter_pressed && !is_scanning.load()) || trigger_pivot)
    {
        is_scanning = true;
        m_cancel = false;
        m_progress = 0;
        m_activeTargetTotal = static_cast<int>(available_sites);
        status_text = "Scanning " + std::to_string(available_sites) + " platform detectors for '" +
                      std::string(m_usernameBuf) + "'...";
        std::string target(m_usernameBuf);
        bool variants = m_checkVariants;
        bool nsfw = m_includeNsfw;
        std::vector<core::PlatformRule> rules_snapshot = rules;

        std::thread([this, rules_snapshot, &is_scanning, &status_text, target, variants, nsfw]() {
            auto results = network::UsernameScanner::Scan(target, rules_snapshot, m_progress, m_cancel, variants, nsfw);
            int found_cnt = 0;
            for (const auto &r : results)
            {
                if (r.found)
                    found_cnt++;
            }
            core::HistoryManager::Add("username", target, std::to_string(found_cnt) + " profiles found");
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_findings = std::move(results);
                m_hasScanned = true;
                status_text = "Username scan complete: " + std::to_string(found_cnt) + " direct profiles found.";
            }
            is_scanning = false;
        }).detach();
    }
    ImGui::EndDisabled();

    if (is_scanning.load())
    {
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.82f, 0.24f, 0.28f, 1.00f));
        if (ImGui::Button("Stop", ImVec2(68.0f, 0.0f)))
        {
            m_cancel = true;
        }
        ImGui::PopStyleColor();
    }

    ImGui::SameLine();
    ImGui::BeginDisabled(is_scanning.load());
    if (ImGui::Button("Import Rules JSON", ImVec2(148.0f, 0.0f)))
    {
        char fileBuf[MAX_PATH]{};
        OPENFILENAMEA ofn{};
        ofn.lStructSize = sizeof(ofn);
        ofn.lpstrFilter = "Platform Rules JSON (*.json)\0*.json\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = fileBuf;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
        if (GetOpenFileNameA(&ofn))
        {
            size_t added = core::ConfigLoader::AppendRulesFile(fileBuf, rules);
            status_text = "Loaded " + std::to_string(added) + " additional platform rules (" +
                          std::to_string(rules.size()) + " total active).";
        }
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(is_scanning.load() || !m_hasScanned);
    if (ImGui::Button("Export JSON", ImVec2(100.0f, 0.0f)))
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        core::EmailAuditResult empty_email;
        core::DomainAuditResult empty_domain;
        if (core::ReportExporter::ExportJson("report_username.json", "username", m_usernameBuf, m_findings, empty_email,
                                             empty_domain))
        {
            status_text = "Exported report_username.json";
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Export HTML", ImVec2(100.0f, 0.0f)))
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        int found_cnt = 0;
        core::ReportTable tbl;
        tbl.title = "Discovered Public Profiles";
        tbl.headers = {"Platform", "Category", "Matched Handle", "Direct URL"};
        for (const auto &f : m_findings)
        {
            if (f.found)
            {
                found_cnt++;
                tbl.rows.push_back(
                    {f.platform, f.category, f.matched_handle.empty() ? m_usernameBuf : f.matched_handle, f.url});
            }
        }
        core::ExecutiveReportData rep;
        rep.moduleName = "Username OSINT Footprint";
        rep.target = m_usernameBuf;
        rep.riskBadge = std::to_string(found_cnt) + " PROFILES EXPOSED";
        rep.riskColorHex = (found_cnt > 10) ? "#fbbf24" : "#22d3ee";
        rep.kpis = {{"Direct Profiles", std::to_string(found_cnt)},
                    {"Detectors Checked", std::to_string(available_sites)},
                    {"Handle Variants", m_checkVariants ? "Enabled" : "Exact"}};
        rep.tables.push_back(std::move(tbl));
        std::string saved = core::HtmlReportExporter::ExportAndOpen(rep, true);
        status_text = "Exported executive HTML report: " + saved;
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(is_scanning.load());
    ImGui::Checkbox("Variants", &m_checkVariants);
    ImGui::SameLine();
    ImGui::Checkbox("NSFW", &m_includeNsfw);
    ImGui::EndDisabled();

    auto recent = core::HistoryManager::GetByModule("username", 6);
    if (!recent.empty() && !is_scanning.load())
    {
        ImGui::Spacing();
        ImGui::TextDisabled("Recent:");
        for (size_t i = 0; i < recent.size(); ++i)
        {
            ImGui::SameLine();
            ImGui::PushID(static_cast<int>(i));
            ImGui::PushFont(Theme::MonoFont());
            if (ImGui::SmallButton(recent[i].target.c_str()))
            {
                strncpy_s(m_usernameBuf, sizeof(m_usernameBuf), recent[i].target.c_str(), _TRUNCATE);
                pivot = {true, 0, recent[i].target};
            }
            ImGui::PopFont();
            ImGui::PopID();
        }
    }

    if (is_scanning.load() && m_activeTargetTotal > 0)
    {
        ImGui::Spacing();
        float frac = static_cast<float>(m_progress.load()) / static_cast<float>(m_activeTargetTotal);
        char progLabel[64];
        snprintf(progLabel, sizeof(progLabel), "Probing platforms: %d / %d", m_progress.load(), m_activeTargetTotal);
        ImGui::ProgressBar(frac, ImVec2(-1.0f, 20.0f), progLabel);
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    int total_found = 0;
    for (const auto &f : m_findings)
    {
        if (f.found)
            total_found++;
    }

    ImGui::Spacing();
    std::string found_kpi = m_hasScanned ? std::to_string(total_found) + " Profiles" : "-";
    std::string checked_kpi = std::to_string(available_sites) + " Sites";
    Components::MetricCard("us_kpi1", "DIRECT PROFILES", found_kpi.c_str(), ImVec4(0.20f, 0.86f, 0.54f, 1.00f), 195.0f);
    ImGui::SameLine();
    Components::MetricCard("us_kpi2", "ACTIVE DETECTORS", checked_kpi.c_str(), ImVec4(0.24f, 0.72f, 0.98f, 1.00f),
                           195.0f);

    ImGui::SameLine();
    ImGui::BeginGroup();
    ImGui::SetNextItemWidth(220.0f);
    ImGui::InputTextWithHint("##filter_plat", "Filter platform...", m_filterBuf, sizeof(m_filterBuf));
    const char *cats[] = {"All Categories", "Dev & Code", "Social", "Gaming", "Media & Art", "Forums & Other"};
    ImGui::SetNextItemWidth(220.0f);
    ImGui::Combo("##cat_combo", &m_selectedCategory, cats, IM_ARRAYSIZE(cats));
    ImGui::EndGroup();

    if (total_found > 0)
    {
        ImGui::SameLine();
        if (ImGui::Button("Copy All URLs", ImVec2(125.0f, 34.0f)))
        {
            std::string allUrls;
            for (const auto &f : m_findings)
            {
                if (f.found)
                    allUrls += f.platform + ": " + f.url + "\r\n";
            }
            ImGui::SetClipboardText(allUrls.c_str());
            status_text = "Copied " + std::to_string(total_found) + " profile URLs to clipboard.";
        }
    }

    ImGui::Spacing();

    if (!m_hasScanned && !is_scanning.load())
    {
        Components::EmptyState("user", "Ready to Enumerate Digital Footprint",
                               "Enter a target handle above to probe online platforms and extract direct profiles.");
        return;
    }

    if (total_found == 0 && !is_scanning.load())
    {
        Components::EmptyState("user", "No Public Profiles Matched",
                               "Try enabling 'Variants' to check common handle permutations or test another alias.");
        return;
    }

    ImGui::BeginChild("UserCardsArea", ImVec2(0.0f, 0.0f), true);

    std::string filter_low = ToLowerCase(m_filterBuf);
    std::string cat_filter = cats[m_selectedCategory];

    float avail_w = ImGui::GetContentRegionAvail().x;
    float card_w = 295.0f;
    int cols = std::max(1, static_cast<int>(avail_w / (card_w + 11.0f)));
    card_w = (avail_w - (cols - 1) * 11.0f) / static_cast<float>(cols);

    int col_idx = 0;
    for (const auto &f : m_findings)
    {
        if (!f.found)
            continue;
        if (m_selectedCategory > 0 && f.category != cat_filter)
            continue;
        if (!filter_low.empty() && ToLowerCase(f.platform).find(filter_low) == std::string::npos)
            continue;

        if (col_idx > 0)
            ImGui::SameLine();

        if (Components::PlatformCard(f, icons, card_w, 66.0f))
        {
            ShellExecuteA(nullptr, "open", f.url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        }

        col_idx++;
        if (col_idx >= cols)
            col_idx = 0;
    }

    ImGui::EndChild();
}

} // namespace ui::views