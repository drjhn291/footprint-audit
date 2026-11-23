#include "EmailView.hpp"
#include "../../core/HistoryManager.hpp"
#include "../../core/HtmlReportExporter.hpp"
#include "../../core/ReportExporter.hpp"
#include "../../network/BreachScanner.hpp"
#include "../Components.hpp"
#include "../Theme.hpp"
#include "imgui.h"
#include <cstring>
#include <shellapi.h>
#include <thread>
#include <vector>
#include <windows.h>

namespace ui::views
{

namespace
{

std::string ExtractAtHandle(const std::string &title)
{
    size_t pos = title.find("(@");
    if (pos == std::string::npos)
        return "";
    size_t end = title.find(')', pos + 2);
    if (end == std::string::npos)
        return "";
    return title.substr(pos + 2, end - (pos + 2));
}

} // namespace

void EmailView::Render(std::atomic<bool> &is_scanning, std::string &status_text, core::PivotAction &pivot)
{
    static bool show_passwords = false;

    Components::SectionHeader("Multi-Source Email Breach & Credential Audit",
                              "Cross-checks XposedOrNot Analytics, LeakCheck, Hudson Rock Infostealers, COMB, PGP "
                              "Keyservers & Social OSINT.");

    ImGui::SetNextItemWidth(330.0f);
    bool enter_pressed = ImGui::InputTextWithHint("##email_input", "Enter email address...", m_email_buf,
                                                  sizeof(m_email_buf), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();

    auto startScan = [&](const std::string &target) {
        is_scanning = true;
        status_text = "Querying 12 breach intelligence & credential sources for " + target + "...";

        std::thread([this, &is_scanning, &status_text, target]() {
            auto res = network::BreachScanner::AuditEmail(target);
            core::HistoryManager::Add("email", target, std::to_string(res.breaches.size()) + " records found");
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_result = std::move(res);
                status_text =
                    "Email audit complete: " + std::to_string(m_result.breaches.size()) + " total records indexed.";
            }
            is_scanning = false;
        }).detach();
    };

    ImGui::BeginDisabled(is_scanning.load() || strlen(m_email_buf) == 0);
    if (ImGui::Button("Audit Email", ImVec2(132.0f, 0.0f)) || (enter_pressed && !is_scanning.load()))
    {
        startScan(m_email_buf);
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(is_scanning.load() || !m_result.completed);
    if (ImGui::Button("Export JSON", ImVec2(105.0f, 0.0f)))
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<core::UsernameFinding> empty_users;
        core::DomainAuditResult empty_domain;
        if (core::ReportExporter::ExportJson("report_email.json", "email", m_email_buf, empty_users, m_result,
                                             empty_domain))
        {
            status_text = "Exported report_email.json";
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Export HTML", ImVec2(105.0f, 0.0f)))
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        core::ReportTable tbl;
        tbl.title = "Breach & OSINT Exposure Records";
        tbl.headers = {"Breach / Record", "Exposed Credential / Risk", "Date", "Intelligence Source"};
        for (const auto &b : m_result.breaches)
        {
            std::string cred = b.exposed_passwords.empty()
                                   ? "N/A"
                                   : (show_passwords || b.exposed_passwords.front() == '[' ? b.exposed_passwords
                                                                                           : "[MASKED IN REPORT]");
            tbl.rows.push_back({b.source_name, cred, b.date, b.provider});
        }
        core::ExecutiveReportData rep;
        rep.moduleName = "Email Breach & Credential Audit";
        rep.target = m_result.email;
        rep.riskBadge = m_result.breaches.empty() ? "CLEAN / NO LEAKS"
                                                  : std::to_string(m_result.breaches.size()) + " RECORDS FOUND";
        rep.riskColorHex = m_result.breaches.empty() ? "#34d399" : "#f87171";
        rep.kpis = {{"Target Email", m_result.email},
                    {"Total Indexed Records", std::to_string(m_result.breaches.size())},
                    {"GitHub Linked", m_result.github_user.empty() ? "None" : m_result.github_user}};
        rep.tables.push_back(std::move(tbl));
        std::string saved = core::HtmlReportExporter::ExportAndOpen(rep, true);
        status_text = "Exported executive HTML report: " + saved;
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (show_passwords)
    {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.88f, 0.45f, 0.14f, 1.00f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.96f, 0.54f, 0.20f, 1.00f));
        if (ImGui::Button("Mask Passwords", ImVec2(142.0f, 0.0f)))
        {
            show_passwords = false;
        }
        ImGui::PopStyleColor(2);
    }
    else
    {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.14f, 0.20f, 0.30f, 1.00f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.19f, 0.27f, 0.40f, 1.00f));
        if (ImGui::Button("Show Passwords", ImVec2(142.0f, 0.0f)))
        {
            show_passwords = true;
        }
        ImGui::PopStyleColor(2);
    }

    // Historial reciente
    auto recent = core::HistoryManager::GetByModule("email", 5);
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
                strncpy_s(m_email_buf, sizeof(m_email_buf), recent[i].target.c_str(), _TRUNCATE);
                startScan(recent[i].target);
            }
            ImGui::PopFont();
            ImGui::PopID();
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<core::BreachRecord> leak_records;
    std::vector<core::BreachRecord> osint_records;
    int stealer_count = 0;

    if (m_result.completed)
    {
        for (const auto &b : m_result.breaches)
        {
            bool is_osint =
                (b.provider.find("OSINT") != std::string::npos || b.provider.find("Keyserver") != std::string::npos);
            if (is_osint)
            {
                osint_records.push_back(b);
            }
            else
            {
                leak_records.push_back(b);
                if (b.provider.find("Hudson Rock") != std::string::npos ||
                    b.source_name.find("Infostealer") != std::string::npos)
                {
                    stealer_count++;
                }
            }
        }
    }

    int linked_total = static_cast<int>(osint_records.size()) + (m_result.github_user.empty() ? 0 : 1) +
                       (m_result.gravatar_name.empty() ? 0 : 1);

    ImGui::Spacing();
    std::string breach_kpi = m_result.completed ? std::to_string(leak_records.size()) + " Leaks" : "-";
    std::string stealer_kpi = m_result.completed ? std::to_string(stealer_count) + " Logs" : "-";
    std::string osint_kpi = m_result.completed ? std::to_string(linked_total) + " Linked" : "-";

    Components::MetricCard(
        "em_kpi1", "DATA BREACHES", breach_kpi.c_str(),
        leak_records.empty() ? ImVec4(0.20f, 0.86f, 0.54f, 1.00f) : ImVec4(0.96f, 0.32f, 0.36f, 1.00f), 185.0f);
    ImGui::SameLine();
    Components::MetricCard("em_kpi2", "INFOSTEALER LOGS", stealer_kpi.c_str(),
                           stealer_count == 0 ? ImVec4(0.20f, 0.86f, 0.54f, 1.00f) : ImVec4(0.98f, 0.58f, 0.16f, 1.00f),
                           195.0f);
    ImGui::SameLine();
    Components::MetricCard("em_kpi3", "OSINT IDENTITIES", osint_kpi.c_str(), ImVec4(0.24f, 0.72f, 0.98f, 1.00f),
                           195.0f);

    ImGui::Spacing();

    if (!m_result.completed)
    {
        Components::EmptyState(
            "email", "No Email Audit Executed Yet",
            "Enter an email address above to cross-check 12 breach databases, stealer logs & OSINT.");
        return;
    }

    ImGui::BeginChild("BreachContainer", ImVec2(0.0f, 0.0f), true);

    if (leak_records.empty())
    {
        std::string ok_msg = "[SAFE] No public data breaches or stealer logs detected for " + m_result.email;
        Components::StatusBadge(ok_msg.c_str(), ImVec4(0.20f, 0.86f, 0.54f, 1.00f));
    }
    else
    {
        std::string alert_msg =
            "[EXPOSED] Found in " + std::to_string(leak_records.size()) + " breach / credential leak sources:";
        Components::StatusBadge(alert_msg.c_str(), ImVec4(0.96f, 0.32f, 0.36f, 1.00f));
        ImGui::Spacing();

        if (ImGui::BeginTable("BreachTable", 4,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_Resizable,
                              ImVec2(0.0f, 235.0f)))
        {
            ImGui::TableSetupColumn("Breach / Compromised Data", ImGuiTableColumnFlags_WidthStretch, 1.15f);
            ImGui::TableSetupColumn("Exposed Passwords / Risk", ImGuiTableColumnFlags_WidthStretch, 1.15f);
            ImGui::TableSetupColumn("Date", ImGuiTableColumnFlags_WidthFixed, 115.0f);
            ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 175.0f);
            ImGui::TableHeadersRow();

            for (size_t rowIdx = 0; rowIdx < leak_records.size(); ++rowIdx)
            {
                const auto &b = leak_records[rowIdx];
                bool is_stealer = (b.provider.find("Hudson Rock") != std::string::npos ||
                                   b.source_name.find("Infostealer") != std::string::npos);

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                if (is_stealer)
                {
                    ImGui::TextColored(ImVec4(0.98f, 0.62f, 0.22f, 1.00f), "%s", b.source_name.c_str());
                }
                else
                {
                    ImGui::TextUnformatted(b.source_name.c_str());
                }

                ImGui::TableSetColumnIndex(1);
                ImGui::PushFont(Theme::MonoFont());
                bool is_meta_tag = (!b.exposed_passwords.empty() && b.exposed_passwords.front() == '[');
                if (b.exposed_passwords.empty())
                {
                    ImGui::TextDisabled("N/A");
                }
                else if (is_meta_tag)
                {
                    ImGui::TextDisabled("%s", b.exposed_passwords.c_str());
                }
                else if (show_passwords)
                {
                    ImGui::TextColored(ImVec4(1.00f, 0.45f, 0.45f, 1.00f), "%s", b.exposed_passwords.c_str());
                    ImGui::SameLine();
                    std::string cid = "cp_pw_" + std::to_string(rowIdx);
                    Components::CopyButton(cid.c_str(), b.exposed_passwords);
                }
                else
                {
                    ImGui::TextColored(ImVec4(0.95f, 0.72f, 0.28f, 1.00f), "•••••••• (Click 'Show Passwords')");
                }
                ImGui::PopFont();

                ImGui::TableSetColumnIndex(2);
                ImGui::PushFont(Theme::MonoFont());
                ImGui::TextUnformatted(b.date.c_str());
                ImGui::PopFont();

                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("%s", b.provider.c_str());
            }
            ImGui::EndTable();
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::PushFont(Theme::BoldFont());
    ImGui::TextColored(ImVec4(0.24f, 0.78f, 0.98f, 1.00f), "Linked Public Accounts & OSINT Pivoting");
    ImGui::PopFont();
    ImGui::Spacing();

    size_t at_pos = m_result.email.find('@');
    if (at_pos != std::string::npos && at_pos > 1)
    {
        std::string prefix = m_result.email.substr(0, at_pos);
        ImGui::BulletText("Email Handle Prefix: %s", prefix.c_str());
        ImGui::SameLine();
        if (ImGui::SmallButton("Scan Handle ->"))
        {
            pivot = {true, 0, prefix};
        }
    }

    if (!m_result.github_user.empty())
    {
        ImGui::BulletText("GitHub Developer Profile: %s", m_result.github_user.c_str());
        ImGui::SameLine();
        if (ImGui::SmallButton("Open GitHub"))
        {
            ShellExecuteA(nullptr, "open", m_result.github_url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Scan Username ->##gh"))
        {
            pivot = {true, 0, m_result.github_user};
        }
    }
    if (!m_result.gravatar_name.empty())
    {
        ImGui::BulletText("Gravatar Identity: %s", m_result.gravatar_name.c_str());
        ImGui::SameLine();
        if (ImGui::SmallButton("Open Gravatar"))
        {
            ShellExecuteA(nullptr, "open", m_result.gravatar_url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        }
    }
    for (size_t idx = 0; idx < osint_records.size(); ++idx)
    {
        const auto &o = osint_records[idx];
        ImGui::BulletText("%s  (%s - %s)", o.source_name.c_str(), o.provider.c_str(), o.date.c_str());
        std::string extracted_user = ExtractAtHandle(o.source_name);
        if (!extracted_user.empty())
        {
            ImGui::SameLine();
            std::string btn_id = "Scan @" + extracted_user + " ->##osint_" + std::to_string(idx);
            if (ImGui::SmallButton(btn_id.c_str()))
            {
                pivot = {true, 0, extracted_user};
            }
        }
    }

    ImGui::EndChild();
}

} // namespace ui::views