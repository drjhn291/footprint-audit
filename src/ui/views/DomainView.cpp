#include "DomainView.hpp"
#include "../../core/HistoryManager.hpp"
#include "../../core/HtmlReportExporter.hpp"
#include "../../core/ReportExporter.hpp"
#include "../../network/DomainScanner.hpp"
#include "../Components.hpp"
#include "../Theme.hpp"
#include "imgui.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <shellapi.h>
#include <thread>
#include <vector>
#include <windows.h>

namespace ui::views
{

namespace
{

std::string ToLowerDomain(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // namespace

void DomainView::Render(std::atomic<bool> &is_scanning, std::string &status_text, core::PivotAction &pivot)
{
    Components::SectionHeader(
        "Domain SSL Recon & DNS Spoofing Audit",
        "Inspects Certificate Transparency logs (crt.sh) and audits DNS A, MX, SPF & DMARC email security records.");

    bool trigger_pivot = false;
    if (pivot.pending && pivot.target_tab == 3)
    {
        strncpy_s(m_domain_buf, sizeof(m_domain_buf), pivot.payload.c_str(), _TRUNCATE);
        pivot.pending = false;
        if (!is_scanning.load() && strlen(m_domain_buf) > 0)
        {
            trigger_pivot = true;
        }
    }

    ImGui::SetNextItemWidth(320.0f);
    bool enter_pressed =
        ImGui::InputTextWithHint("##domain_input", "Enter root domain (e.g. example.com)...", m_domain_buf,
                                 sizeof(m_domain_buf), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();

    auto startDomainAudit = [&](const std::string &target) {
        is_scanning = true;
        status_text = "Querying CT logs & native DNS (A/MX/SPF/DMARC) for " + target + "...";

        std::thread([this, &is_scanning, &status_text, target]() {
            auto res = network::DomainScanner::AuditDomain(target);
            core::HistoryManager::Add("domain", res.domain.empty() ? target : res.domain,
                                      std::to_string(res.subdomains.size()) + " subdomains");
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_result = std::move(res);
                status_text = "Domain recon complete: " + std::to_string(m_result.subdomains.size()) +
                              " subdomains & DNS policies analyzed.";
            }
            is_scanning = false;
        }).detach();
    };

    ImGui::BeginDisabled(is_scanning.load() || strlen(m_domain_buf) == 0);
    if (ImGui::Button("Recon Domain", ImVec2(140.0f, 0.0f)) || (enter_pressed && !is_scanning.load()) || trigger_pivot)
    {
        startDomainAudit(m_domain_buf);
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(is_scanning.load() || !m_result.completed);
    if (ImGui::Button("Export JSON", ImVec2(105.0f, 0.0f)))
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<core::UsernameFinding> empty_users;
        core::EmailAuditResult empty_email;
        if (core::ReportExporter::ExportJson("report_domain.json", "domain", m_domain_buf, empty_users, empty_email,
                                             m_result))
        {
            status_text = "Exported report_domain.json";
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Export HTML", ImVec2(105.0f, 0.0f)))
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        core::ExecutiveReportData rep;
        rep.moduleName = "Domain & DNS Security Recon";
        rep.target = m_result.domain.empty() ? std::string(m_domain_buf) : m_result.domain;
        rep.riskBadge = m_result.dmarc_enforced ? "DMARC ENFORCED" : "SPOOFING RISK";
        rep.riskColorHex = m_result.dmarc_enforced ? "#34d399" : "#fbbf24";
        rep.kpis = {{"Primary IPv4", m_result.resolved_ip.empty() ? "Unresolved" : m_result.resolved_ip},
                    {"CT Subdomains", std::to_string(m_result.subdomains.size())},
                    {"SPF Record", m_result.has_spf ? "Present" : "Missing"},
                    {"DMARC Policy", m_result.has_dmarc ? "Present" : "Missing"}};
        rep.details = {{"Spoofing Assessment", m_result.spoof_risk},
                       {"SPF Policy", m_result.has_spf ? m_result.spf_record : "None configured"},
                       {"DMARC Policy", m_result.has_dmarc ? m_result.dmarc_record : "None configured"}};

        if (!m_result.subdomains.empty())
        {
            core::ReportTable subTbl;
            subTbl.title = "Certificate Transparency Subdomains";
            subTbl.headers = {"Subdomain", "HTTPS URL"};
            for (const auto &s : m_result.subdomains)
            {
                subTbl.rows.push_back({s, "https://" + s});
            }
            rep.tables.push_back(std::move(subTbl));
        }
        std::string saved = core::HtmlReportExporter::ExportAndOpen(rep, true);
        status_text = "Exported executive HTML report: " + saved;
    }
    ImGui::EndDisabled();

    // Historial reciente
    auto recent = core::HistoryManager::GetByModule("domain", 6);
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
                strncpy_s(m_domain_buf, sizeof(m_domain_buf), recent[i].target.c_str(), _TRUNCATE);
                startDomainAudit(recent[i].target);
            }
            ImGui::PopFont();
            ImGui::PopID();
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    ImGui::Spacing();
    std::string ip_kpi =
        m_result.completed ? (m_result.resolved_ip.empty() ? "Unresolved" : m_result.resolved_ip) : "-";
    std::string sub_kpi = m_result.completed ? std::to_string(m_result.subdomains.size()) + " Hosts" : "-";
    std::string dmarc_kpi = m_result.completed ? (m_result.has_dmarc ? "Present" : "Missing") : "-";
    std::string spf_kpi = m_result.completed ? (m_result.has_spf ? "Present" : "Missing") : "-";

    Components::MetricCard("dm_kpi1", "PRIMARY IPv4", ip_kpi.c_str(), ImVec4(0.24f, 0.72f, 0.98f, 1.00f), 190.0f);
    ImGui::SameLine();
    Components::MetricCard("dm_kpi2", "CT SUBDOMAINS", sub_kpi.c_str(), ImVec4(0.20f, 0.86f, 0.54f, 1.00f), 185.0f);
    ImGui::SameLine();
    Components::MetricCard("dm_kpi3", "SPF RECORD", spf_kpi.c_str(),
                           m_result.has_spf ? ImVec4(0.20f, 0.86f, 0.54f, 1.00f) : ImVec4(0.96f, 0.32f, 0.36f, 1.00f),
                           165.0f);
    ImGui::SameLine();
    Components::MetricCard("dm_kpi4", "DMARC POLICY", dmarc_kpi.c_str(),
                           m_result.has_dmarc ? ImVec4(0.20f, 0.86f, 0.54f, 1.00f) : ImVec4(0.96f, 0.32f, 0.36f, 1.00f),
                           165.0f);

    ImGui::Spacing();

    if (!m_result.completed)
    {
        Components::EmptyState(
            "domain", "No Domain Reconnaissance Executed Yet",
            "Enter a root domain above to enumerate CT subdomains and audit DNS/SPF/DMARC policies.");
        return;
    }

    ImGui::BeginChild("DomainBody", ImVec2(0.0f, 0.0f), true);

    ImVec4 risk_col = m_result.dmarc_enforced
                          ? ImVec4(0.20f, 0.86f, 0.54f, 1.00f)
                          : ((m_result.has_spf || m_result.has_dmarc) ? ImVec4(0.98f, 0.62f, 0.22f, 1.00f)
                                                                      : ImVec4(0.96f, 0.32f, 0.36f, 1.00f));
    Components::StatusBadge(m_result.spoof_risk.c_str(), risk_col);

    if (!m_result.resolved_ip.empty())
    {
        ImGui::SameLine();
        Components::CopyButton("copy_dom_ip", m_result.resolved_ip);
        ImGui::SameLine();
        if (ImGui::SmallButton("Recon Primary IP ->"))
        {
            pivot = {true, 4, m_result.resolved_ip};
        }
    }

    std::string activeDomain = m_result.domain.empty() ? std::string(m_domain_buf) : m_result.domain;
    if (!activeDomain.empty())
    {
        ImGui::SameLine();
        if (ImGui::SmallButton("Audit SSL/TLS & Headers ->"))
        {
            pivot = {true, 6, activeDomain};
        }
    }

    ImGui::Spacing();
    ImGui::PushFont(Theme::MonoFont());
    ImGui::TextColored(ImVec4(0.65f, 0.82f, 1.00f, 1.00f), "SPF   : %s",
                       m_result.has_spf ? m_result.spf_record.c_str() : "None configured");
    if (m_result.has_spf)
    {
        ImGui::SameLine();
        Components::CopyButton("copy_spf", m_result.spf_record);
    }

    ImGui::TextColored(ImVec4(0.65f, 0.82f, 1.00f, 1.00f), "DMARC : %s",
                       m_result.has_dmarc ? m_result.dmarc_record.c_str() : "None configured");
    if (m_result.has_dmarc)
    {
        ImGui::SameLine();
        Components::CopyButton("copy_dmarc", m_result.dmarc_record);
    }

    if (!m_result.mx_records.empty())
    {
        std::string mx_joined;
        for (size_t i = 0; i < m_result.mx_records.size(); ++i)
        {
            if (i > 0)
                mx_joined += " | ";
            mx_joined += m_result.mx_records[i];
        }
        ImGui::TextDisabled("MX    : %s", mx_joined.c_str());
    }
    ImGui::PopFont();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::SetNextItemWidth(280.0f);
    ImGui::InputTextWithHint("##sub_filter", "Filter subdomains...", m_sub_filter, sizeof(m_sub_filter));

    if (!m_result.subdomains.empty())
    {
        ImGui::SameLine();
        if (ImGui::Button("Copy All Subdomains", ImVec2(170.0f, 0.0f)))
        {
            std::string allSubs;
            for (const auto &s : m_result.subdomains)
            {
                allSubs += s + "\r\n";
            }
            ImGui::SetClipboardText(allSubs.c_str());
            status_text = "Copied " + std::to_string(m_result.subdomains.size()) + " subdomains to clipboard.";
        }
    }

    ImGui::Spacing();

    if (ImGui::BeginTable("SubdomainTable", 2,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, 0.0f)))
    {
        ImGui::TableSetupColumn("Discovered Subdomain", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 235.0f);
        ImGui::TableHeadersRow();

        std::string filter_low = ToLowerDomain(m_sub_filter);
        for (size_t i = 0; i < m_result.subdomains.size(); ++i)
        {
            const auto &sub = m_result.subdomains[i];
            if (!filter_low.empty() && ToLowerDomain(sub).find(filter_low) == std::string::npos)
                continue;

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushFont(Theme::MonoFont());
            ImGui::TextUnformatted(sub.c_str());
            ImGui::PopFont();

            ImGui::TableSetColumnIndex(1);
            std::string recon_id = "IP Recon##sub_" + std::to_string(i);
            if (ImGui::SmallButton(recon_id.c_str()))
            {
                pivot = {true, 4, sub};
            }
            ImGui::SameLine();
            std::string ssl_id = "TLS##ssl_" + std::to_string(i);
            if (ImGui::SmallButton(ssl_id.c_str()))
            {
                pivot = {true, 6, sub};
            }
            ImGui::SameLine();
            std::string open_id = "Open##open_" + std::to_string(i);
            if (ImGui::SmallButton(open_id.c_str()))
            {
                std::string url = "https://" + sub;
                ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
        }
        ImGui::EndTable();
    }

    ImGui::EndChild();
}

} // namespace ui::views