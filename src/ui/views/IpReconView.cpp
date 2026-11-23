#include "IpReconView.hpp"
#include "../../core/HistoryManager.hpp"
#include "../../core/HtmlReportExporter.hpp"
#include "../../network/IpReconScanner.hpp"
#include "../Components.hpp"
#include "../Theme.hpp"
#include "imgui.h"
#include <cstring>
#include <shellapi.h>
#include <thread>
#include <windows.h>

namespace ui::views
{

void IpReconView::Render(std::atomic<bool> &is_scanning, std::string &status_text, core::PivotAction &pivot)
{
    Components::SectionHeader("IP & Server Reconnaissance (Shodan InternetDB)",
                              "Enumerates exposed ports, known CVEs, CPE software fingerprints, hostnames, ASN & "
                              "geolocation without API keys.");

    bool trigger_pivot = false;
    if (pivot.pending && pivot.target_tab == 4)
    {
        strncpy_s(m_target_buf, sizeof(m_target_buf), pivot.payload.c_str(), _TRUNCATE);
        pivot.pending = false;
        if (!is_scanning.load() && strlen(m_target_buf) > 0)
        {
            trigger_pivot = true;
        }
    }

    ImGui::SetNextItemWidth(320.0f);
    bool enter_pressed =
        ImGui::InputTextWithHint("##ip_input", "Enter IPv4 or hostname (e.g. 1.1.1.1)...", m_target_buf,
                                 sizeof(m_target_buf), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();

    auto startRecon = [&](const std::string &target) {
        is_scanning = true;
        status_text = "Querying Shodan InternetDB & Geolocation for " + target + "...";

        std::thread([this, &is_scanning, &status_text, target]() {
            auto res = network::IpReconScanner::ReconTarget(target);
            if (res.error.empty() && !res.ip.empty())
            {
                core::HistoryManager::Add("ip", res.ip,
                                          std::to_string(res.ports.size()) + " ports, " +
                                              std::to_string(res.vulns.size()) + " CVEs");
            }
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_result = std::move(res);
                if (!m_result.error.empty())
                {
                    status_text = "IP Recon error: " + m_result.error;
                }
                else
                {
                    status_text = "IP Recon complete for " + m_result.ip + ": " +
                                  std::to_string(m_result.ports.size()) + " open ports, " +
                                  std::to_string(m_result.vulns.size()) + " CVEs.";
                }
            }
            is_scanning = false;
        }).detach();
    };

    ImGui::BeginDisabled(is_scanning.load() || strlen(m_target_buf) == 0);
    if (ImGui::Button("Recon Server", ImVec2(140.0f, 0.0f)) || (enter_pressed && !is_scanning.load()) || trigger_pivot)
    {
        startRecon(m_target_buf);
    }
    ImGui::EndDisabled();

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_result.completed && m_result.error.empty())
        {
            ImGui::SameLine();
            if (ImGui::Button("Open in Shodan.io ->", ImVec2(165.0f, 0.0f)))
            {
                std::string shodanUrl = "https://www.shodan.io/host/" + m_result.ip;
                ShellExecuteA(nullptr, "open", shodanUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
            ImGui::SameLine();
            if (ImGui::Button("Export HTML Report", ImVec2(165.0f, 0.0f)))
            {
                std::string portsStr;
                for (size_t i = 0; i < m_result.ports.size(); ++i)
                {
                    if (i > 0)
                        portsStr += ", ";
                    portsStr += std::to_string(m_result.ports[i]);
                }
                core::ExecutiveReportData rep;
                rep.moduleName = "IP & Server Reconnaissance";
                rep.target = m_result.ip;
                rep.riskBadge =
                    m_result.vulns.empty() ? "0 KNOWN CVES" : std::to_string(m_result.vulns.size()) + " CVES EXPOSED";
                rep.riskColorHex = m_result.vulns.empty() ? "#34d399" : "#f87171";
                rep.kpis = {{"Resolved IP", m_result.ip},
                            {"Open Ports", std::to_string(m_result.ports.size())},
                            {"Known CVEs", std::to_string(m_result.vulns.size())},
                            {"Location", m_result.city + ", " + m_result.country_code}};
                rep.details = {{"ISP / Organization", m_result.isp + " (" + m_result.org + ")"},
                               {"ASN", m_result.asn.empty() ? "Unknown" : m_result.asn},
                               {"Exposed Ports", portsStr.empty() ? "None detected" : portsStr}};
                if (!m_result.vulns.empty())
                {
                    core::ReportTable cveTbl;
                    cveTbl.title = "Associated CVE Vulnerabilities";
                    cveTbl.headers = {"CVE Identifier", "NIST NVD Reference"};
                    for (const auto &v : m_result.vulns)
                    {
                        cveTbl.rows.push_back({v, "https://nvd.nist.gov/vuln/detail/" + v});
                    }
                    rep.tables.push_back(std::move(cveTbl));
                }
                std::string saved = core::HtmlReportExporter::ExportAndOpen(rep, true);
                status_text = "Exported executive HTML report: " + saved;
            }
        }
    }

    // Historial reciente
    auto recent = core::HistoryManager::GetByModule("ip", 6);
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
                strncpy_s(m_target_buf, sizeof(m_target_buf), recent[i].target.c_str(), _TRUNCATE);
                startRecon(recent[i].target);
            }
            ImGui::PopFont();
            ImGui::PopID();
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    ImGui::Spacing();
    std::string ip_kpi = m_result.completed && !m_result.ip.empty() ? m_result.ip : "-";
    std::string ports_kpi = m_result.completed ? std::to_string(m_result.ports.size()) + " Open" : "-";
    std::string cve_kpi = m_result.completed ? std::to_string(m_result.vulns.size()) + " CVEs" : "-";
    std::string loc_kpi =
        m_result.completed && !m_result.country_code.empty() ? (m_result.city + ", " + m_result.country_code) : "-";

    Components::MetricCard("ip_kpi1", "RESOLVED IP", ip_kpi.c_str(), ImVec4(0.24f, 0.72f, 0.98f, 1.00f), 190.0f);
    ImGui::SameLine();
    Components::MetricCard(
        "ip_kpi2", "EXPOSED PORTS", ports_kpi.c_str(),
        m_result.ports.empty() ? ImVec4(0.20f, 0.86f, 0.54f, 1.00f) : ImVec4(0.98f, 0.58f, 0.16f, 1.00f), 175.0f);
    ImGui::SameLine();
    Components::MetricCard(
        "ip_kpi3", "KNOWN VULNS", cve_kpi.c_str(),
        m_result.vulns.empty() ? ImVec4(0.20f, 0.86f, 0.54f, 1.00f) : ImVec4(0.96f, 0.32f, 0.36f, 1.00f), 175.0f);
    ImGui::SameLine();
    Components::MetricCard("ip_kpi4", "LOCATION", loc_kpi.c_str(), ImVec4(0.62f, 0.54f, 0.98f, 1.00f), 220.0f);

    ImGui::Spacing();

    if (!m_result.completed)
    {
        Components::EmptyState(
            "ip", "No Server Reconnaissance Executed Yet",
            "Enter an IPv4 address or hostname above (or pivot from Domain Recon) to inspect ports & CVEs.");
        return;
    }

    ImGui::BeginChild("IpReconBody", ImVec2(0.0f, 0.0f), true);

    if (!m_result.error.empty())
    {
        Components::StatusBadge(m_result.error.c_str(), ImVec4(0.96f, 0.32f, 0.36f, 1.00f));
    }
    else
    {
        ImGui::PushFont(Theme::BoldFont());
        ImGui::TextColored(ImVec4(0.24f, 0.78f, 0.98f, 1.00f), "Network & Infrastructure Intelligence");
        ImGui::PopFont();
        ImGui::Spacing();

        ImGui::PushFont(Theme::MonoFont());
        ImGui::Text("Target IPv4  : %s", m_result.ip.c_str());
        ImGui::SameLine();
        Components::CopyButton("copy_ip_val", m_result.ip);

        ImGui::Text("ISP / Org    : %s (%s)", m_result.isp.c_str(), m_result.org.c_str());
        ImGui::Text("ASN          : %s", m_result.asn.empty() ? "Unknown" : m_result.asn.c_str());
        ImGui::Text("Network Type : %s%s", m_result.is_hosting ? "Cloud / Datacenter  " : "Standard Network  ",
                    m_result.is_proxy ? "[VPN / Proxy Detected]" : "");
        ImGui::PopFont();

        if (!m_result.tags.empty())
        {
            std::string tags_str;
            for (size_t i = 0; i < m_result.tags.size(); ++i)
            {
                if (i > 0)
                    tags_str += ", ";
                tags_str += m_result.tags[i];
            }
            ImGui::Spacing();
            Components::StatusBadge(("Tags: " + tags_str).c_str(), ImVec4(0.24f, 0.72f, 0.98f, 1.00f));
        }

        if (!m_result.ports.empty())
        {
            std::string ports_str;
            for (size_t i = 0; i < m_result.ports.size(); ++i)
            {
                if (i > 0)
                    ports_str += ", ";
                ports_str += std::to_string(m_result.ports[i]);
            }
            ImGui::Spacing();
            ImGui::PushFont(Theme::BoldFont());
            ImGui::TextColored(ImVec4(0.98f, 0.62f, 0.22f, 1.00f), "Open Ports:");
            ImGui::PopFont();
            ImGui::SameLine();
            ImGui::PushFont(Theme::MonoFont());
            ImGui::TextUnformatted(ports_str.c_str());
            ImGui::SameLine();
            Components::CopyButton("copy_ports", ports_str);
            ImGui::PopFont();
        }

        if (!m_result.cpes.empty())
        {
            ImGui::Spacing();
            ImGui::PushFont(Theme::BoldFont());
            ImGui::TextColored(ImVec4(0.65f, 0.82f, 1.00f, 1.00f), "Detected Software Fingerprints (CPE):");
            ImGui::PopFont();
            ImGui::PushFont(Theme::MonoFont());
            for (const auto &cpe : m_result.cpes)
            {
                ImGui::BulletText("%s", cpe.c_str());
            }
            ImGui::PopFont();
        }

        if (!m_result.vulns.empty())
        {
            ImGui::Spacing();
            ImGui::PushFont(Theme::BoldFont());
            ImGui::TextColored(ImVec4(0.96f, 0.32f, 0.36f, 1.00f),
                               "Associated Vulnerabilities (Click CVE to inspect NIST NVD):");
            ImGui::PopFont();
            ImGui::PushFont(Theme::MonoFont());
            for (size_t i = 0; i < m_result.vulns.size(); ++i)
            {
                if (i > 0 && (i % 5) != 0)
                    ImGui::SameLine();
                if (ImGui::SmallButton(m_result.vulns[i].c_str()))
                {
                    std::string nvd = "https://nvd.nist.gov/vuln/detail/" + m_result.vulns[i];
                    ShellExecuteA(nullptr, "open", nvd.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
                }
            }
            ImGui::PopFont();
        }

        if (!m_result.hostnames.empty())
        {
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::PushFont(Theme::BoldFont());
            ImGui::TextColored(ImVec4(0.24f, 0.78f, 0.98f, 1.00f), "Reverse DNS Hostnames:");
            ImGui::PopFont();
            ImGui::PushFont(Theme::MonoFont());
            for (size_t i = 0; i < m_result.hostnames.size(); ++i)
            {
                ImGui::BulletText("%s", m_result.hostnames[i].c_str());
                ImGui::SameLine();
                std::string p_id = "Domain Recon ->##host_" + std::to_string(i);
                if (ImGui::SmallButton(p_id.c_str()))
                {
                    pivot = {true, 3, m_result.hostnames[i]};
                }
            }
            ImGui::PopFont();
        }
    }

    ImGui::EndChild();
}

} // namespace ui::views