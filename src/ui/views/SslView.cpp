#include "SslView.hpp"
#include "../../core/HistoryManager.hpp"
#include "../../core/HtmlReportExporter.hpp"
#include "../Components.hpp"
#include "../Theme.hpp"
#include "imgui.h"
#include <cstdio>
#include <cstring>
#include <thread>

namespace ui::views
{

void SslView::SetTargetAndScan(const std::string &domain, std::atomic<bool> &isScanning, std::string &statusText)
{
    std::snprintf(m_domainInput, sizeof(m_domainInput), "%s", domain.c_str());
    if (isScanning.load())
        return;

    isScanning = true;
    statusText = "Inspecting TLS certificate & security headers for " + domain + "...";
    std::string targetCopy = domain;

    std::thread([this, targetCopy, &isScanning, &statusText]() {
        core::SslAuditResult res = core::SslAuditor::Audit(targetCopy);
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_result = res;
            m_hasRun = true;
        }
        if (res.success)
        {
            core::HistoryManager::Add("ssl", res.host,
                                      "Grade " + res.grade + " | " + std::to_string(res.daysRemaining) + "d left");
            statusText = "SSL/TLS audit completed for " + res.host + " (Grade " + res.grade + ").";
        }
        else
        {
            statusText = "SSL/TLS audit failed: " + res.errorMessage;
        }
        isScanning = false;
    }).detach();
}

void SslView::Render(std::atomic<bool> &isScanning, std::string &statusText)
{
    Components::SectionHeader(
        "SSL/TLS Certificate & HTTP Security Headers",
        "Inspects live X.509 certificates, expiration windows, cipher signatures & OWASP headers.");

    ImGui::SetNextItemWidth(340.0f);
    bool enterPressed = ImGui::InputTextWithHint("##ssl_host", "Enter domain (e.g. github.com)...", m_domainInput,
                                                 sizeof(m_domainInput), ImGuiInputTextFlags_EnterReturnsTrue);

    ImGui::SameLine();
    bool busy = isScanning.load();
    ImGui::BeginDisabled(busy || m_domainInput[0] == '\0');
    if (ImGui::Button("Audit TLS & Headers", ImVec2(175.0f, 0.0f)) ||
        (enterPressed && !busy && m_domainInput[0] != '\0'))
    {
        SetTargetAndScan(m_domainInput, isScanning, statusText);
    }
    ImGui::EndDisabled();

    core::SslAuditResult snap;
    bool hasRun = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        snap = m_result;
        hasRun = m_hasRun;
    }

    if (hasRun && snap.success)
    {
        ImGui::SameLine();
        if (ImGui::Button("Export HTML Report", ImVec2(165.0f, 0.0f)))
        {
            core::ExecutiveReportData rep;
            rep.moduleName = "SSL/TLS & Security Headers";
            rep.target = snap.host;
            rep.riskBadge = "GRADE " + snap.grade + " (" + std::to_string(snap.securityScore) + "/100)";
            rep.riskColorHex =
                (snap.securityScore >= 80) ? "#34d399" : (snap.securityScore >= 50 ? "#fbbf24" : "#f87171");
            rep.kpis = {{"Security Grade", snap.grade + " (" + std::to_string(snap.securityScore) + "%)"},
                        {"Certificate Status", snap.certValid ? "TRUSTED" : "UNTRUSTED"},
                        {"Days Remaining", std::to_string(snap.daysRemaining) + " days"},
                        {"HTTP Status", std::to_string(snap.httpStatus)}};
            rep.details = {{"Common Name (CN)", snap.subject},
                           {"Issuer CA", snap.issuer},
                           {"Valid From", snap.validFrom},
                           {"Expires On", snap.validTo},
                           {"Signature Algorithm", snap.signatureAlgo},
                           {"Serial Number", snap.serialNumber},
                           {"Server Banner", snap.serverBanner}};
            core::ReportTable tbl;
            tbl.title = "HTTP Security Headers Audit";
            tbl.headers = {"Header", "Status", "Value", "Security Purpose"};
            for (const auto &h : snap.headers)
            {
                tbl.rows.push_back(
                    {h.name, h.present ? "PRESENT" : "MISSING", h.present ? h.value : "-", h.recommendation});
            }
            rep.tables.push_back(std::move(tbl));
            std::string saved = core::HtmlReportExporter::ExportAndOpen(rep, true);
            statusText = "Exported executive HTML report: " + saved;
        }
    }

    // Barra de historial rapido
    auto recent = core::HistoryManager::GetByModule("ssl", 6);
    if (!recent.empty())
    {
        ImGui::Spacing();
        ImGui::TextDisabled("Recent:");
        for (size_t i = 0; i < recent.size(); ++i)
        {
            ImGui::SameLine();
            ImGui::PushID(static_cast<int>(i));
            ImGui::PushFont(Theme::MonoFont());
            if (ImGui::SmallButton(recent[i].target.c_str()) && !busy)
            {
                SetTargetAndScan(recent[i].target, isScanning, statusText);
            }
            ImGui::PopFont();
            ImGui::PopID();
        }
    }

    ImGui::Spacing();

    if (!hasRun)
    {
        Components::EmptyState("ssl", "No TLS Audit Executed Yet",
                               "Enter any HTTPS domain above to inspect its certificate chain and OWASP headers.");
        return;
    }

    if (!snap.success)
    {
        Components::StatusBadge(snap.errorMessage.c_str(), ImVec4(0.96f, 0.35f, 0.38f, 1.0f));
        return;
    }

    float cardW = (ImGui::GetContentRegionAvail().x - 36.0f) * 0.25f;
    ImVec4 gradeCol = (snap.securityScore >= 80) ? ImVec4(0.20f, 0.88f, 0.56f, 1.0f)
                                                 : (snap.securityScore >= 50 ? ImVec4(0.98f, 0.75f, 0.18f, 1.0f)
                                                                             : ImVec4(0.96f, 0.35f, 0.38f, 1.0f));
    std::string gradeVal = snap.grade + " (" + std::to_string(snap.securityScore) + "/100)";
    Components::MetricCard("ssl_grade", "SECURITY GRADE", gradeVal.c_str(), gradeCol, cardW);
    ImGui::SameLine();

    ImVec4 certCol = snap.certValid ? ImVec4(0.20f, 0.88f, 0.56f, 1.0f) : ImVec4(0.96f, 0.35f, 0.38f, 1.0f);
    Components::MetricCard("ssl_trust", "TLS CHAIN", snap.certValid ? "VALID & TRUSTED" : "INVALID / UNTRUSTED",
                           certCol, cardW);
    ImGui::SameLine();

    std::string daysStr = std::to_string(snap.daysRemaining) + " Days";
    ImVec4 daysCol = (snap.daysRemaining > 30) ? ImVec4(0.16f, 0.84f, 0.96f, 1.0f) : ImVec4(0.98f, 0.65f, 0.15f, 1.0f);
    Components::MetricCard("ssl_days", "EXPIRATION WINDOW", daysStr.c_str(), daysCol, cardW);
    ImGui::SameLine();

    Components::MetricCard("ssl_algo", "SIGNATURE", snap.signatureAlgo.c_str(), ImVec4(0.66f, 0.55f, 0.98f, 1.0f),
                           cardW);

    ImGui::Spacing();

    ImGui::BeginChild("SslDetailsPanel", ImVec2(0.0f, 0.0f), true);
    ImGui::PushFont(Theme::BoldFont());
    ImGui::TextColored(ImVec4(0.20f, 0.84f, 0.96f, 1.0f), "X.509 Certificate Metadata");
    ImGui::PopFont();
    ImGui::Spacing();

    ImGui::PushFont(Theme::MonoFont());
    ImGui::Text("Subject CN   : %s", snap.subject.c_str());
    ImGui::Text("Issuer CA    : %s", snap.issuer.c_str());
    ImGui::Text("Validity     : %s  ->  %s", snap.validFrom.c_str(), snap.validTo.c_str());
    ImGui::Text("Serial Hex   : %s", snap.serialNumber.c_str());
    ImGui::SameLine();
    Components::CopyButton("copy_serial", snap.serialNumber);
    ImGui::Text("Server Header: %s", snap.serverBanner.c_str());
    ImGui::PopFont();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::PushFont(Theme::BoldFont());
    ImGui::TextColored(ImVec4(0.20f, 0.84f, 0.96f, 1.0f), "OWASP HTTP Security Headers");
    ImGui::PopFont();
    ImGui::Spacing();

    if (ImGui::BeginTable("HeadersTable", 4,
                          ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupColumn("Header Name", ImGuiTableColumnFlags_WidthFixed, 230.0f);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Configured Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Security Impact", ImGuiTableColumnFlags_WidthFixed, 270.0f);
        ImGui::TableHeadersRow();

        for (const auto &h : snap.headers)
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushFont(Theme::MonoFont());
            ImGui::TextUnformatted(h.name.c_str());
            ImGui::PopFont();

            ImGui::TableNextColumn();
            if (h.present)
                Components::StatusBadge("PRESENT", ImVec4(0.20f, 0.88f, 0.56f, 1.0f));
            else
                Components::StatusBadge("MISSING", ImVec4(0.96f, 0.35f, 0.38f, 1.0f));

            ImGui::TableNextColumn();
            ImGui::PushFont(Theme::MonoFont());
            ImGui::TextDisabled("%s", h.present ? h.value.c_str() : "Not configured");
            if (h.present && ImGui::IsItemHovered())
            {
                ImGui::SetTooltip("%s", h.value.c_str());
            }
            ImGui::PopFont();

            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", h.recommendation.c_str());
        }
        ImGui::EndTable();
    }

    ImGui::EndChild();
}

} // namespace ui::views