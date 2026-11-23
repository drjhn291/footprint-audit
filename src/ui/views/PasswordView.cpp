#include "PasswordView.hpp"
#include "../../network/BreachScanner.hpp"
#include "../Components.hpp"
#include "../Theme.hpp"
#include "imgui.h"
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <thread>

namespace ui::views
{

namespace
{

struct LocalStrengthInfo
{
    double entropyBits = 0.0;
    int charsetSize = 0;
    bool hasLower = false;
    bool hasUpper = false;
    bool hasDigit = false;
    bool hasSymbol = false;
    const char *rating = "EMPTY";
    ImVec4 color = ImVec4(0.45f, 0.55f, 0.72f, 1.0f);
};

LocalStrengthInfo EvaluateLocalStrength(const char *pwd)
{
    LocalStrengthInfo info;
    size_t len = std::strlen(pwd);
    if (len == 0)
        return info;

    for (size_t i = 0; i < len; ++i)
    {
        unsigned char c = static_cast<unsigned char>(pwd[i]);
        if (std::islower(c))
            info.hasLower = true;
        else if (std::isupper(c))
            info.hasUpper = true;
        else if (std::isdigit(c))
            info.hasDigit = true;
        else
            info.hasSymbol = true;
    }

    if (info.hasLower)
        info.charsetSize += 26;
    if (info.hasUpper)
        info.charsetSize += 26;
    if (info.hasDigit)
        info.charsetSize += 10;
    if (info.hasSymbol)
        info.charsetSize += 33;

    if (info.charsetSize > 0)
    {
        info.entropyBits = static_cast<double>(len) * std::log2(static_cast<double>(info.charsetSize));
    }

    if (info.entropyBits < 40.0)
    {
        info.rating = "WEAK";
        info.color = ImVec4(0.96f, 0.32f, 0.36f, 1.00f);
    }
    else if (info.entropyBits < 60.0)
    {
        info.rating = "MODERATE";
        info.color = ImVec4(0.98f, 0.65f, 0.18f, 1.00f);
    }
    else if (info.entropyBits < 80.0)
    {
        info.rating = "STRONG";
        info.color = ImVec4(0.20f, 0.86f, 0.54f, 1.00f);
    }
    else
    {
        info.rating = "EXCELLENT";
        info.color = ImVec4(0.16f, 0.84f, 0.96f, 1.00f);
    }

    return info;
}

} // namespace

void PasswordView::Render(std::atomic<bool> &is_scanning, std::string &status_text)
{
    Components::SectionHeader(
        "Private Password Exposure Check (HIBP k-Anonymity)",
        "Your password never leaves your machine. Only the first 5 characters of its SHA-1 hash are queried.");

    ImGui::SetNextItemWidth(340.0f);
    ImGuiInputTextFlags flags =
        (m_show_plain ? ImGuiInputTextFlags_None : ImGuiInputTextFlags_Password) | ImGuiInputTextFlags_EnterReturnsTrue;
    bool enter_pressed =
        ImGui::InputTextWithHint("##pass_input", "Enter password to verify...", m_pass_buf, sizeof(m_pass_buf), flags);
    ImGui::SameLine();

    ImGui::Checkbox("Show", &m_show_plain);
    ImGui::SameLine();

    auto runCheck = [&]() {
        is_scanning = true;
        status_text = "Querying k-Anonymity SHA-1 prefix range...";
        std::string pwd(m_pass_buf);

        std::thread([this, &is_scanning, &status_text, pwd]() {
            int cnt = network::BreachScanner::CheckPasswordPwnedCount(pwd);
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_pwned_count = cnt;
                status_text = "Password k-Anonymity verification finished.";
            }
            is_scanning = false;
        }).detach();
    };

    ImGui::BeginDisabled(is_scanning.load() || strlen(m_pass_buf) == 0);
    if (ImGui::Button("Verify Password", ImVec2(145.0f, 0.0f)) || (enter_pressed && !is_scanning.load()))
    {
        runCheck();
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear", ImVec2(75.0f, 0.0f)))
    {
        std::memset(m_pass_buf, 0, sizeof(m_pass_buf));
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pwned_count = -2;
    }
    ImGui::EndDisabled();

    LocalStrengthInfo strength = EvaluateLocalStrength(m_pass_buf);

    std::lock_guard<std::mutex> lock(m_mutex);

    ImGui::Spacing();
    std::string exposure_val = (m_pwned_count >= 0) ? (std::to_string(m_pwned_count) + " Hits") : "Pending";
    ImVec4 exposure_col = (m_pwned_count > 0) ? ImVec4(0.96f, 0.32f, 0.36f, 1.00f)
                                              : (m_pwned_count == 0 ? ImVec4(0.20f, 0.86f, 0.54f, 1.00f)
                                                                    : ImVec4(0.24f, 0.72f, 0.98f, 1.00f));

    char entKpi[48] = "-";
    if (strlen(m_pass_buf) > 0)
    {
        std::snprintf(entKpi, sizeof(entKpi), "%.0f bits (%s)", strength.entropyBits, strength.rating);
    }

    Components::MetricCard("pw_kpi1", "BREACH CORPUS HITS", exposure_val.c_str(), exposure_col, 210.0f);
    ImGui::SameLine();
    Components::MetricCard("pw_kpi2", "LOCAL ENTROPY", entKpi, strength.color, 230.0f);
    ImGui::SameLine();
    Components::MetricCard("pw_kpi3", "PRIVACY PROTOCOL", "SHA-1 k-Anon", ImVec4(0.65f, 0.55f, 0.98f, 1.00f), 205.0f);

    ImGui::Spacing();

    if (m_pwned_count == -2 && strlen(m_pass_buf) == 0)
    {
        Components::EmptyState(
            "pass", "Zero-Knowledge Password Audit Ready",
            "Type a password above to measure local entropy and check HIBP k-Anonymity breach dumps.");
        return;
    }

    ImGui::BeginChild("PassContainer", ImVec2(0.0f, 0.0f), true);

    if (m_pwned_count == 0)
    {
        Components::StatusBadge("[SAFE] This password was NOT found in any known public breach corpus.",
                                ImVec4(0.20f, 0.86f, 0.54f, 1.00f));
    }
    else if (m_pwned_count > 0)
    {
        std::string msg = "[COMPROMISED] Appeared " + std::to_string(m_pwned_count) +
                          " times in public data leaks! Change this password immediately.";
        Components::StatusBadge(msg.c_str(), ImVec4(0.96f, 0.32f, 0.36f, 1.00f));
    }
    else if (m_pwned_count == -1)
    {
        Components::StatusBadge("[ERROR] Could not reach PwnedPasswords API.", ImVec4(0.98f, 0.65f, 0.20f, 1.00f));
    }

    if (strlen(m_pass_buf) > 0)
    {
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::PushFont(Theme::BoldFont());
        ImGui::TextColored(ImVec4(0.24f, 0.78f, 0.98f, 1.00f), "Local Cryptographic Entropy Breakdown");
        ImGui::PopFont();
        ImGui::Spacing();

        ImGui::PushFont(Theme::MonoFont());
        ImGui::Text("Length         : %zu characters", std::strlen(m_pass_buf));
        ImGui::Text("Character Pool : %d possible symbols  [Lower: %s | Upper: %s | Digits: %s | Symbols: %s]",
                    strength.charsetSize, strength.hasLower ? "YES" : "NO", strength.hasUpper ? "YES" : "NO",
                    strength.hasDigit ? "YES" : "NO", strength.hasSymbol ? "YES" : "NO");
        ImGui::Text("Shannon Metric : %.2f bits  (%s)", strength.entropyBits, strength.rating);
        ImGui::PopFont();
    }

    ImGui::EndChild();
}

} // namespace ui::views