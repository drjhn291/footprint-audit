#include "HtmlReportExporter.hpp"

#include <windows.h>

#include <shellapi.h>

#include <cctype>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace core
{

namespace
{

std::string HtmlEscape(const std::string &s)
{
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s)
    {
        switch (c)
        {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '\"':
            out += "&quot;";
            break;
        default:
            out.push_back(c);
            break;
        }
    }
    return out;
}

std::string SanitizeFilename(const std::string &s)
{
    std::string out;
    for (unsigned char c : s)
    {
        if (std::isalnum(c) || c == '-' || c == '_')
            out.push_back(static_cast<char>(c));
        else
            out.push_back('_');
    }
    if (out.empty())
        out = "audit";
    if (out.size() > 48)
        out.resize(48);
    return out;
}

std::string NowFormatted(const char *fmt)
{
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tmLocal{};
    localtime_s(&tmLocal, &tt);
    std::ostringstream oss;
    oss << std::put_time(&tmLocal, fmt);
    return oss.str();
}

} // namespace

std::string HtmlReportExporter::ExportAndOpen(const ExecutiveReportData &data, bool openInBrowser)
{
    std::filesystem::create_directories("reports");
    std::string fileName = "reports/" + SanitizeFilename(data.moduleName) + "_" + SanitizeFilename(data.target) + "_" +
                           NowFormatted("%Y%m%d_%H%M%S") + ".html";

    std::ofstream out(fileName, std::ios::binary | std::ios::trunc);
    if (!out.is_open())
        return {};

    std::string generatedAt = NowFormatted("%Y-%m-%d %H:%M:%S");

    out << R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Footprint Audit - )"
        << HtmlEscape(data.moduleName) << " (" << HtmlEscape(data.target) << R"()</title>
<style>
  :root { --bg: #070b14; --card: #0e1525; --border: #1e2d4a; --text: #f1f5f9; --muted: #94a3b8; --accent: #22d3ee; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 32px; background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; }
  .container { max-width: 1120px; margin: 0 auto; }
  .header { display: flex; justify-content: space-between; align-items: center; padding: 24px 28px; background: linear-gradient(135deg, #0d1628, #111d35); border: 1px solid var(--border); border-radius: 16px; margin-bottom: 22px; }
  .brand { font-size: 12px; letter-spacing: 2px; color: var(--accent); font-weight: 700; text-transform: uppercase; }
  h1 { margin: 6px 0 4px; font-size: 24px; }
  .meta { color: var(--muted); font-size: 13px; font-family: Consolas, monospace; }
  .badge { padding: 8px 16px; border-radius: 999px; font-weight: 700; font-size: 13px; border: 1px solid )"
        << HtmlEscape(data.riskColorHex) << "; color: " << HtmlEscape(data.riskColorHex)
        << R"(; background: rgba(34,211,238,0.08); }
  .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; margin-bottom: 22px; }
  .kpi { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 16px 20px; }
  .kpi-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); }
  .kpi-val { font-size: 22px; font-weight: 700; color: var(--accent); margin-top: 6px; font-family: Consolas, monospace; }
  .panel { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 20px 24px; margin-bottom: 20px; }
  .panel h2 { margin: 0 0 14px; font-size: 16px; color: #e2e8f0; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
  .kv { display: grid; grid-template-columns: 220px 1fr; padding: 8px 0; border-bottom: 1px solid rgba(30,45,74,0.45); font-size: 14px; }
  .kv:last-child { border-bottom: none; }
  .kv-k { color: var(--muted); font-weight: 600; }
  .kv-v { font-family: Consolas, monospace; word-break: break-all; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 12px; background: #131d33; color: var(--accent); font-family: Consolas, monospace; border-bottom: 1px solid var(--border); }
  td { padding: 9px 12px; border-bottom: 1px solid rgba(30,45,74,0.45); font-family: Consolas, monospace; word-break: break-all; }
  tr:nth-child(even) td { background: rgba(255,255,255,0.015); }
  .footer { text-align: center; color: var(--muted); font-size: 12px; margin-top: 28px; }
  @media print { body { background: #fff; color: #0f172a; padding: 12px; } .header, .kpi, .panel { background: #fff; border-color: #cbd5e1; } .kpi-val, th { color: #0284c7; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="brand">Footprint Audit // Executive Intelligence Report</div>
      <h1>)"
        << HtmlEscape(data.moduleName) << " - " << HtmlEscape(data.target) << R"(</h1>
      <div class="meta">Generated: )"
        << HtmlEscape(generatedAt) << R"( | Engine: Native C++20 OSINT Suite</div>
    </div>
    <div class="badge">)"
        << HtmlEscape(data.riskBadge) << R"(</div>
  </div>
)";

    if (!data.kpis.empty())
    {
        out << "  <div class=\"kpis\">\n";
        for (const auto &k : data.kpis)
        {
            out << "    <div class=\"kpi\"><div class=\"kpi-label\">" << HtmlEscape(k.first)
                << "</div><div class=\"kpi-val\">" << HtmlEscape(k.second) << "</div></div>\n";
        }
        out << "  </div>\n";
    }

    if (!data.details.empty())
    {
        out << "  <div class=\"panel\"><h2>Technical Intelligence Summary</h2>\n";
        for (const auto &d : data.details)
        {
            out << "    <div class=\"kv\"><div class=\"kv-k\">" << HtmlEscape(d.first) << "</div><div class=\"kv-v\">"
                << HtmlEscape(d.second) << "</div></div>\n";
        }
        out << "  </div>\n";
    }

    for (const auto &tbl : data.tables)
    {
        out << "  <div class=\"panel\"><h2>" << HtmlEscape(tbl.title) << "</h2><table><thead><tr>";
        for (const auto &h : tbl.headers)
        {
            out << "<th>" << HtmlEscape(h) << "</th>";
        }
        out << "</tr></thead><tbody>\n";
        for (const auto &row : tbl.rows)
        {
            out << "<tr>";
            for (const auto &cell : row)
            {
                out << "<td>" << HtmlEscape(cell) << "</td>";
            }
            out << "</tr>\n";
        }
        out << "</tbody></table></div>\n";
    }

    out << R"(  <div class="footer">Footprint Audit OSINT &amp; Privacy Suite &bull; Tip: Press Ctrl+P to save as PDF</div>
</div>
</body>
</html>
)";
    out.close();

    std::string absPath = std::filesystem::absolute(fileName).string();
    if (openInBrowser)
    {
        ShellExecuteA(nullptr, "open", absPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }
    return absPath;
}

} // namespace core