#include "ReportExporter.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>

using json = nlohmann::json;

namespace core
{

namespace
{

std::string CurrentTimestampUTC()
{
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_utc{};
    gmtime_s(&tm_utc, &t);
    std::ostringstream oss;
    oss << std::put_time(&tm_utc, "%Y-%m-%d %H:%M:%S UTC");
    return oss.str();
}

} // namespace

bool ReportExporter::ExportJson(const std::string &filepath, const std::string &mode, const std::string &target,
                                const std::vector<UsernameFinding> &user_findings, const EmailAuditResult &email_res,
                                const DomainAuditResult &domain_res)
{
    json out;
    out["tool"] = "footprint-audit";
    out["version"] = "2.2.0";
    out["exported_at"] = CurrentTimestampUTC();
    out["mode"] = mode;
    out["target"] = target;

    if (mode == "username")
    {
        json arr = json::array();
        for (const auto &f : user_findings)
        {
            if (f.found)
            {
                arr.push_back({{"platform", f.platform}, {"category", f.category}, {"url", f.url}});
            }
        }
        out["found_count"] = arr.size();
        out["found_profiles"] = arr;
    }
    else if (mode == "email")
    {
        json arr = json::array();
        for (const auto &b : email_res.breaches)
        {
            arr.push_back({{"source", b.source_name},
                           {"exposed_passwords", b.exposed_passwords},
                           {"date", b.date},
                           {"provider", b.provider}});
        }
        out["breach_count"] = arr.size();
        out["breaches"] = arr;
        out["github_user"] = email_res.github_user;
        out["github_url"] = email_res.github_url;
        out["gravatar_name"] = email_res.gravatar_name;
        out["gravatar_url"] = email_res.gravatar_url;
    }
    else if (mode == "domain")
    {
        out["resolved_ip"] = domain_res.resolved_ip;
        out["mx_records"] = domain_res.mx_records;
        out["spf_record"] = domain_res.spf_record;
        out["dmarc_record"] = domain_res.dmarc_record;
        out["spoof_risk"] = domain_res.spoof_risk;
        out["subdomain_count"] = domain_res.subdomains.size();
        out["subdomains"] = domain_res.subdomains;
    }

    std::ofstream file(filepath);
    if (!file.is_open())
        return false;
    file << out.dump(2);
    return true;
}

bool ReportExporter::ExportHtml(const std::string &filepath, const std::string &mode, const std::string &target,
                                const std::vector<UsernameFinding> &user_findings, const EmailAuditResult &email_res,
                                const DomainAuditResult &domain_res)
{
    std::ofstream file(filepath);
    if (!file.is_open())
        return false;

    file << R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Footprint Audit Report</title>
<style>
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #090d16; color: #e6edf3; margin: 0; padding: 32px; }
  .container { max-width: 980px; margin: 0 auto; }
  h1 { color: #38bdf8; margin-bottom: 4px; }
  .meta { color: #8b949e; margin-bottom: 24px; font-size: 14px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 14px; }
  .card { background: #101726; border: 1px solid #24324a; border-radius: 10px; padding: 14px; display: flex; align-items: center; gap: 12px; text-decoration: none; color: inherit; }
  .card:hover { border-color: #38bdf8; }
  .card img { width: 36px; height: 36px; border-radius: 6px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 99px; font-size: 11px; font-weight: 600; background: #1f6feb33; color: #58a6ff; }
  table { width: 100%; border-collapse: collapse; background: #101726; border-radius: 8px; overflow: hidden; }
  th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid #24324a; }
  th { background: #162033; color: #8b949e; font-size: 13px; }
</style>
</head>
<body>
<div class="container">
  <h1>Footprint Audit Report</h1>
  <div class="meta">Target: <strong>)"
         << target << "</strong> &bull; Mode: <strong>" << mode
         << "</strong> &bull; Generated: " << CurrentTimestampUTC() << "</div>\n";

    if (mode == "username")
    {
        file << "<div class=\"grid\">\n";
        for (const auto &f : user_findings)
        {
            if (!f.found)
                continue;
            file << "<a class=\"card\" href=\"" << f.url << "\" target=\"_blank\">"
                 << "<img src=\"https://www.google.com/s2/favicons?domain=" << f.domain << "&sz=64\" alt=\"\">"
                 << "<div><div><strong>" << f.platform << "</strong></div>"
                 << "<span class=\"badge\">" << f.category << "</span></div></a>\n";
        }
        file << "</div>\n";
    }
    else if (mode == "email")
    {
        file
            << "<table><thead><tr><th>Breach Source</th><th>Exposed Passwords / Risk</th><th>Date</th><th>Intelligence "
               "Provider</th></tr></thead><tbody>\n";
        for (const auto &b : email_res.breaches)
        {
            file << "<tr><td>" << b.source_name << "</td><td>" << b.exposed_passwords << "</td><td>" << b.date
                 << "</td><td>" << b.provider << "</td></tr>\n";
        }
        file << "</tbody></table>\n";
    }
    else if (mode == "domain")
    {
        file << "<table><thead><tr><th>Discovered Public Subdomains</th></tr></thead><tbody>\n";
        for (const auto &s : domain_res.subdomains)
        {
            file << "<tr><td>" << s << "</td></tr>\n";
        }
        file << "</tbody></table>\n";
    }

    file << "</div></body></html>\n";
    return true;
}

} // namespace core