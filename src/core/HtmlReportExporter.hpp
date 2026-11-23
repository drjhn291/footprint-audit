#pragma once

#include <string>
#include <utility>
#include <vector>

namespace core
{

struct ReportTable
{
    std::string title;
    std::vector<std::string> headers;
    std::vector<std::vector<std::string>> rows;
};

struct ExecutiveReportData
{
    std::string moduleName;
    std::string target;
    std::string riskBadge;
    std::string riskColorHex = "#22d3ee";
    std::vector<std::pair<std::string, std::string>> kpis;
    std::vector<std::pair<std::string, std::string>> details;
    std::vector<ReportTable> tables;
};

class HtmlReportExporter
{
  public:
    static std::string ExportAndOpen(const ExecutiveReportData &data, bool openInBrowser = true);
};

} // namespace core