#include "DomainScanner.hpp"
#include "HttpClient.hpp"
#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>
#include <set>
#include <sstream>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <windns.h>
#include <ws2tcpip.h>

#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "ws2_32.lib")

using json = nlohmann::json;

namespace network
{

namespace
{

std::string CleanDomainInput(std::string d)
{
    std::transform(d.begin(), d.end(), d.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    size_t scheme = d.find("://");
    if (scheme != std::string::npos)
        d = d.substr(scheme + 3);
    size_t slash = d.find('/');
    if (slash != std::string::npos)
        d = d.substr(0, slash);
    while (!d.empty() && (d.front() == '.' || std::isspace(static_cast<unsigned char>(d.front()))))
        d.erase(d.begin());
    while (!d.empty() && (d.back() == '.' || std::isspace(static_cast<unsigned char>(d.back()))))
        d.pop_back();
    return d;
}

std::string ToLowerStr(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

void AddSubdomain(std::set<std::string> &out, std::string host, const std::string &root_domain)
{
    host = ToLowerStr(host);
    while (!host.empty() && (std::isspace(static_cast<unsigned char>(host.front())) || host.front() == '.'))
        host.erase(host.begin());
    while (!host.empty() && (std::isspace(static_cast<unsigned char>(host.back())) || host.back() == '.'))
        host.pop_back();
    if (host.rfind("*.", 0) == 0)
        host = host.substr(2);
    if (host.empty())
        return;

    for (unsigned char c : host)
    {
        if (!(std::isalnum(c) || c == '.' || c == '-' || c == '_'))
            return;
    }

    if (host == root_domain)
    {
        out.insert(host);
        return;
    }

    std::string suffix = "." + root_domain;
    if (host.size() > suffix.size() && host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0)
    {
        out.insert(host);
    }
}

std::vector<std::string> QueryTxtRecords(const std::string &name)
{
    std::vector<std::string> records;
    PDNS_RECORDA pDnsRecord = nullptr;
    DNS_STATUS status = DnsQuery_A(name.c_str(), DNS_TYPE_TEXT, DNS_QUERY_BYPASS_CACHE, nullptr, &pDnsRecord, nullptr);
    if (status == 0 && pDnsRecord)
    {
        for (PDNS_RECORDA p = pDnsRecord; p != nullptr; p = p->pNext)
        {
            if (p->wType == DNS_TYPE_TEXT)
            {
                std::string full_txt;
                for (DWORD i = 0; i < p->Data.TXT.dwStringCount; ++i)
                {
                    if (p->Data.TXT.pStringArray[i])
                    {
                        full_txt += p->Data.TXT.pStringArray[i];
                    }
                }
                if (!full_txt.empty())
                {
                    records.push_back(full_txt);
                }
            }
        }
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    }
    return records;
}

} // namespace

std::string DomainScanner::ResolveHostToIp(const std::string &host)
{
    std::string clean = CleanDomainInput(host);
    if (clean.empty())
        return "";

    IN_ADDR addr{};
    if (inet_pton(AF_INET, clean.c_str(), &addr) == 1)
    {
        return clean;
    }

    PDNS_RECORDA pDnsRecord = nullptr;
    DNS_STATUS status = DnsQuery_A(clean.c_str(), DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr, &pDnsRecord, nullptr);
    std::string resolved;
    if (status == 0 && pDnsRecord)
    {
        for (PDNS_RECORDA p = pDnsRecord; p != nullptr; p = p->pNext)
        {
            if (p->wType == DNS_TYPE_A)
            {
                char ipBuf[INET_ADDRSTRLEN]{};
                IN_ADDR inAddr{};
                inAddr.S_un.S_addr = p->Data.A.IpAddress;
                if (inet_ntop(AF_INET, &inAddr, ipBuf, sizeof(ipBuf)))
                {
                    resolved = ipBuf;
                    break;
                }
            }
        }
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    }
    return resolved;
}

core::DomainAuditResult DomainScanner::AuditDomain(const std::string &domain)
{
    core::DomainAuditResult res;
    res.domain = CleanDomainInput(domain);
    if (res.domain.empty())
        return res;

    res.resolved_ip = ResolveHostToIp(res.domain);

    PDNS_RECORDA pMxRecord = nullptr;
    if (DnsQuery_A(res.domain.c_str(), DNS_TYPE_MX, DNS_QUERY_BYPASS_CACHE, nullptr, &pMxRecord, nullptr) == 0 &&
        pMxRecord)
    {
        for (PDNS_RECORDA p = pMxRecord; p != nullptr; p = p->pNext)
        {
            if (p->wType == DNS_TYPE_MX && p->Data.MX.pNameExchange)
            {
                res.mx_records.push_back(std::to_string(p->Data.MX.wPreference) + " " +
                                         std::string(p->Data.MX.pNameExchange));
            }
        }
        DnsRecordListFree(pMxRecord, DnsFreeRecordList);
    }

    auto root_txts = QueryTxtRecords(res.domain);
    for (const auto &txt : root_txts)
    {
        std::string low = ToLowerStr(txt);
        if (low.find("v=spf1") != std::string::npos)
        {
            res.has_spf = true;
            res.spf_record = txt;
            break;
        }
    }

    auto dmarc_txts = QueryTxtRecords("_dmarc." + res.domain);
    for (const auto &txt : dmarc_txts)
    {
        std::string low = ToLowerStr(txt);
        if (low.find("v=dmarc1") != std::string::npos)
        {
            res.has_dmarc = true;
            res.dmarc_record = txt;
            if (low.find("p=reject") != std::string::npos || low.find("p=quarantine") != std::string::npos)
            {
                res.dmarc_enforced = true;
            }
            break;
        }
    }

    if (res.has_spf && res.has_dmarc && res.dmarc_enforced)
    {
        res.spoof_risk = "LOW (Strict SPF + DMARC Enforced)";
    }
    else if (res.has_spf || res.has_dmarc)
    {
        res.spoof_risk = "MEDIUM (Partial Policy or DMARC p=none)";
    }
    else
    {
        res.spoof_risk = "HIGH (No SPF/DMARC - Vulnerable to Spoofing)";
    }

    std::set<std::string> unique_subs;

    // 1. HackerTarget HostSearch (secuencial, muy rápido)
    HttpResponse ht_resp = HttpClient::Get("https://api.hackertarget.com/hostsearch/?q=" + res.domain, 5000);
    if (ht_resp.status == 200 && !ht_resp.body.empty() && ht_resp.body.find("API count exceeded") == std::string::npos)
    {
        std::istringstream iss(ht_resp.body);
        std::string line;
        while (std::getline(iss, line))
        {
            size_t comma = line.find(',');
            std::string host = (comma != std::string::npos) ? line.substr(0, comma) : line;
            AddSubdomain(unique_subs, host, res.domain);
        }
    }

    // 2. AlienVault OTX Passive DNS
    HttpResponse otx_resp =
        HttpClient::Get("https://otx.alienvault.com/api/v1/indicators/domain/" + res.domain + "/passive_dns", 5000);
    if (otx_resp.status == 200 && !otx_resp.body.empty())
    {
        try
        {
            auto j = json::parse(otx_resp.body);
            if (j.contains("passive_dns") && j["passive_dns"].is_array())
            {
                for (const auto &item : j["passive_dns"])
                {
                    if (item.is_object() && item.contains("hostname") && item["hostname"].is_string())
                    {
                        AddSubdomain(unique_subs, item["hostname"].get<std::string>(), res.domain);
                    }
                }
            }
        }
        catch (...)
        {
        }
    }

    // 3. urlscan.io
    HttpResponse us_resp =
        HttpClient::Get("https://urlscan.io/api/v1/search/?q=domain:" + res.domain + "&size=100", 5000);
    if (us_resp.status == 200 && !us_resp.body.empty())
    {
        try
        {
            auto j = json::parse(us_resp.body);
            if (j.contains("results") && j["results"].is_array())
            {
                for (const auto &item : j["results"])
                {
                    if (!item.is_object())
                        continue;
                    if (item.contains("page") && item["page"].is_object())
                    {
                        AddSubdomain(unique_subs, item["page"].value("domain", ""), res.domain);
                    }
                    if (item.contains("task") && item["task"].is_object())
                    {
                        AddSubdomain(unique_subs, item["task"].value("domain", ""), res.domain);
                    }
                }
            }
        }
        catch (...)
        {
        }
    }

    // 4. Respaldo CertSpotter y crt.sh si las fuentes rápidas devolvieron pocos resultados
    if (unique_subs.size() < 10)
    {
        HttpResponse cs_resp = HttpClient::Get("https://api.certspotter.com/v1/issuances?domain=" + res.domain +
                                                   "&include_subdomains=true&expand=dns_names",
                                               6000);
        if (cs_resp.status == 200 && !cs_resp.body.empty())
        {
            try
            {
                auto j = json::parse(cs_resp.body);
                if (j.is_array())
                {
                    for (const auto &item : j)
                    {
                        if (item.is_object() && item.contains("dns_names") && item["dns_names"].is_array())
                        {
                            for (const auto &dns_val : item["dns_names"])
                            {
                                if (dns_val.is_string())
                                {
                                    AddSubdomain(unique_subs, dns_val.get<std::string>(), res.domain);
                                }
                            }
                        }
                    }
                }
            }
            catch (...)
            {
            }
        }
    }

    if (unique_subs.empty())
    {
        HttpResponse crt_resp =
            HttpClient::Get("https://crt.sh/?q=%25." + res.domain + "&exclude=expired&output=json", 7000);
        if (crt_resp.status == 200 && !crt_resp.body.empty())
        {
            try
            {
                auto j = json::parse(crt_resp.body);
                if (j.is_array())
                {
                    for (const auto &entry : j)
                    {
                        if (!entry.is_object())
                            continue;
                        std::string nv = entry.value("name_value", "");
                        std::istringstream iss(nv);
                        std::string line;
                        while (std::getline(iss, line))
                        {
                            AddSubdomain(unique_subs, line, res.domain);
                        }
                    }
                }
            }
            catch (...)
            {
            }
        }
    }

    res.subdomains.assign(unique_subs.begin(), unique_subs.end());
    res.completed = true;
    return res;
}

} // namespace network