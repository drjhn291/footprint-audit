#include "IpReconScanner.hpp"
#include "DomainScanner.hpp"
#include "HttpClient.hpp"
#include <algorithm>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace network
{

core::IpReconResult IpReconScanner::ReconTarget(const std::string &target)
{
    core::IpReconResult res;
    res.query = target;

    std::string ip = DomainScanner::ResolveHostToIp(target);
    if (ip.empty())
    {
        res.error = "Could not resolve target to a valid IPv4 address.";
        res.completed = true;
        return res;
    }
    res.ip = ip;

    HttpResponse shodan = HttpClient::Get("https://internetdb.shodan.io/" + ip, 10000);
    if (shodan.status == 200 && !shodan.body.empty())
    {
        try
        {
            auto j = json::parse(shodan.body);
            if (j.contains("ports") && j["ports"].is_array())
            {
                for (const auto &p : j["ports"])
                {
                    if (p.is_number_integer())
                        res.ports.push_back(p.get<int>());
                }
                std::sort(res.ports.begin(), res.ports.end());
            }
            if (j.contains("vulns") && j["vulns"].is_array())
            {
                for (const auto &v : j["vulns"])
                {
                    if (v.is_string())
                        res.vulns.push_back(v.get<std::string>());
                }
            }
            if (j.contains("hostnames") && j["hostnames"].is_array())
            {
                for (const auto &h : j["hostnames"])
                {
                    if (h.is_string())
                        res.hostnames.push_back(h.get<std::string>());
                }
            }
            if (j.contains("tags") && j["tags"].is_array())
            {
                for (const auto &t : j["tags"])
                {
                    if (t.is_string())
                        res.tags.push_back(t.get<std::string>());
                }
            }
            if (j.contains("cpes") && j["cpes"].is_array())
            {
                for (const auto &c : j["cpes"])
                {
                    if (c.is_string())
                        res.cpes.push_back(c.get<std::string>());
                }
            }
        }
        catch (...)
        {
        }
    }

    HttpResponse geo = HttpClient::Get(
        "http://ip-api.com/json/" + ip + "?fields=status,country,countryCode,regionName,city,isp,org,as,proxy,hosting",
        9000);
    if (geo.status == 200 && !geo.body.empty())
    {
        try
        {
            auto g = json::parse(geo.body);
            if (g.value("status", "") == "success")
            {
                res.country = g.value("country", "");
                res.country_code = g.value("countryCode", "");
                res.region = g.value("regionName", "");
                res.city = g.value("city", "");
                res.isp = g.value("isp", "");
                res.org = g.value("org", "");
                res.asn = g.value("as", "");
                res.is_proxy = g.value("proxy", false);
                res.is_hosting = g.value("hosting", false);
            }
        }
        catch (...)
        {
        }
    }

    res.completed = true;
    return res;
}

} // namespace network