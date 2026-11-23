#include "ConfigLoader.hpp"
#include "PlatformCatalogData.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <nlohmann/json.hpp>
#include <unordered_set>

using json = nlohmann::json;

namespace core
{

namespace
{

std::string ToLowerStr(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string ExtractDomainFromUrl(const std::string &url)
{
    std::string d = ToLowerStr(url);
    size_t scheme = d.find("://");
    if (scheme != std::string::npos)
        d = d.substr(scheme + 3);
    size_t slash = d.find('/');
    if (slash != std::string::npos)
        d = d.substr(0, slash);
    size_t colon = d.find(':');
    if (colon != std::string::npos)
        d = d.substr(0, colon);
    if (d.rfind("www.", 0) == 0)
        d = d.substr(4);
    if (d.rfind("{}", 0) == 0 && d.size() > 3)
        d = d.substr(3);
    while (!d.empty() && d.back() == '.')
        d.pop_back();
    return d;
}

std::string InferCategory(const std::string &name, const std::string &domain)
{
    std::string key = ToLowerStr(name + " " + domain);
    if (key.find("git") != std::string::npos || key.find("code") != std::string::npos ||
        key.find("npm") != std::string::npos || key.find("pypi") != std::string::npos ||
        key.find("docker") != std::string::npos || key.find("dev") != std::string::npos ||
        key.find("hack") != std::string::npos || key.find("kaggle") != std::string::npos ||
        key.find("crate") != std::string::npos || key.find("ruby") != std::string::npos ||
        key.find("nuget") != std::string::npos || key.find("replit") != std::string::npos ||
        key.find("hugging") != std::string::npos || key.find("keybase") != std::string::npos ||
        key.find("linux") != std::string::npos || key.find("python") != std::string::npos ||
        key.find("gradle") != std::string::npos || key.find("arduino") != std::string::npos ||
        key.find("packagist") != std::string::npos || key.find("bugcrowd") != std::string::npos ||
        key.find("intigriti") != std::string::npos || key.find("pentest") != std::string::npos ||
        key.find("virustotal") != std::string::npos || key.find("weblate") != std::string::npos ||
        key.find("wakatime") != std::string::npos || key.find("asciinema") != std::string::npos ||
        key.find("ctan") != std::string::npos || key.find("stackoverflow") != std::string::npos)
    {
        return "Dev & Code";
    }
    if (key.find("steam") != std::string::npos || key.find("roblox") != std::string::npos ||
        key.find("chess") != std::string::npos || key.find("minecraft") != std::string::npos ||
        key.find("game") != std::string::npos || key.find("osu") != std::string::npos ||
        key.find("itch") != std::string::npos || key.find("mod") != std::string::npos ||
        key.find("achievement") != std::string::npos || key.find("tetr") != std::string::npos ||
        key.find("speedrun") != std::string::npos || key.find("xbox") != std::string::npos ||
        key.find("psn") != std::string::npos || key.find("fortnite") != std::string::npos ||
        key.find("valorant") != std::string::npos || key.find("runescape") != std::string::npos ||
        key.find("wowhead") != std::string::npos || key.find("curseforge") != std::string::npos ||
        key.find("pokemon") != std::string::npos || key.find("nintendo") != std::string::npos ||
        key.find("warframe") != std::string::npos || key.find("kongregate") != std::string::npos ||
        key.find("newgrounds") != std::string::npos || key.find("trackmania") != std::string::npos ||
        key.find("typeracer") != std::string::npos || key.find("monkeytype") != std::string::npos ||
        key.find("lichess") != std::string::npos)
    {
        return "Gaming";
    }
    if (key.find("youtube") != std::string::npos || key.find("twitch") != std::string::npos ||
        key.find("kick") != std::string::npos || key.find("spotify") != std::string::npos ||
        key.find("sound") != std::string::npos || key.find("art") != std::string::npos ||
        key.find("behance") != std::string::npos || key.find("dribbble") != std::string::npos ||
        key.find("photo") != std::string::npos || key.find("flickr") != std::string::npos ||
        key.find("unsplash") != std::string::npos || key.find("pexels") != std::string::npos ||
        key.find("vimeo") != std::string::npos || key.find("anime") != std::string::npos ||
        key.find("letterboxd") != std::string::npos || key.find("music") != std::string::npos ||
        key.find("bandcamp") != std::string::npos || key.find("deviant") != std::string::npos ||
        key.find("giphy") != std::string::npos || key.find("tenor") != std::string::npos ||
        key.find("imgur") != std::string::npos || key.find("pixelfed") != std::string::npos ||
        key.find("vsco") != std::string::npos || key.find("last.fm") != std::string::npos ||
        key.find("mixcloud") != std::string::npos || key.find("genius") != std::string::npos ||
        key.find("musescore") != std::string::npos || key.find("dailymotion") != std::string::npos ||
        key.find("rumble") != std::string::npos || key.find("odysee") != std::string::npos ||
        key.find("trovo") != std::string::npos || key.find("moviedb") != std::string::npos ||
        key.find("trakt") != std::string::npos || key.find("wattpad") != std::string::npos)
    {
        return "Media & Art";
    }
    if (key.find("twitter") != std::string::npos || key.find("x.com") != std::string::npos ||
        key.find("instagram") != std::string::npos || key.find("tiktok") != std::string::npos ||
        key.find("reddit") != std::string::npos || key.find("threads") != std::string::npos ||
        key.find("telegram") != std::string::npos || key.find("mastodon") != std::string::npos ||
        key.find("mstdn") != std::string::npos || key.find("bluesky") != std::string::npos ||
        key.find("pinterest") != std::string::npos || key.find("tumblr") != std::string::npos ||
        key.find("medium") != std::string::npos || key.find("linktr") != std::string::npos ||
        key.find("vk.com") != std::string::npos || key.find("discord") != std::string::npos ||
        key.find("snapchat") != std::string::npos || key.find("linkedin") != std::string::npos ||
        key.find("patreon") != std::string::npos || key.find("ko-fi") != std::string::npos ||
        key.find("buymeacoffee") != std::string::npos || key.find("substack") != std::string::npos ||
        key.find("lemmy") != std::string::npos || key.find("fosstodon") != std::string::npos ||
        key.find("chaos.social") != std::string::npos)
    {
        return "Social";
    }
    return "Forums & Other";
}

bool ParseRuleEntry(const std::string &site_name, const json &obj, PlatformRule &out)
{
    if (!obj.is_object() || site_name.empty() || site_name[0] == '$')
        return false;

    std::string url = obj.value("url", "");
    if (url.empty())
        return false;

    out.name = site_name;
    out.url_template = url;
    out.probe_template = obj.value("urlProbe", url);
    out.main_url = obj.value("urlMain", "");
    out.domain = obj.value("domain", "");
    if (out.domain.empty())
    {
        out.domain = ExtractDomainFromUrl(!out.main_url.empty() ? out.main_url : out.url_template);
    }

    out.category = obj.value("category", "");
    if (out.category.empty())
    {
        out.category = InferCategory(out.name, out.domain);
    }

    if (obj.contains("errorType"))
    {
        if (obj["errorType"].is_string())
        {
            out.error_types.push_back(obj["errorType"].get<std::string>());
        }
        else if (obj["errorType"].is_array())
        {
            for (const auto &et : obj["errorType"])
            {
                if (et.is_string())
                    out.error_types.push_back(et.get<std::string>());
            }
        }
    }
    if (out.error_types.empty())
    {
        out.error_types.push_back("status_code");
    }

    out.error_url = obj.value("errorUrl", "");

    if (obj.contains("errorCode"))
    {
        if (obj["errorCode"].is_number_integer())
        {
            out.error_codes.push_back(obj["errorCode"].get<int>());
        }
        else if (obj["errorCode"].is_array())
        {
            for (const auto &ec : obj["errorCode"])
            {
                if (ec.is_number_integer())
                    out.error_codes.push_back(ec.get<int>());
            }
        }
    }

    out.regex_check = obj.value("regexCheck", "");
    out.request_method = obj.value("request_method", "");
    out.is_nsfw = obj.value("isNSFW", false);

    if (obj.contains("request_payload") && !obj["request_payload"].is_null())
    {
        if (obj["request_payload"].is_string())
            out.request_payload_json = obj["request_payload"].get<std::string>();
        else
            out.request_payload_json = obj["request_payload"].dump();
    }

    if (obj.contains("errorMsg"))
    {
        if (obj["errorMsg"].is_string())
        {
            out.error_msgs.push_back(obj["errorMsg"].get<std::string>());
        }
        else if (obj["errorMsg"].is_array())
        {
            for (const auto &m : obj["errorMsg"])
            {
                if (m.is_string())
                    out.error_msgs.push_back(m.get<std::string>());
            }
        }
    }

    if (obj.contains("headers") && obj["headers"].is_object())
    {
        for (auto it = obj["headers"].begin(); it != obj["headers"].end(); ++it)
        {
            if (it.value().is_string())
            {
                out.headers[it.key()] = it.value().get<std::string>();
            }
        }
    }

    return true;
}

void ParseJsonRoot(const json &root, std::vector<PlatformRule> &rules, std::unordered_set<std::string> &seen_names)
{
    if (root.is_object())
    {
        for (auto it = root.begin(); it != root.end(); ++it)
        {
            PlatformRule r;
            if (ParseRuleEntry(it.key(), it.value(), r) && seen_names.insert(r.name).second)
            {
                rules.push_back(std::move(r));
            }
        }
    }
    else if (root.is_array())
    {
        for (const auto &item : root)
        {
            if (!item.is_object())
                continue;
            std::string name = item.value("name", "");
            PlatformRule r;
            if (!name.empty() && ParseRuleEntry(name, item, r) && seen_names.insert(r.name).second)
            {
                rules.push_back(std::move(r));
            }
        }
    }
}

} // namespace

std::vector<PlatformRule> ConfigLoader::LoadPlatforms(const std::string &json_path)
{
    std::vector<PlatformRule> rules;
    std::unordered_set<std::string> seen_names;

    try
    {
        json core_json = json::parse(kEmbeddedPlatformCatalog);
        ParseJsonRoot(core_json, rules, seen_names);
    }
    catch (...)
    {
    }

    const std::string extra_paths[] = {"data/platform_rules.json", "data/data.json", json_path};
    for (const auto &p : extra_paths)
    {
        if (p.empty())
            continue;
        std::ifstream f(p);
        if (f.is_open())
        {
            try
            {
                json j;
                f >> j;
                ParseJsonRoot(j, rules, seen_names);
            }
            catch (...)
            {
            }
        }
    }

    return rules;
}

size_t ConfigLoader::AppendRulesFile(const std::string &rules_json_path, std::vector<PlatformRule> &rules)
{
    std::ifstream f(rules_json_path);
    if (!f.is_open())
        return 0;

    std::unordered_set<std::string> seen_names;
    for (const auto &r : rules)
    {
        seen_names.insert(r.name);
    }

    size_t before = rules.size();
    try
    {
        json j;
        f >> j;
        ParseJsonRoot(j, rules, seen_names);
    }
    catch (...)
    {
        return 0;
    }

    return rules.size() - before;
}

} // namespace core