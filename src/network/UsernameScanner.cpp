#include "UsernameScanner.hpp"
#include "HttpClient.hpp"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <mutex>
#include <regex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace network
{

namespace
{

std::string ReplaceAll(std::string str, const std::string &from, const std::string &to)
{
    if (from.empty())
        return str;
    size_t pos = 0;
    while ((pos = str.find(from, pos)) != std::string::npos)
    {
        str.replace(pos, from.length(), to);
        pos += to.length();
    }
    return str;
}

std::string ApplyHandleTemplate(const std::string &tmpl, const std::string &handle)
{
    std::string out = ReplaceAll(tmpl, "{username}", handle);
    out = ReplaceAll(out, "{account}", handle);
    out = ReplaceAll(out, "{}", handle);
    return out;
}

std::vector<std::string> BuildHandleCandidates(const std::string &username, bool checkVariants)
{
    std::vector<std::string> candidates;
    std::unordered_set<std::string> seen;

    auto add = [&](const std::string &h) {
        if (!h.empty() && seen.insert(h).second)
            candidates.push_back(h);
    };

    add(username);
    if (!checkVariants)
        return candidates;

    add(username + "_");
    add("_" + username);
    add(username + ".");
    add(username + "1");

    if (username.find('_') != std::string::npos)
    {
        add(ReplaceAll(username, "_", "."));
        add(ReplaceAll(username, "_", "-"));
        add(ReplaceAll(username, "_", ""));
    }
    if (username.find('.') != std::string::npos)
    {
        add(ReplaceAll(username, ".", "_"));
        add(ReplaceAll(username, ".", ""));
    }

    return candidates;
}

bool MatchesRegexSafe(const std::string &pattern, const std::string &value)
{
    if (pattern.empty())
        return true;
    try
    {
        std::regex re(pattern, std::regex::ECMAScript);
        return std::regex_match(value, re);
    }
    catch (...)
    {
        return true;
    }
}

bool HasErrorType(const std::vector<std::string> &types, const std::string &target)
{
    return std::find(types.begin(), types.end(), target) != types.end();
}

std::string ExtractMetaContent(const std::string &html, const std::string &propertyName)
{
    if (html.empty())
        return {};

    size_t pos = html.find(propertyName);
    if (pos == std::string::npos)
        return {};

    size_t tagStart = html.rfind('<', pos);
    size_t tagEnd = html.find('>', pos);
    if (tagStart == std::string::npos || tagEnd == std::string::npos || tagEnd <= tagStart)
        return {};

    std::string tag = html.substr(tagStart, tagEnd - tagStart + 1);
    size_t cPos = tag.find("content=");
    if (cPos == std::string::npos)
        return {};

    cPos += 8;
    if (cPos >= tag.size())
        return {};

    char quote = tag[cPos];
    if (quote != '"' && quote != '\'')
        return {};

    size_t valStart = cPos + 1;
    size_t valEnd = tag.find(quote, valStart);
    if (valEnd == std::string::npos || valEnd <= valStart)
        return {};

    std::string val = tag.substr(valStart, valEnd - valStart);
    if (val.size() > 240)
        val.resize(240);
    return val;
}

bool EvaluateResponse(const core::PlatformRule &rule, const HttpResponse &resp)
{
    if (resp.status <= 0 || resp.status >= 500)
        return false;

    for (int code : rule.error_codes)
    {
        if (resp.status == code)
            return false;
    }

    bool checkStatus = rule.error_types.empty() || HasErrorType(rule.error_types, "status_code");
    bool checkMsg = HasErrorType(rule.error_types, "message") || !rule.error_msgs.empty();
    bool checkUrl = HasErrorType(rule.error_types, "response_url") && !rule.error_url.empty();

    if (checkStatus)
    {
        if (resp.status < 200 || resp.status >= 300)
            return false;
    }

    if (checkUrl)
    {
        if (resp.final_url == rule.error_url || resp.final_url.find(rule.error_url) != std::string::npos)
            return false;
    }

    if (checkMsg)
    {
        for (const auto &errMsg : rule.error_msgs)
        {
            if (!errMsg.empty() && resp.body.find(errMsg) != std::string::npos)
                return false;
        }
    }

    return true;
}

} // namespace

std::vector<core::UsernameFinding> UsernameScanner::Scan(const std::string &username,
                                                         const std::vector<core::PlatformRule> &rules,
                                                         std::atomic<int> &progress_current,
                                                         std::atomic<bool> &cancel_flag, bool check_variants,
                                                         bool include_nsfw)
{
    std::vector<core::PlatformRule> activeRules;
    activeRules.reserve(rules.size());
    for (const auto &r : rules)
    {
        if (!r.is_nsfw || include_nsfw)
            activeRules.push_back(r);
    }

    std::vector<core::UsernameFinding> findings;
    if (activeRules.empty() || username.empty())
        return findings;

    std::vector<std::string> candidates = BuildHandleCandidates(username, check_variants);
    std::atomic<size_t> nextIndex{0};
    std::mutex resultsMutex;

    unsigned int hwThreads = std::thread::hardware_concurrency();
    size_t workerCount = std::min<size_t>(activeRules.size(), std::max<unsigned int>(8u, hwThreads * 2u));
    if (workerCount > 24)
        workerCount = 24;

    std::vector<std::thread> workers;
    workers.reserve(workerCount);

    for (size_t w = 0; w < workerCount; ++w)
    {
        workers.emplace_back([&]() {
            while (!cancel_flag.load())
            {
                size_t idx = nextIndex.fetch_add(1);
                if (idx >= activeRules.size())
                    break;

                const auto &rule = activeRules[idx];
                core::UsernameFinding finding;
                finding.platform = rule.name;
                finding.category = rule.category;
                finding.domain = rule.domain;

                for (const auto &handle : candidates)
                {
                    if (cancel_flag.load())
                        break;
                    if (!MatchesRegexSafe(rule.regex_check, handle))
                        continue;

                    std::string profileUrl = ApplyHandleTemplate(rule.url_template, handle);
                    std::string probeUrl =
                        rule.probe_template.empty() ? profileUrl : ApplyHandleTemplate(rule.probe_template, handle);

                    std::map<std::string, std::string> reqHeaders;
                    for (const auto &[k, v] : rule.headers)
                    {
                        reqHeaders[k] = ApplyHandleTemplate(v, handle);
                    }

                    std::string method = rule.request_method.empty() ? "GET" : rule.request_method;
                    std::string payload = ApplyHandleTemplate(rule.request_payload_json, handle);

                    HttpResponse resp = HttpClient::Request(method, probeUrl, reqHeaders, payload, true, 8000);
                    finding.status_code = resp.status;
                    finding.http_status = resp.status;
                    finding.url = profileUrl;

                    if (EvaluateResponse(rule, resp))
                    {
                        finding.found = true;
                        finding.matched_handle = handle;
                        finding.display_name = ExtractMetaContent(resp.body, "og:title");
                        finding.avatar_url = ExtractMetaContent(resp.body, "og:image");
                        finding.bio = ExtractMetaContent(resp.body, "og:description");
                        break;
                    }
                }

                {
                    std::lock_guard<std::mutex> lock(resultsMutex);
                    findings.push_back(std::move(finding));
                }
                progress_current.fetch_add(1);
            }
        });
    }

    for (auto &t : workers)
    {
        if (t.joinable())
            t.join();
    }

    std::sort(findings.begin(), findings.end(),
              [](const core::UsernameFinding &a, const core::UsernameFinding &b) { return a.platform < b.platform; });

    return findings;
}

} // namespace network