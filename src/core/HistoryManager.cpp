#include "HistoryManager.hpp"
#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>

namespace core
{

namespace
{

std::mutex g_historyMutex;
const char *kHistoryPath = "data/history.json";

std::string CurrentTimestamp()
{
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tmLocal{};
    localtime_s(&tmLocal, &tt);
    std::ostringstream oss;
    oss << std::put_time(&tmLocal, "%Y-%m-%d %H:%M");
    return oss.str();
}

std::string EscapeJson(const std::string &s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '\"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c >= 0x20)
                out.push_back(static_cast<char>(c));
            break;
        }
    }
    return out;
}

std::string ExtractJsonField(const std::string &obj, const std::string &key)
{
    std::string pattern = "\"" + key + "\"";
    size_t kPos = obj.find(pattern);
    if (kPos == std::string::npos)
        return {};
    size_t colon = obj.find(':', kPos + pattern.size());
    if (colon == std::string::npos)
        return {};
    size_t q1 = obj.find('\"', colon + 1);
    if (q1 == std::string::npos)
        return {};

    std::string val;
    bool escape = false;
    for (size_t i = q1 + 1; i < obj.size(); ++i)
    {
        char c = obj[i];
        if (escape)
        {
            if (c == 'n')
                val.push_back('\n');
            else if (c == 'r')
                val.push_back('\r');
            else if (c == 't')
                val.push_back('\t');
            else
                val.push_back(c);
            escape = false;
        }
        else if (c == '\\')
        {
            escape = true;
        }
        else if (c == '\"')
        {
            break;
        }
        else
        {
            val.push_back(c);
        }
    }
    return val;
}

std::vector<HistoryEntry> LoadAllUnlocked()
{
    std::vector<HistoryEntry> items;
    std::ifstream in(kHistoryPath, std::ios::binary);
    if (!in.is_open())
        return items;

    std::ostringstream ss;
    ss << in.rdbuf();
    std::string content = ss.str();

    size_t pos = 0;
    while (pos < content.size())
    {
        size_t b1 = content.find('{', pos);
        if (b1 == std::string::npos)
            break;
        size_t b2 = content.find('}', b1);
        if (b2 == std::string::npos)
            break;

        std::string chunk = content.substr(b1, b2 - b1 + 1);
        HistoryEntry e;
        e.module = ExtractJsonField(chunk, "module");
        e.target = ExtractJsonField(chunk, "target");
        e.summary = ExtractJsonField(chunk, "summary");
        e.timestamp = ExtractJsonField(chunk, "timestamp");
        if (!e.module.empty() && !e.target.empty())
        {
            items.push_back(std::move(e));
        }
        pos = b2 + 1;
    }
    return items;
}

void SaveAllUnlocked(const std::vector<HistoryEntry> &items)
{
    std::filesystem::create_directories("data");
    std::ofstream out(kHistoryPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open())
        return;

    out << "[\n";
    for (size_t i = 0; i < items.size(); ++i)
    {
        const auto &it = items[i];
        out << "  {\"module\": \"" << EscapeJson(it.module) << "\", "
            << "\"target\": \"" << EscapeJson(it.target) << "\", "
            << "\"summary\": \"" << EscapeJson(it.summary) << "\", "
            << "\"timestamp\": \"" << EscapeJson(it.timestamp) << "\"}";
        if (i + 1 < items.size())
            out << ",";
        out << "\n";
    }
    out << "]\n";
}

} // namespace

void HistoryManager::Add(const std::string &module, const std::string &target, const std::string &summary)
{
    if (module.empty() || target.empty())
        return;

    std::lock_guard<std::mutex> lock(g_historyMutex);
    auto items = LoadAllUnlocked();

    items.erase(std::remove_if(items.begin(), items.end(),
                               [&](const HistoryEntry &e) { return e.module == module && e.target == target; }),
                items.end());

    items.insert(items.begin(), HistoryEntry{module, target, summary, CurrentTimestamp()});

    if (items.size() > 120)
    {
        items.resize(120);
    }
    SaveAllUnlocked(items);
}

std::vector<HistoryEntry> HistoryManager::GetByModule(const std::string &module, size_t maxItems)
{
    std::lock_guard<std::mutex> lock(g_historyMutex);
    auto all = LoadAllUnlocked();
    std::vector<HistoryEntry> filtered;
    for (auto &e : all)
    {
        if (e.module == module)
        {
            filtered.push_back(std::move(e));
            if (filtered.size() >= maxItems)
                break;
        }
    }
    return filtered;
}

void HistoryManager::ClearModule(const std::string &module)
{
    std::lock_guard<std::mutex> lock(g_historyMutex);
    auto items = LoadAllUnlocked();
    items.erase(std::remove_if(items.begin(), items.end(), [&](const HistoryEntry &e) { return e.module == module; }),
                items.end());
    SaveAllUnlocked(items);
}

} // namespace core