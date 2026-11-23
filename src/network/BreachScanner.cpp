#include "BreachScanner.hpp"
#include "HttpClient.hpp"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <set>
#include <sstream>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <wincrypt.h>

using json = nlohmann::json;

namespace network
{

namespace
{

std::string UrlEncode(const std::string &value)
{
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (unsigned char c : value)
    {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            escaped << c;
        }
        else
        {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << static_cast<int>(c);
            escaped << std::nouppercase;
        }
    }
    return escaped.str();
}

std::string Sha1HexUpper(const std::string &input)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;
    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
        {
            CryptHashData(hHash, reinterpret_cast<const BYTE *>(input.data()), (DWORD)input.size(), 0);
            BYTE hash[20];
            DWORD hashLen = 20;
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
            {
                std::ostringstream oss;
                for (DWORD i = 0; i < hashLen; i++)
                {
                    oss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                }
                result = oss.str();
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return result;
}

std::string Md5HexLower(const std::string &input)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;
    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
        {
            CryptHashData(hHash, reinterpret_cast<const BYTE *>(input.data()), (DWORD)input.size(), 0);
            BYTE hash[16];
            DWORD hashLen = 16;
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
            {
                std::ostringstream oss;
                for (DWORD i = 0; i < hashLen; i++)
                {
                    oss << std::nouppercase << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                }
                result = oss.str();
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return result;
}

std::string ToLowerKey(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string JoinList(const std::vector<std::string> &items, size_t max_items = 6)
{
    std::string out;
    size_t count = std::min(items.size(), max_items);
    for (size_t i = 0; i < count; ++i)
    {
        if (i > 0)
            out += ", ";
        out += items[i];
    }
    if (items.size() > max_items)
    {
        out += " (+" + std::to_string(items.size() - max_items) + " more)";
    }
    return out;
}

} // namespace

core::EmailAuditResult BreachScanner::AuditEmail(const std::string &email)
{
    core::EmailAuditResult res;
    res.email = email;
    std::set<std::string> seen_sources;
    const std::string encoded_email = UrlEncode(email);
    const std::string lower_email = ToLowerKey(email);

    auto add_finding = [&](const std::string &title, const std::string &date, const std::string &provider,
                           const std::string &passwords = "") {
        if (title.empty())
            return;
        std::string key = ToLowerKey(title);
        if (seen_sources.insert(key).second)
        {
            res.breaches.push_back({title, date.empty() ? "Unknown" : date, provider, passwords});
        }
    };

    // 1. XposedOrNot Breach Analytics (fechas reales + nivel de riesgo de contraseña)
    HttpResponse xon_analytics =
        HttpClient::Get("https://api.xposedornot.com/v1/breach-analytics?email=" + encoded_email, 12000);
    if (xon_analytics.status == 200 && !xon_analytics.body.empty())
    {
        try
        {
            auto j = json::parse(xon_analytics.body);
            if (j.contains("ExposedBreaches") && j["ExposedBreaches"].is_object() &&
                j["ExposedBreaches"].contains("breaches_details") &&
                j["ExposedBreaches"]["breaches_details"].is_array())
            {
                for (const auto &item : j["ExposedBreaches"]["breaches_details"])
                {
                    std::string breach_name = item.value("breach", "");
                    std::string xposed_date = item.value("xposed_date", "Indexed");
                    std::string xposed_data = item.value("xposed_data", "");
                    std::string pwd_risk = item.value("password_risk", "");

                    std::string label = breach_name;
                    if (!xposed_data.empty())
                    {
                        label += " [" + xposed_data + "]";
                    }

                    std::string pwd_info = "No password exposed";
                    if (ToLowerKey(xposed_data).find("password") != std::string::npos)
                    {
                        pwd_info = pwd_risk.empty() ? "[Password Leaked - Hash/Encrypted]"
                                                    : "[Risk: " + pwd_risk + " - API hides plaintext]";
                    }

                    if (!breach_name.empty())
                    {
                        seen_sources.insert(ToLowerKey(breach_name));
                        res.breaches.push_back({label, xposed_date, "XposedOrNot Analytics", pwd_info});
                    }
                }
            }
        }
        catch (...)
        {
        }
    }

    // 2. XposedOrNot Check-Email (respaldo)
    HttpResponse xon = HttpClient::Get("https://api.xposedornot.com/v1/check-email/" + encoded_email, 11000);
    if (xon.status == 200 && !xon.body.empty())
    {
        try
        {
            auto j = json::parse(xon.body);
            if (j.contains("breaches") && j["breaches"].is_array() && !j["breaches"].empty())
            {
                const auto &list = j["breaches"][0].is_array() ? j["breaches"][0] : j["breaches"];
                for (const auto &b : list)
                {
                    if (b.is_string())
                    {
                        add_finding(b.get<std::string>(), "Indexed", "XposedOrNot", "[Indexed Breach]");
                    }
                }
            }
        }
        catch (...)
        {
        }
    }

    // 3. LeakCheck Public API (campos filtrados)
    HttpResponse lc = HttpClient::Get("https://leakcheck.io/api/public?check=" + encoded_email, 11000);
    if (lc.status == 200 && !lc.body.empty())
    {
        try
        {
            auto j = json::parse(lc.body);
            std::string fields_hint = "[Public tier - fields masked]";
            if (j.contains("fields") && j["fields"].is_array())
            {
                std::vector<std::string> flds;
                for (const auto &f : j["fields"])
                {
                    if (f.is_string())
                        flds.push_back(f.get<std::string>());
                }
                if (!flds.empty())
                {
                    fields_hint = "[Exposed fields: " + JoinList(flds, 5) + "]";
                }
            }

            if (j.value("success", false) && j.contains("sources") && j["sources"].is_array())
            {
                for (const auto &src : j["sources"])
                {
                    std::string name = src.value("name", "");
                    std::string date = src.value("date", "Unknown");
                    add_finding(name, date.empty() ? "Unknown" : date, "LeakCheck Public", fields_hint);
                }
            }
        }
        catch (...)
        {
        }
    }

    // 4. Hudson Rock Cavalier OSINT (stealer_family + top_passwords)
    HttpResponse hr = HttpClient::Get(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=" + encoded_email, 11000);
    if (hr.status == 200 && !hr.body.empty())
    {
        try
        {
            auto j = json::parse(hr.body);
            if (j.contains("stealers") && j["stealers"].is_array())
            {
                for (const auto &st : j["stealers"])
                {
                    std::string family = st.value("stealer_family", "Infostealer Malware");
                    std::string os = st.value("operating_system", "");
                    std::string date = st.value("date_compromised", "Unknown");
                    if (date.size() > 10)
                        date = date.substr(0, 10);

                    std::vector<std::string> stolen_pwds;
                    if (st.contains("top_passwords") && st["top_passwords"].is_array())
                    {
                        for (const auto &p : st["top_passwords"])
                        {
                            if (p.is_string() && !p.get<std::string>().empty())
                            {
                                stolen_pwds.push_back(p.get<std::string>());
                            }
                        }
                    }

                    std::string title = "Infostealer Log (" + family + ")";
                    if (!os.empty() && os != "Not Found")
                    {
                        title += " - " + os;
                    }
                    std::string pwd_str =
                        stolen_pwds.empty() ? "[Stealer log indexed - passwords redacted]" : JoinList(stolen_pwds, 6);
                    add_finding(title, date, "Hudson Rock Cavalier", pwd_str);
                }
            }
        }
        catch (...)
        {
        }
    }

    // 5. ProxyNova COMB (extrae pares email:contraseña reales del corpus COMB)
    HttpResponse comb = HttpClient::Get("https://api.proxynova.com/comb?query=" + encoded_email, 10000);
    if (comb.status == 200 && !comb.body.empty())
    {
        try
        {
            auto j = json::parse(comb.body);
            int count = j.value("count", 0);
            std::vector<std::string> comb_passwords;
            std::set<std::string> seen_pwds;

            if (j.contains("lines") && j["lines"].is_array())
            {
                for (const auto &line_val : j["lines"])
                {
                    if (!line_val.is_string())
                        continue;
                    std::string line = line_val.get<std::string>();
                    size_t colon = line.find(':');
                    if (colon != std::string::npos)
                    {
                        std::string line_email = ToLowerKey(line.substr(0, colon));
                        std::string line_pwd = line.substr(colon + 1);
                        while (!line_pwd.empty() && (line_pwd.back() == '\r' || line_pwd.back() == '\n'))
                            line_pwd.pop_back();

                        if (line_email == lower_email && !line_pwd.empty() && seen_pwds.insert(line_pwd).second)
                        {
                            comb_passwords.push_back(line_pwd);
                        }
                    }
                }
            }

            if (count > 0 || !comb_passwords.empty())
            {
                std::string pwd_summary =
                    comb_passwords.empty() ? "[Matched in COMB archive]" : JoinList(comb_passwords, 8);
                int display_count = !comb_passwords.empty() ? (int)comb_passwords.size() : count;
                add_finding("COMB Credential Compilation (" + std::to_string(display_count) + " records)",
                            "2021-Archive", "ProxyNova COMB", pwd_summary);
            }
        }
        catch (...)
        {
        }
    }

    // 6. GitHub OSINT
    HttpResponse gh = HttpClient::Get("https://api.github.com/search/users?q=" + encoded_email + "+in:email", 9000);
    if (gh.status == 200 && !gh.body.empty())
    {
        try
        {
            auto j = json::parse(gh.body);
            if (j.value("total_count", 0) > 0 && j.contains("items") && !j["items"].empty())
            {
                res.github_user = j["items"][0].value("login", "");
                res.github_url = j["items"][0].value("html_url", "");
            }
        }
        catch (...)
        {
        }
    }

    // 7. Gravatar OSINT
    std::string md5 = Md5HexLower(lower_email);
    HttpResponse grav = HttpClient::Get("https://en.gravatar.com/" + md5 + ".json", 9000);
    if (grav.status == 200 && !grav.body.empty())
    {
        try
        {
            auto j = json::parse(grav.body);
            if (j.contains("entry") && j["entry"].is_array() && !j["entry"].empty())
            {
                res.gravatar_name = j["entry"][0].value("displayName", "");
                res.gravatar_url = j["entry"][0].value("profileUrl", "");
            }
        }
        catch (...)
        {
        }
    }

    // 8-12. Cuentas y claves públicas vinculadas
    HttpResponse pgp = HttpClient::Get("https://keys.openpgp.org/vks/v1/by-email/" + encoded_email, 8000);
    if (pgp.status == 200 && pgp.body.find("BEGIN PGP PUBLIC KEY BLOCK") != std::string::npos)
    {
        add_finding("OpenPGP Public Key Registered", "Active Key", "OpenPGP Keyserver");
    }

    HttpResponse ub_pgp =
        HttpClient::Get("https://keyserver.ubuntu.com/pks/lookup?op=index&options=mr&search=" + encoded_email, 8000);
    if (ub_pgp.status == 200 && ub_pgp.body.find("pub:") != std::string::npos)
    {
        add_finding("Ubuntu PGP Keyserver Record", "Indexed Key", "Ubuntu Keyserver");
    }

    HttpResponse proton =
        HttpClient::Get("https://api.protonmail.ch/pks/lookup?op=index&search=" + encoded_email, 8000);
    if (proton.status == 200 && proton.body.find("pub:") != std::string::npos)
    {
        add_finding("Proton / PGP Encryption Key", "Verified Key", "Proton PKS OSINT");
    }

    HttpResponse gl = HttpClient::Get("https://gitlab.com/api/v4/users?search=" + encoded_email, 8000);
    if (gl.status == 200 && !gl.body.empty())
    {
        try
        {
            auto j = json::parse(gl.body);
            if (j.is_array() && !j.empty())
            {
                std::string gl_user = j[0].value("username", "");
                if (!gl_user.empty())
                {
                    add_finding("GitLab Account (@" + gl_user + ")", "Public Profile", "GitLab OSINT");
                }
            }
        }
        catch (...)
        {
        }
    }

    HttpResponse kb = HttpClient::Get("https://keybase.io/_/api/1.0/user/lookup.json?email=" + encoded_email, 8000);
    if (kb.status == 200 && !kb.body.empty())
    {
        try
        {
            auto j = json::parse(kb.body);
            if (j.contains("them") && j["them"].is_array() && !j["them"].empty() && !j["them"][0].is_null())
            {
                std::string kb_user = j["them"][0].value("basics", json::object()).value("username", "");
                if (!kb_user.empty())
                {
                    add_finding("Keybase Identity (@" + kb_user + ")", "Verified Account", "Keybase OSINT");
                }
            }
        }
        catch (...)
        {
        }
    }

    HttpResponse duo = HttpClient::Get("https://www.duolingo.com/2017-06-30/users?email=" + encoded_email, 8000);
    if (duo.status == 200 && !duo.body.empty())
    {
        try
        {
            auto j = json::parse(duo.body);
            if (j.contains("users") && j["users"].is_array() && !j["users"].empty())
            {
                std::string duo_user = j["users"][0].value("username", "");
                if (!duo_user.empty())
                {
                    add_finding("Duolingo Account (@" + duo_user + ")", "Registered", "Duolingo OSINT");
                }
            }
        }
        catch (...)
        {
        }
    }

    res.completed = true;
    return res;
}

int BreachScanner::CheckPasswordPwnedCount(const std::string &password)
{
    if (password.empty())
        return 0;
    std::string sha1 = Sha1HexUpper(password);
    if (sha1.size() < 40)
        return -1;

    std::string prefix = sha1.substr(0, 5);
    std::string suffix = sha1.substr(5);

    HttpResponse resp = HttpClient::Get("https://api.pwnedpasswords.com/range/" + prefix, 9000);
    if (resp.status != 200)
        return -1;

    std::istringstream iss(resp.body);
    std::string line;
    while (std::getline(iss, line))
    {
        if (line.rfind(suffix, 0) == 0)
        {
            auto colon = line.find(':');
            if (colon != std::string::npos)
            {
                return std::stoi(line.substr(colon + 1));
            }
        }
    }
    return 0;
}

} // namespace network