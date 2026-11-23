#include "HttpClient.hpp"
#include <algorithm>
#include <cctype>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

namespace network
{

namespace
{

std::wstring ToWide(const std::string &s)
{
    if (s.empty())
        return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &w[0], len);
    return w;
}

std::string ToUtf8(const std::wstring &w)
{
    if (w.empty())
        return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &s[0], len, nullptr, nullptr);
    return s;
}

std::string LowerKey(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // namespace

HttpResponse HttpClient::Request(const std::string &method, const std::string &url,
                                 const std::map<std::string, std::string> &headers, const std::string &payload,
                                 bool allow_redirects, int timeout_ms)
{
    HttpResponse resp;
    std::wstring wurl = ToWide(url);
    if (wurl.empty())
        return resp;

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t hostName[256]{};
    wchar_t urlPath[4096]{};
    uc.lpszHostName = hostName;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = urlPath;
    uc.dwUrlPathLength = 4096;

    if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &uc))
    {
        return resp;
    }

    std::wstring userAgent = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0";
    for (const auto &kv : headers)
    {
        if (LowerKey(kv.first) == "user-agent" && !kv.second.empty())
        {
            userAgent = ToWide(kv.second);
            break;
        }
    }

    HINTERNET hSession = WinHttpOpen(userAgent.c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
        return resp;

    WinHttpSetTimeouts(hSession, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));

    HINTERNET hConnect = WinHttpConnect(hSession, hostName, uc.nPort, 0);
    if (!hConnect)
    {
        WinHttpCloseHandle(hSession);
        return resp;
    }

    std::wstring wMethod = method.empty() ? L"GET" : ToWide(method);
    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, wMethod.c_str(), urlPath, nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    DWORD redirectPolicy =
        allow_redirects ? WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS : WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

    DWORD decompression = WINHTTP_DECOMPRESSION_FLAG_ALL;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_DECOMPRESSION, &decompression, sizeof(decompression));

    bool has_accept = false;
    bool has_accept_lang = false;
    bool has_content_type = false;
    bool has_cookie = false;
    std::wstring customHeaders;

    for (const auto &kv : headers)
    {
        std::string lk = LowerKey(kv.first);
        if (lk == "user-agent" || lk == "host")
            continue;
        if (lk == "accept")
            has_accept = true;
        if (lk == "accept-language")
            has_accept_lang = true;
        if (lk == "content-type")
            has_content_type = true;
        if (lk == "cookie")
            has_cookie = true;
        customHeaders += ToWide(kv.first + ": " + kv.second + "\r\n");
    }

    std::wstring extraHeaders;
    if (!has_accept)
        extraHeaders +=
            L"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7\r\n";
    if (!has_accept_lang)
        extraHeaders += L"Accept-Language: en-US,en;q=0.9\r\n";
    if (!has_cookie)
        extraHeaders += L"Cookie: SOCS=CAI\r\n";
    if (!payload.empty() && !has_content_type)
        extraHeaders += L"Content-Type: application/json\r\n";
    extraHeaders += customHeaders;

    LPVOID bodyPtr = payload.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char *>(payload.data());
    DWORD bodyLen = static_cast<DWORD>(payload.size());

    if (WinHttpSendRequest(hRequest, extraHeaders.c_str(), static_cast<DWORD>(-1L), bodyPtr, bodyLen, bodyLen, 0) &&
        WinHttpReceiveResponse(hRequest, nullptr))
    {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX))
        {
            resp.status = static_cast<int>(statusCode);
        }

        wchar_t finalBuf[4096]{};
        DWORD finalSize = sizeof(finalBuf);
        if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_URL, finalBuf, &finalSize))
        {
            resp.final_url = ToUtf8(finalBuf);
        }
        else
        {
            resp.final_url = url;
        }

        if (wMethod != L"HEAD")
        {
            DWORD bytesAvailable = 0;
            while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0)
            {
                std::vector<char> buffer(bytesAvailable);
                DWORD bytesRead = 0;
                if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead) && bytesRead > 0)
                {
                    resp.body.append(buffer.data(), bytesRead);
                }
                if (resp.body.size() > 4194304)
                    break;
            }
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

HttpResponse HttpClient::Get(const std::string &url, int timeout_ms)
{
    return Request("GET", url, {}, "", true, timeout_ms);
}

std::vector<unsigned char> HttpClient::GetBytes(const std::string &url, int timeout_ms)
{
    HttpResponse resp = Get(url, timeout_ms);
    if (resp.status == 200 && !resp.body.empty())
    {
        return std::vector<unsigned char>(resp.body.begin(), resp.body.end());
    }
    return {};
}

} // namespace network