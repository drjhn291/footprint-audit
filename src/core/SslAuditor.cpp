#include "SslAuditor.hpp"

#include <windows.h>

#include <wincrypt.h>
#include <winhttp.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

namespace core
{

namespace
{

std::string CleanHost(std::string input)
{
    auto trim = [](std::string &s) {
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
            s.erase(s.begin());
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
            s.pop_back();
    };
    trim(input);

    if (input.rfind("https://", 0) == 0)
        input.erase(0, 8);
    else if (input.rfind("http://", 0) == 0)
        input.erase(0, 7);

    size_t slash = input.find('/');
    if (slash != std::string::npos)
        input.erase(slash);

    size_t colon = input.find(':');
    if (colon != std::string::npos)
        input.erase(colon);

    return input;
}

std::wstring ToWide(const std::string &s)
{
    if (s.empty())
        return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(len > 0 ? len - 1 : 0, L'\0');
    if (len > 1)
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), len);
    return w;
}

std::string FormatFileTime(const FILETIME &ft)
{
    SYSTEMTIME st{};
    FileTimeToSystemTime(&ft, &st);
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d UTC", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return buf;
}

int CalcDaysUntil(const FILETIME &ftExpiry)
{
    FILETIME ftNow{};
    GetSystemTimeAsFileTime(&ftNow);

    ULARGE_INTEGER uNow{}, uExp{};
    uNow.LowPart = ftNow.dwLowDateTime;
    uNow.HighPart = ftNow.dwHighDateTime;
    uExp.LowPart = ftExpiry.dwLowDateTime;
    uExp.HighPart = ftExpiry.dwHighDateTime;

    long long diff = static_cast<long long>(uExp.QuadPart) - static_cast<long long>(uNow.QuadPart);
    return static_cast<int>(diff / 864000000000LL);
}

std::string MapSignatureOid(const char *oid)
{
    if (!oid)
        return "Unknown";
    std::string o(oid);
    if (o == "1.2.840.113549.1.1.11")
        return "SHA256-RSA";
    if (o == "1.2.840.113549.1.1.12")
        return "SHA384-RSA";
    if (o == "1.2.840.113549.1.1.13")
        return "SHA512-RSA";
    if (o == "1.2.840.10045.4.3.2")
        return "ECDSA-SHA256";
    if (o == "1.2.840.10045.4.3.3")
        return "ECDSA-SHA384";
    if (o == "1.2.840.113549.1.1.5")
        return "SHA1-RSA (Weak)";
    return o;
}

std::string QuerySingleHeader(HINTERNET hRequest, const wchar_t *headerName)
{
    DWORD size = 0;
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, headerName, nullptr, &size, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return {};

    std::wstring buf(size / sizeof(wchar_t), L'\0');
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, headerName, buf.data(), &size, WINHTTP_NO_HEADER_INDEX))
        return {};

    while (!buf.empty() && buf.back() == L'\0')
        buf.pop_back();

    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, buf.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(utf8Len > 0 ? utf8Len - 1 : 0, '\0');
    if (utf8Len > 1)
        WideCharToMultiByte(CP_UTF8, 0, buf.c_str(), -1, out.data(), utf8Len, nullptr, nullptr);
    return out;
}

} // namespace

SslAuditResult SslAuditor::Audit(const std::string &rawTarget)
{
    SslAuditResult res;
    res.host = CleanHost(rawTarget);
    if (res.host.empty())
    {
        res.errorMessage = "Please enter a valid domain name.";
        return res;
    }

    HINTERNET hSession =
        WinHttpOpen(L"FootprintAudit-TLSInspector/2.4", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
    if (!hSession)
    {
        res.errorMessage = "Failed to initialize WinHTTP session.";
        return res;
    }

    DWORD timeout = 9000;
    WinHttpSetTimeouts(hSession, timeout, timeout, timeout, timeout);

    std::wstring wHost = ToWide(res.host);
    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect)
    {
        WinHttpCloseHandle(hSession);
        res.errorMessage = "Unable to resolve or connect to host on port 443.";
        return res;
    }

    auto tryRequest = [&](bool allowInvalidCert) -> HINTERNET {
        HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", L"/", nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hReq)
            return nullptr;

        if (allowInvalidCert)
        {
            DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                             SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
        }

        if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0) ||
            !WinHttpReceiveResponse(hReq, nullptr))
        {
            WinHttpCloseHandle(hReq);
            return nullptr;
        }
        return hReq;
    };

    HINTERNET hRequest = tryRequest(false);
    if (hRequest)
    {
        res.certValid = true;
    }
    else
    {
        hRequest = tryRequest(true);
        res.certValid = false;
    }

    if (!hRequest)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        res.errorMessage = "HTTPS handshake failed (port 443 unreachable or TLS rejected).";
        return res;
    }

    res.success = true;

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX))
    {
        res.httpStatus = static_cast<int>(statusCode);
    }

    PCCERT_CONTEXT pCert = nullptr;
    DWORD certSize = sizeof(pCert);
    if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &pCert, &certSize) && pCert)
    {
        char subjBuf[256]{};
        char issBuf[256]{};
        CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subjBuf, sizeof(subjBuf));
        CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, issBuf,
                           sizeof(issBuf));

        res.subject = subjBuf;
        res.issuer = issBuf;
        res.validFrom = FormatFileTime(pCert->pCertInfo->NotBefore);
        res.validTo = FormatFileTime(pCert->pCertInfo->NotAfter);
        res.daysRemaining = CalcDaysUntil(pCert->pCertInfo->NotAfter);
        res.signatureAlgo = MapSignatureOid(pCert->pCertInfo->SignatureAlgorithm.pszObjId);

        std::ostringstream serialHex;
        const auto &sn = pCert->pCertInfo->SerialNumber;
        for (DWORD i = sn.cbData; i > 0; --i)
        {
            char hex[4]{};
            std::snprintf(hex, sizeof(hex), "%02X", sn.pbData[i - 1]);
            serialHex << hex;
        }
        res.serialNumber = serialHex.str();

        CertFreeCertificateContext(pCert);
    }

    res.serverBanner = QuerySingleHeader(hRequest, L"Server");
    if (res.serverBanner.empty())
        res.serverBanner = "Hidden / Not Disclosed";

    struct HeaderSpec
    {
        const char *name;
        const wchar_t *wname;
        const char *rec;
        int weight;
    };

    const HeaderSpec specs[] = {
        {"Strict-Transport-Security", L"Strict-Transport-Security", "Enforces HTTPS connections (HSTS)", 20},
        {"Content-Security-Policy", L"Content-Security-Policy", "Mitigates XSS & script injection", 20},
        {"X-Frame-Options", L"X-Frame-Options", "Protects against Clickjacking", 10},
        {"X-Content-Type-Options", L"X-Content-Type-Options", "Prevents MIME-sniffing attacks", 10},
        {"Referrer-Policy", L"Referrer-Policy", "Controls referrer leakage across origins", 5},
        {"Permissions-Policy", L"Permissions-Policy", "Restricts browser camera/mic/GPS APIs", 5},
    };

    int score = res.certValid && res.daysRemaining > 0 ? 30 : 0;
    for (const auto &sp : specs)
    {
        SecurityHeaderCheck chk;
        chk.name = sp.name;
        chk.value = QuerySingleHeader(hRequest, sp.wname);
        chk.present = !chk.value.empty();
        chk.recommendation = sp.rec;
        if (chk.present)
            score += sp.weight;
        res.headers.push_back(std::move(chk));
    }

    res.securityScore = std::clamp(score, 0, 100);
    if (res.securityScore >= 90)
        res.grade = "A+";
    else if (res.securityScore >= 80)
        res.grade = "A";
    else if (res.securityScore >= 65)
        res.grade = "B";
    else if (res.securityScore >= 50)
        res.grade = "C";
    else if (res.securityScore >= 35)
        res.grade = "D";
    else
        res.grade = "F";

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return res;
}

} // namespace core