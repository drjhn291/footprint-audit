#include "FileHashAnalyzer.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace core
{

namespace
{

std::filesystem::path PathFromUtf8(const std::string &utf8)
{
    if (utf8.empty())
        return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), nullptr, 0);
    if (len <= 0)
        return std::filesystem::path(utf8);
    std::wstring wide(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), wide.data(), len);
    return std::filesystem::path(std::move(wide));
}

std::string PathToUtf8(const std::filesystem::path &p)
{
    std::wstring wide = p.wstring();
    if (wide.empty())
        return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return p.string();
    std::string utf8(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), utf8.data(), len, nullptr, nullptr);
    return utf8;
}

std::string FormatSize(uint64_t bytes)
{
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int idx = 0;
    double val = static_cast<double>(bytes);
    while (val >= 1024.0 && idx < 4)
    {
        val /= 1024.0;
        ++idx;
    }
    char buf[64]{};
    if (idx == 0)
        std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
    else
        std::snprintf(buf, sizeof(buf), "%.2f %s", val, units[idx]);
    return buf;
}

std::string DetectMagic(const std::vector<uint8_t> &head)
{
    if (head.size() >= 2 && head[0] == 'M' && head[1] == 'Z')
        return "Windows PE Executable / DLL (MZ)";
    if (head.size() >= 4 && head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F')
        return "Linux ELF Binary";
    if (head.size() >= 4 && head[0] == '%' && head[1] == 'P' && head[2] == 'D' && head[3] == 'F')
        return "PDF Document";
    if (head.size() >= 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 0x03 && head[3] == 0x04)
        return "ZIP Archive / Office OOXML / APK";
    if (head.size() >= 8 && head[0] == 0x89 && head[1] == 'P' && head[2] == 'N' && head[3] == 'G')
        return "PNG Image";
    if (head.size() >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF)
        return "JPEG Image";
    if (head.size() >= 6 && head[0] == 'R' && head[1] == 'a' && head[2] == 'r' && head[3] == '!')
        return "RAR Archive";
    if (head.size() >= 6 && head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF)
        return "7-Zip Archive";
    if (head.size() >= 15 && std::string(reinterpret_cast<const char *>(head.data()), 15) == "SQLite format 3")
        return "SQLite 3 Database";
    return "Generic Binary / Text Data";
}

struct CngHasher
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::vector<uint8_t> hashObj;
    std::vector<uint8_t> digest;

    bool Init(LPCWSTR algId)
    {
        if (BCryptOpenAlgorithmProvider(&hAlg, algId, nullptr, 0) != 0)
            return false;
        DWORD objLen = 0, dataLen = 0, hashLen = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(DWORD), &dataLen, 0);
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(DWORD), &dataLen, 0);
        hashObj.resize(objLen);
        digest.resize(hashLen);
        return BCryptCreateHash(hAlg, &hHash, hashObj.data(), objLen, nullptr, 0, 0) == 0;
    }

    void Update(const uint8_t *data, size_t len)
    {
        if (hHash && len > 0)
        {
            BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0);
        }
    }

    std::string FinishHex()
    {
        if (!hHash)
            return {};
        BCryptFinishHash(hHash, digest.data(), static_cast<ULONG>(digest.size()), 0);
        std::string out;
        out.reserve(digest.size() * 2);
        for (uint8_t b : digest)
        {
            char hex[4]{};
            std::snprintf(hex, sizeof(hex), "%02x", b);
            out += hex;
        }
        return out;
    }

    ~CngHasher()
    {
        if (hHash)
            BCryptDestroyHash(hHash);
        if (hAlg)
            BCryptCloseAlgorithmProvider(hAlg, 0);
    }
};

} // namespace

FileAnalysisResult FileHashAnalyzer::Analyze(const std::string &utf8Path)
{
    FileAnalysisResult res;
    res.filePath = utf8Path;

    std::filesystem::path p = PathFromUtf8(utf8Path);
    res.fileName = PathToUtf8(p.filename());

    std::ifstream in(p, std::ios::binary);
    if (!in.is_open())
    {
        res.errorMessage = "Unable to open file for reading.";
        return res;
    }

    CngHasher md5, sha1, sha256;
    if (!md5.Init(BCRYPT_MD5_ALGORITHM) || !sha1.Init(BCRYPT_SHA1_ALGORITHM) || !sha256.Init(BCRYPT_SHA256_ALGORITHM))
    {
        res.errorMessage = "Windows CNG cryptographic provider initialization failed.";
        return res;
    }

    std::array<uint64_t, 256> freq{};
    std::vector<uint8_t> buffer(65536);
    std::vector<uint8_t> headerBytes;
    uint64_t totalBytes = 0;

    while (in)
    {
        in.read(reinterpret_cast<char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        std::streamsize got = in.gcount();
        if (got <= 0)
            break;

        size_t chunkLen = static_cast<size_t>(got);
        if (headerBytes.size() < 32)
        {
            size_t take = std::min<size_t>(32 - headerBytes.size(), chunkLen);
            headerBytes.insert(headerBytes.end(), buffer.begin(), buffer.begin() + take);
        }

        md5.Update(buffer.data(), chunkLen);
        sha1.Update(buffer.data(), chunkLen);
        sha256.Update(buffer.data(), chunkLen);

        for (size_t i = 0; i < chunkLen; ++i)
        {
            freq[buffer[i]]++;
        }
        totalBytes += chunkLen;
    }

    res.success = true;
    res.fileSizeBytes = totalBytes;
    res.humanSize = FormatSize(totalBytes);
    res.magicType = DetectMagic(headerBytes);
    res.md5 = md5.FinishHex();
    res.sha1 = sha1.FinishHex();
    res.sha256 = sha256.FinishHex();

    double entropy = 0.0;
    if (totalBytes > 0)
    {
        double invTotal = 1.0 / static_cast<double>(totalBytes);
        for (uint64_t count : freq)
        {
            if (count > 0)
            {
                double prob = static_cast<double>(count) * invTotal;
                entropy -= prob * std::log2(prob);
            }
        }
    }
    res.shannonEntropy = entropy;

    if (entropy >= 7.5)
        res.entropyVerdict = "HIGH (Packed / Encrypted / Compressed)";
    else if (entropy >= 6.5)
        res.entropyVerdict = "ELEVATED (Dense Binary / Media)";
    else if (entropy >= 4.5)
        res.entropyVerdict = "NORMAL (Standard Executable / Code)";
    else
        res.entropyVerdict = "LOW (Plaintext / Structured)";

    return res;
}

} // namespace core