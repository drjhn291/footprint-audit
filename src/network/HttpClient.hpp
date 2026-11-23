#pragma once

#include <map>
#include <string>
#include <vector>

namespace network
{

struct HttpResponse
{
    int status = 0;
    std::string body;
    std::string final_url;
};

class HttpClient
{
  public:
    static HttpResponse Request(const std::string &method, const std::string &url,
                                const std::map<std::string, std::string> &headers = {}, const std::string &payload = "",
                                bool allow_redirects = true, int timeout_ms = 10000);
    static HttpResponse Get(const std::string &url, int timeout_ms = 10000);
    static std::vector<unsigned char> GetBytes(const std::string &url, int timeout_ms = 10000);
};

} // namespace network