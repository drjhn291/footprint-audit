#pragma once

#include <map>
#include <string>
#include <vector>

namespace core
{

struct PlatformRule
{
    std::string name;
    std::string category;
    std::string domain;
    std::string url_template;
    std::string probe_template;
    std::string main_url;
    std::vector<std::string> error_types;
    std::vector<std::string> error_msgs;
    std::string error_url;
    std::vector<int> error_codes;
    std::string regex_check;
    std::string request_method;
    std::string request_payload_json;
    std::map<std::string, std::string> headers;
    bool is_nsfw = false;
};

struct UsernameFinding
{
    std::string platform;
    std::string category;
    std::string domain;
    std::string url;
    std::string matched_handle;
    int status_code = 0;
    int http_status = 0;
    bool found = false;
    std::string avatar_url;
    std::string display_name;
    std::string bio;
};

struct BreachRecord
{
    std::string source_name;
    std::string date;
    std::string provider;
    std::string exposed_passwords;
};

struct EmailAuditResult
{
    std::string email;
    std::vector<BreachRecord> breaches;
    std::string github_user;
    std::string github_url;
    std::string gravatar_name;
    std::string gravatar_url;
    bool completed = false;
};

struct SubdomainResult
{
    std::string subdomain;
    std::string issuer;
    std::string logged_at;
};

struct DomainAuditResult
{
    std::string domain;
    std::string resolved_ip;
    std::vector<std::string> mx_records;
    std::string spf_record;
    std::string dmarc_record;
    bool has_spf = false;
    bool has_dmarc = false;
    bool dmarc_enforced = false;
    std::string spoof_risk;
    std::vector<std::string> subdomains;
    bool completed = false;
};

struct IpReconResult
{
    std::string query;
    std::string ip;
    std::string country;
    std::string country_code;
    std::string region;
    std::string city;
    std::string isp;
    std::string org;
    std::string asn;
    bool is_proxy = false;
    bool is_hosting = false;
    std::vector<int> ports;
    std::vector<std::string> vulns;
    std::vector<std::string> hostnames;
    std::vector<std::string> tags;
    std::vector<std::string> cpes;
    std::string error;
    bool completed = false;
};

struct ExifTag
{
    std::string group;
    std::string name;
    std::string value;
};

struct ExifInspectResult
{
    std::string filepath;
    std::string filename;
    std::string format;
    size_t file_size = 0;
    int width = 0;
    int height = 0;
    std::string make;
    std::string model;
    std::string software;
    std::string datetime;
    bool has_gps = false;
    double latitude = 0.0;
    double longitude = 0.0;
    double altitude = 0.0;
    std::vector<ExifTag> tags;
    std::string error;
    bool loaded = false;
};

struct PivotAction
{
    bool pending = false;
    int target_tab = 0;
    std::string payload;
};

} // namespace core