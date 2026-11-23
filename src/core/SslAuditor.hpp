#pragma once

#include <string>
#include <vector>

namespace core
{

struct SecurityHeaderCheck
{
    std::string name;
    bool present = false;
    std::string value;
    std::string recommendation;
};

struct SslAuditResult
{
    bool success = false;
    std::string host;
    std::string errorMessage;
    int httpStatus = 0;

    bool certValid = false;
    std::string subject;
    std::string issuer;
    std::string validFrom;
    std::string validTo;
    int daysRemaining = 0;
    std::string signatureAlgo;
    std::string serialNumber;
    std::string serverBanner;

    int securityScore = 0;
    std::string grade = "F";
    std::vector<SecurityHeaderCheck> headers;
};

class SslAuditor
{
  public:
    static SslAuditResult Audit(const std::string &rawTarget);
};

} // namespace core