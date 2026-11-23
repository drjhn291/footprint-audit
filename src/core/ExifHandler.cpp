#include "ExifHandler.hpp"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

namespace core
{

namespace
{

uint16_t ReadU16(const uint8_t *p, bool big_endian)
{
    if (big_endian)
        return (static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]);
    return (static_cast<uint16_t>(p[1]) << 8) | static_cast<uint16_t>(p[0]);
}

uint32_t ReadU32(const uint8_t *p, bool big_endian)
{
    if (big_endian)
    {
        return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
    }
    return (static_cast<uint32_t>(p[3]) << 24) | (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) | static_cast<uint32_t>(p[0]);
}

double ReadRational(const uint8_t *p, bool big_endian)
{
    uint32_t num = ReadU32(p, big_endian);
    uint32_t den = ReadU32(p + 4, big_endian);
    if (den == 0)
        return 0.0;
    return static_cast<double>(num) / static_cast<double>(den);
}

std::string TrimNullAndSpace(const std::string &s)
{
    size_t start = 0;
    while (start < s.size() && (s[start] == '\0' || std::isspace(static_cast<unsigned char>(s[start]))))
        start++;
    size_t end = s.size();
    while (end > start && (s[end - 1] == '\0' || std::isspace(static_cast<unsigned char>(s[end - 1]))))
        end--;
    return s.substr(start, end - start);
}

std::string ExtractFilename(const std::string &path)
{
    size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos)
        return path;
    return path.substr(pos + 1);
}

std::string TagNameFromId(uint16_t tag, bool is_gps)
{
    if (is_gps)
    {
        switch (tag)
        {
        case 0x0000:
            return "GPSVersionID";
        case 0x0001:
            return "GPSLatitudeRef";
        case 0x0002:
            return "GPSLatitude";
        case 0x0003:
            return "GPSLongitudeRef";
        case 0x0004:
            return "GPSLongitude";
        case 0x0005:
            return "GPSAltitudeRef";
        case 0x0006:
            return "GPSAltitude";
        case 0x0007:
            return "GPSTimeStamp";
        case 0x001D:
            return "GPSDateStamp";
        default:
            break;
        }
    }
    switch (tag)
    {
    case 0x010E:
        return "ImageDescription";
    case 0x010F:
        return "Make";
    case 0x0110:
        return "Model";
    case 0x0112:
        return "Orientation";
    case 0x011A:
        return "XResolution";
    case 0x011B:
        return "YResolution";
    case 0x0131:
        return "Software";
    case 0x0132:
        return "DateTime";
    case 0x013B:
        return "Artist";
    case 0x8298:
        return "Copyright";
    case 0x829A:
        return "ExposureTime";
    case 0x829D:
        return "FNumber";
    case 0x8827:
        return "ISOSpeedRatings";
    case 0x9003:
        return "DateTimeOriginal";
    case 0x9004:
        return "DateTimeDigitized";
    case 0x920A:
        return "FocalLength";
    case 0xA002:
        return "PixelXDimension";
    case 0xA003:
        return "PixelYDimension";
    case 0xA430:
        return "CameraOwnerName";
    case 0xA431:
        return "BodySerialNumber";
    case 0xA433:
        return "LensMake";
    case 0xA434:
        return "LensModel";
    default:
        break;
    }
    std::ostringstream oss;
    oss << "Tag_0x" << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << tag;
    return oss.str();
}

size_t TypeByteSize(uint16_t type)
{
    switch (type)
    {
    case 1:
    case 2:
    case 6:
    case 7:
        return 1;
    case 3:
    case 8:
        return 2;
    case 4:
    case 9:
    case 11:
        return 4;
    case 5:
    case 10:
    case 12:
        return 8;
    default:
        return 0;
    }
}

struct GpsAccumulator
{
    std::string lat_ref;
    std::string lon_ref;
    double lat_deg = 0.0;
    double lon_deg = 0.0;
    bool has_lat = false;
    bool has_lon = false;
    double alt = 0.0;
    int alt_ref = 0;
};

void ParseIfd(const uint8_t *tiff, size_t tiff_len, uint32_t ifd_offset, bool big_endian, bool is_gps,
              const std::string &group_name, ExifInspectResult &out, GpsAccumulator &gps, int depth = 0)
{
    if (depth > 4 || ifd_offset == 0 || static_cast<size_t>(ifd_offset) + 2 > tiff_len)
        return;

    uint16_t count = ReadU16(tiff + ifd_offset, big_endian);
    size_t pos = static_cast<size_t>(ifd_offset) + 2;

    for (uint16_t i = 0; i < count; ++i)
    {
        if (pos + 12 > tiff_len)
            break;

        uint16_t tag = ReadU16(tiff + pos, big_endian);
        uint16_t type = ReadU16(tiff + pos + 2, big_endian);
        uint32_t num_components = ReadU32(tiff + pos + 4, big_endian);
        const uint8_t *val_field = tiff + pos + 8;

        size_t unit_size = TypeByteSize(type);
        size_t total_bytes = unit_size * static_cast<size_t>(num_components);
        const uint8_t *data_ptr = nullptr;

        if (total_bytes <= 4)
        {
            data_ptr = val_field;
        }
        else
        {
            uint32_t offset = ReadU32(val_field, big_endian);
            if (static_cast<size_t>(offset) + total_bytes <= tiff_len)
            {
                data_ptr = tiff + offset;
            }
        }

        if (!is_gps && tag == 0x8769 && data_ptr && total_bytes >= 4)
        {
            uint32_t sub_offset = ReadU32(data_ptr, big_endian);
            ParseIfd(tiff, tiff_len, sub_offset, big_endian, false, "EXIF", out, gps, depth + 1);
        }
        else if (!is_gps && tag == 0x8825 && data_ptr && total_bytes >= 4)
        {
            uint32_t gps_offset = ReadU32(data_ptr, big_endian);
            ParseIfd(tiff, tiff_len, gps_offset, big_endian, true, "GPS", out, gps, depth + 1);
        }
        else if (data_ptr && unit_size > 0)
        {
            std::string val_str;
            if (type == 2)
            {
                val_str = TrimNullAndSpace(std::string(reinterpret_cast<const char *>(data_ptr), total_bytes));
            }
            else if (type == 1 && is_gps && tag == 0x0005 && num_components >= 1)
            {
                gps.alt_ref = data_ptr[0];
                val_str = (gps.alt_ref == 1) ? "Below Sea Level" : "Above Sea Level";
            }
            else if (type == 3 && num_components >= 1)
            {
                val_str = std::to_string(ReadU16(data_ptr, big_endian));
            }
            else if (type == 4 && num_components >= 1)
            {
                val_str = std::to_string(ReadU32(data_ptr, big_endian));
            }
            else if (type == 5 && num_components >= 1)
            {
                if (is_gps && (tag == 0x0002 || tag == 0x0004) && num_components >= 3)
                {
                    double d = ReadRational(data_ptr, big_endian);
                    double m = ReadRational(data_ptr + 8, big_endian);
                    double s = ReadRational(data_ptr + 16, big_endian);
                    double dec = d + (m / 60.0) + (s / 3600.0);
                    if (tag == 0x0002)
                    {
                        gps.lat_deg = dec;
                        gps.has_lat = true;
                    }
                    else
                    {
                        gps.lon_deg = dec;
                        gps.has_lon = true;
                    }
                    std::ostringstream oss;
                    oss << std::fixed << std::setprecision(6) << dec << " deg";
                    val_str = oss.str();
                }
                else
                {
                    double r = ReadRational(data_ptr, big_endian);
                    if (is_gps && tag == 0x0006)
                    {
                        gps.alt = r;
                    }
                    std::ostringstream oss;
                    oss << std::fixed << std::setprecision(4) << r;
                    val_str = oss.str();
                }
            }

            if (!val_str.empty())
            {
                std::string tname = TagNameFromId(tag, is_gps);
                out.tags.push_back({group_name, tname, val_str});

                if (is_gps && tag == 0x0001)
                    gps.lat_ref = val_str;
                else if (is_gps && tag == 0x0003)
                    gps.lon_ref = val_str;
                else if (!is_gps && tag == 0x010F)
                    out.make = val_str;
                else if (!is_gps && tag == 0x0110)
                    out.model = val_str;
                else if (!is_gps && tag == 0x0131)
                    out.software = val_str;
                else if (!is_gps && (tag == 0x9003 || (tag == 0x0132 && out.datetime.empty())))
                    out.datetime = val_str;
            }
        }

        pos += 12;
    }
}

void ParseTiffBlock(const uint8_t *tiff, size_t tiff_len, ExifInspectResult &out)
{
    if (tiff_len < 8)
        return;

    bool big_endian = false;
    if (tiff[0] == 'M' && tiff[1] == 'M')
        big_endian = true;
    else if (tiff[0] == 'I' && tiff[1] == 'I')
        big_endian = false;
    else
        return;

    if (ReadU16(tiff + 2, big_endian) != 0x002A)
        return;

    uint32_t ifd0 = ReadU32(tiff + 4, big_endian);
    GpsAccumulator gps;
    ParseIfd(tiff, tiff_len, ifd0, big_endian, false, "Image", out, gps, 0);

    if (gps.has_lat && gps.has_lon)
    {
        out.has_gps = true;
        out.latitude = (gps.lat_ref == "S" || gps.lat_ref == "s") ? -gps.lat_deg : gps.lat_deg;
        out.longitude = (gps.lon_ref == "W" || gps.lon_ref == "w") ? -gps.lon_deg : gps.lon_deg;
        out.altitude = (gps.alt_ref == 1) ? -gps.alt : gps.alt;
    }
}

void InspectJpeg(const std::vector<uint8_t> &buf, ExifInspectResult &out)
{
    out.format = "JPEG";
    size_t pos = 2;
    while (pos + 4 <= buf.size())
    {
        if (buf[pos] != 0xFF)
            break;
        while (pos < buf.size() && buf[pos] == 0xFF)
            pos++;
        if (pos >= buf.size())
            break;

        uint8_t marker = buf[pos++];
        if (marker == 0xD9 || marker == 0xDA)
            break;
        if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7))
            continue;

        if (pos + 2 > buf.size())
            break;
        uint16_t seg_len = ReadU16(buf.data() + pos, true);
        if (seg_len < 2 || pos + seg_len > buf.size())
            break;

        const uint8_t *payload = buf.data() + pos + 2;
        size_t payload_len = static_cast<size_t>(seg_len) - 2;

        if ((marker == 0xC0 || marker == 0xC1 || marker == 0xC2) && payload_len >= 5)
        {
            out.height = ReadU16(payload + 1, true);
            out.width = ReadU16(payload + 3, true);
        }
        else if (marker == 0xE1 && payload_len >= 6 && std::memcmp(payload, "Exif\0\0", 6) == 0)
        {
            ParseTiffBlock(payload + 6, payload_len - 6, out);
        }
        else if (marker == 0xE1 && payload_len > 29 && std::memcmp(payload, "http://ns.adobe.com/xap/1.0/", 28) == 0)
        {
            out.tags.push_back({"XMP", "Adobe XMP Packet", std::to_string(payload_len) + " bytes embedded"});
        }
        else if (marker == 0xED && payload_len > 14 && std::memcmp(payload, "Photoshop 3.0", 13) == 0)
        {
            out.tags.push_back({"IPTC", "Photoshop / IPTC Profile", std::to_string(payload_len) + " bytes embedded"});
        }
        else if (marker == 0xFE && payload_len > 0)
        {
            std::string comment = TrimNullAndSpace(std::string(reinterpret_cast<const char *>(payload), payload_len));
            if (!comment.empty())
            {
                out.tags.push_back({"Comment", "JPEG COM Marker", comment});
            }
        }

        pos += seg_len;
    }
}

void InspectPng(const std::vector<uint8_t> &buf, ExifInspectResult &out)
{
    out.format = "PNG";
    size_t pos = 8;
    while (pos + 12 <= buf.size())
    {
        uint32_t len = ReadU32(buf.data() + pos, true);
        std::string type(reinterpret_cast<const char *>(buf.data() + pos + 4), 4);
        if (pos + 12 + static_cast<size_t>(len) > buf.size())
            break;

        const uint8_t *data = buf.data() + pos + 8;

        if (type == "IHDR" && len >= 8)
        {
            out.width = static_cast<int>(ReadU32(data, true));
            out.height = static_cast<int>(ReadU32(data + 4, true));
        }
        else if (type == "eXIf" && len >= 8)
        {
            ParseTiffBlock(data, len, out);
        }
        else if (type == "tEXt" && len > 0)
        {
            const uint8_t *nul = static_cast<const uint8_t *>(std::memchr(data, 0, len));
            if (nul)
            {
                size_t key_len = static_cast<size_t>(nul - data);
                std::string key(reinterpret_cast<const char *>(data), key_len);
                std::string val(reinterpret_cast<const char *>(nul + 1), len - key_len - 1);
                out.tags.push_back({"PNG-tEXt", key, TrimNullAndSpace(val)});
                if (key == "Software" && out.software.empty())
                    out.software = TrimNullAndSpace(val);
            }
        }
        else if (type == "iTXt" && len > 0)
        {
            const uint8_t *nul = static_cast<const uint8_t *>(std::memchr(data, 0, len));
            if (nul)
            {
                size_t key_len = static_cast<size_t>(nul - data);
                std::string key(reinterpret_cast<const char *>(data), key_len);
                out.tags.push_back({"PNG-iTXt", key, std::to_string(len) + " bytes"});
            }
        }

        pos += 12 + static_cast<size_t>(len);
        if (type == "IEND")
            break;
    }
}

std::string BuildCleanOutputPath(const std::string &input_path)
{
    size_t dot = input_path.find_last_of('.');
    size_t slash = input_path.find_last_of("\\/");
    if (dot != std::string::npos && (slash == std::string::npos || dot > slash))
    {
        return input_path.substr(0, dot) + "_clean" + input_path.substr(dot);
    }
    return input_path + "_clean";
}

} // namespace

ExifInspectResult ExifHandler::InspectFile(const std::string &filepath)
{
    ExifInspectResult res;
    res.filepath = filepath;
    res.filename = ExtractFilename(filepath);

    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        res.error = "Unable to open file.";
        return res;
    }

    std::streamsize sz = file.tellg();
    if (sz <= 8)
    {
        res.error = "File is empty or too small.";
        return res;
    }

    res.file_size = static_cast<size_t>(sz);
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(res.file_size);
    if (!file.read(reinterpret_cast<char *>(buf.data()), sz))
    {
        res.error = "Failed reading file bytes.";
        return res;
    }

    const uint8_t png_sig[8] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (buf[0] == 0xFF && buf[1] == 0xD8)
    {
        InspectJpeg(buf, res);
        res.loaded = true;
    }
    else if (std::memcmp(buf.data(), png_sig, 8) == 0)
    {
        InspectPng(buf, res);
        res.loaded = true;
    }
    else
    {
        res.error = "Unsupported format. Please drop a JPEG (.jpg/.jpeg) or PNG (.png) image.";
    }

    return res;
}

bool ExifHandler::StripMetadata(const std::string &input_path, std::string &output_path, std::string &error_msg)
{
    std::ifstream file(input_path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        error_msg = "Could not open source image.";
        return false;
    }

    std::streamsize sz = file.tellg();
    if (sz <= 8)
    {
        error_msg = "Invalid image size.";
        return false;
    }

    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    file.read(reinterpret_cast<char *>(buf.data()), sz);
    file.close();

    output_path = BuildCleanOutputPath(input_path);
    std::vector<uint8_t> out;
    out.reserve(buf.size());

    const uint8_t png_sig[8] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (buf[0] == 0xFF && buf[1] == 0xD8)
    {
        out.push_back(0xFF);
        out.push_back(0xD8);
        size_t pos = 2;
        while (pos + 2 <= buf.size())
        {
            if (buf[pos] != 0xFF)
            {
                out.insert(out.end(), buf.begin() + pos, buf.end());
                break;
            }
            size_t marker_start = pos;
            while (pos < buf.size() && buf[pos] == 0xFF)
                pos++;
            if (pos >= buf.size())
                break;

            uint8_t marker = buf[pos++];
            if (marker == 0xDA)
            {
                out.insert(out.end(), buf.begin() + marker_start, buf.end());
                break;
            }
            if (marker == 0xD9)
            {
                out.push_back(0xFF);
                out.push_back(0xD9);
                break;
            }
            if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7))
            {
                out.push_back(0xFF);
                out.push_back(marker);
                continue;
            }

            if (pos + 2 > buf.size())
                break;
            uint16_t seg_len = ReadU16(buf.data() + pos, true);
            if (seg_len < 2 || pos + seg_len > buf.size())
                break;

            bool strip = (marker == 0xE1 || marker == 0xE2 || marker == 0xEC || marker == 0xED || marker == 0xEE ||
                          marker == 0xFE);
            if (!strip)
            {
                out.push_back(0xFF);
                out.push_back(marker);
                out.insert(out.end(), buf.begin() + pos, buf.begin() + pos + seg_len);
            }
            pos += seg_len;
        }
    }
    else if (std::memcmp(buf.data(), png_sig, 8) == 0)
    {
        out.insert(out.end(), buf.begin(), buf.begin() + 8);
        size_t pos = 8;
        while (pos + 12 <= buf.size())
        {
            uint32_t len = ReadU32(buf.data() + pos, true);
            std::string type(reinterpret_cast<const char *>(buf.data() + pos + 4), 4);
            size_t chunk_total = 12 + static_cast<size_t>(len);
            if (pos + chunk_total > buf.size())
                break;

            bool keep = (type == "IHDR" || type == "PLTE" || type == "IDAT" || type == "IEND" || type == "tRNS" ||
                         type == "sRGB" || type == "gAMA");
            if (keep)
            {
                out.insert(out.end(), buf.begin() + pos, buf.begin() + pos + chunk_total);
            }
            pos += chunk_total;
            if (type == "IEND")
                break;
        }
    }
    else
    {
        error_msg = "Unsupported image format.";
        return false;
    }

    std::ofstream out_file(output_path, std::ios::binary);
    if (!out_file.is_open())
    {
        error_msg = "Failed to write sanitized file.";
        return false;
    }
    out_file.write(reinterpret_cast<const char *>(out.data()), static_cast<std::streamsize>(out.size()));
    return true;
}

} // namespace core