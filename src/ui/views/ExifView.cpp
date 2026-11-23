#include "ExifView.hpp"

#include <windows.h>

#include <commdlg.h>
#include <shellapi.h>
#include <wincodec.h>

#include "../../core/ExifHandler.hpp"
#include "../../core/HtmlReportExporter.hpp"
#include "../Components.hpp"
#include "../Theme.hpp"
#include "imgui.h"
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <vector>

#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "windowscodecs.lib")

namespace ui::views
{

namespace
{

std::wstring Utf8ToWidePath(const std::string &utf8)
{
    if (utf8.empty())
        return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), nullptr, 0);
    if (len <= 0)
        return std::wstring(utf8.begin(), utf8.end());
    std::wstring wide(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), wide.data(), len);
    return wide;
}

} // namespace

ExifView::~ExifView()
{
    ReleasePreview();
}

void ExifView::ReleasePreview()
{
    if (m_previewSrv)
    {
        m_previewSrv->Release();
        m_previewSrv = nullptr;
    }
    m_previewW = 0;
    m_previewH = 0;
}

void ExifView::EnsurePreviewTexture(ID3D11Device *device)
{
    if (!m_previewDirty || !device || !m_result.loaded)
        return;

    m_previewDirty = false;
    ReleasePreview();

    HRESULT hrCom = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    IWICImagingFactory *factory = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory))))
    {
        if (hrCom == S_OK)
            CoUninitialize();
        return;
    }

    std::wstring wpath = Utf8ToWidePath(m_result.filepath);
    IWICBitmapDecoder *decoder = nullptr;
    if (SUCCEEDED(factory->CreateDecoderFromFilename(wpath.c_str(), nullptr, GENERIC_READ,
                                                     WICDecodeMetadataCacheOnDemand, &decoder)))
    {
        IWICBitmapFrameDecode *frame = nullptr;
        if (SUCCEEDED(decoder->GetFrame(0, &frame)))
        {
            UINT origW = 0, origH = 0;
            frame->GetSize(&origW, &origH);

            UINT dstW = origW;
            UINT dstH = origH;
            const UINT maxDim = 640;
            if (dstW > maxDim || dstH > maxDim)
            {
                if (dstW >= dstH)
                {
                    dstH = std::max<UINT>(1, (dstH * maxDim) / dstW);
                    dstW = maxDim;
                }
                else
                {
                    dstW = std::max<UINT>(1, (dstW * maxDim) / dstH);
                    dstH = maxDim;
                }
            }

            IWICBitmapSource *source = frame;
            IWICBitmapScaler *scaler = nullptr;
            if ((dstW != origW || dstH != origH) && SUCCEEDED(factory->CreateBitmapScaler(&scaler)))
            {
                if (SUCCEEDED(scaler->Initialize(frame, dstW, dstH, WICBitmapInterpolationModeFant)))
                {
                    source = scaler;
                }
            }

            IWICFormatConverter *converter = nullptr;
            if (SUCCEEDED(factory->CreateFormatConverter(&converter)))
            {
                if (SUCCEEDED(converter->Initialize(source, GUID_WICPixelFormat32bppRGBA, WICBitmapDitherTypeNone,
                                                    nullptr, 0.0f, WICBitmapPaletteTypeCustom)))
                {
                    std::vector<BYTE> pixels(static_cast<size_t>(dstW) * dstH * 4);
                    if (SUCCEEDED(
                            converter->CopyPixels(nullptr, dstW * 4, static_cast<UINT>(pixels.size()), pixels.data())))
                    {
                        D3D11_TEXTURE2D_DESC desc{};
                        desc.Width = dstW;
                        desc.Height = dstH;
                        desc.MipLevels = 1;
                        desc.ArraySize = 1;
                        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
                        desc.SampleDesc.Count = 1;
                        desc.Usage = D3D11_USAGE_DEFAULT;
                        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

                        D3D11_SUBRESOURCE_DATA initData{};
                        initData.pSysMem = pixels.data();
                        initData.SysMemPitch = dstW * 4;

                        ID3D11Texture2D *tex = nullptr;
                        if (SUCCEEDED(device->CreateTexture2D(&desc, &initData, &tex)))
                        {
                            device->CreateShaderResourceView(tex, nullptr, &m_previewSrv);
                            tex->Release();
                            m_previewW = static_cast<int>(dstW);
                            m_previewH = static_cast<int>(dstH);
                        }
                    }
                }
                converter->Release();
            }
            if (scaler)
                scaler->Release();
            frame->Release();
        }
        decoder->Release();
    }
    factory->Release();
    if (hrCom == S_OK)
        CoUninitialize();
}

void ExifView::LoadFile(const std::string &filepath, std::string &status_text)
{
    m_cleanMessage.clear();
    m_result = core::ExifHandler::InspectFile(filepath);
    if (m_result.loaded)
    {
        m_previewDirty = true;
        status_text = "Inspected " + m_result.filename + ": " + std::to_string(m_result.tags.size()) +
                      " metadata tags extracted.";
    }
    else
    {
        ReleasePreview();
        status_text = "Metadata inspection failed: " + m_result.error;
    }
}

void ExifView::Render(ID3D11Device *device, std::string &status_text)
{
    EnsurePreviewTexture(device);

    Components::SectionHeader("EXIF & Metadata Privacy Inspector (Drag & Drop)",
                              "Drag and drop any JPEG or PNG image onto this window to inspect GPS coordinates, device "
                              "info & wipe metadata.");

    if (ImGui::Button("Select Image (.jpg / .png)...", ImVec2(220.0f, 0.0f)))
    {
        char fileBuf[MAX_PATH]{};
        OPENFILENAMEA ofn{};
        ofn.lStructSize = sizeof(ofn);
        ofn.lpstrFilter = "Images (*.jpg;*.jpeg;*.png)\0*.jpg;*.jpeg;*.png\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = fileBuf;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
        if (GetOpenFileNameA(&ofn))
        {
            LoadFile(fileBuf, status_text);
        }
    }

    ImGui::SameLine();
    ImGui::BeginDisabled(!m_result.loaded);
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.16f, 0.62f, 0.42f, 1.00f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.72f, 0.50f, 1.00f));
    if (ImGui::Button("Strip All Metadata & Save Clean Copy", ImVec2(275.0f, 0.0f)))
    {
        std::string out_path;
        std::string err;
        if (core::ExifHandler::StripMetadata(m_result.filepath, out_path, err))
        {
            m_cleanMessage = "Sanitized copy saved to: " + out_path;
            status_text = m_cleanMessage;
        }
        else
        {
            m_cleanMessage = "Error: " + err;
        }
    }
    ImGui::PopStyleColor(2);

    ImGui::SameLine();
    if (ImGui::Button("Export HTML Report", ImVec2(165.0f, 0.0f)))
    {
        core::ExecutiveReportData rep;
        rep.moduleName = "EXIF Forensic Metadata Audit";
        rep.target = m_result.filename;
        rep.riskBadge =
            m_result.has_gps ? "GPS EXPOSED" : (m_result.tags.empty() ? "CLEAN / NO EXIF" : "METADATA PRESENT");
        rep.riskColorHex = m_result.has_gps ? "#f87171" : (m_result.tags.empty() ? "#34d399" : "#fbbf24");
        rep.kpis = {{"Format & Resolution", m_result.format + " (" + std::to_string(m_result.width) + "x" +
                                                std::to_string(m_result.height) + ")"},
                    {"Metadata Tags", std::to_string(m_result.tags.size())},
                    {"GPS Coordinates", m_result.has_gps ? "EXPOSED" : "None"}};
        if (m_result.has_gps)
        {
            char gpsStr[96]{};
            std::snprintf(gpsStr, sizeof(gpsStr), "%.6f, %.6f (Alt: %.1f m)", m_result.latitude, m_result.longitude,
                          m_result.altitude);
            rep.details.push_back({"GPS Location", gpsStr});
        }
        if (!m_result.make.empty() || !m_result.model.empty())
            rep.details.push_back({"Camera Device", m_result.make + " " + m_result.model});
        if (!m_result.software.empty())
            rep.details.push_back({"Software", m_result.software});

        core::ReportTable tbl;
        tbl.title = "Extracted EXIF / XMP / Comment Tags";
        tbl.headers = {"Group", "Tag Name", "Extracted Value"};
        for (const auto &t : m_result.tags)
        {
            tbl.rows.push_back({t.group, t.name, t.value});
        }
        rep.tables.push_back(std::move(tbl));
        std::string saved = core::HtmlReportExporter::ExportAndOpen(rep, true);
        status_text = "Exported executive HTML report: " + saved;
    }
    ImGui::EndDisabled();

    ImGui::Spacing();
    std::string fmt_kpi =
        m_result.loaded
            ? (m_result.format + " (" + std::to_string(m_result.width) + "x" + std::to_string(m_result.height) + ")")
            : "-";
    std::string tags_kpi = m_result.loaded ? std::to_string(m_result.tags.size()) + " Tags" : "-";
    std::string gps_kpi = m_result.loaded ? (m_result.has_gps ? "EXPOSED" : "None") : "-";

    Components::MetricCard("ex_kpi1", "IMAGE FORMAT", fmt_kpi.c_str(), ImVec4(0.24f, 0.72f, 0.98f, 1.00f), 215.0f);
    ImGui::SameLine();
    Components::MetricCard(
        "ex_kpi2", "METADATA TAGS", tags_kpi.c_str(),
        m_result.tags.empty() ? ImVec4(0.20f, 0.86f, 0.54f, 1.00f) : ImVec4(0.98f, 0.58f, 0.16f, 1.00f), 180.0f);
    ImGui::SameLine();
    Components::MetricCard("ex_kpi3", "GPS LOCATION", gps_kpi.c_str(),
                           m_result.has_gps ? ImVec4(0.96f, 0.32f, 0.36f, 1.00f) : ImVec4(0.20f, 0.86f, 0.54f, 1.00f),
                           180.0f);

    ImGui::Spacing();

    if (!m_result.loaded)
    {
        if (!m_result.error.empty())
        {
            Components::StatusBadge(m_result.error.c_str(), ImVec4(0.96f, 0.32f, 0.36f, 1.00f));
            ImGui::Spacing();
        }
        Components::EmptyState("exif", "No Image Loaded for EXIF Inspection",
                               "Drag and drop any .JPG or .PNG photo anywhere into the window, or click Select Image.");
        return;
    }

    ImGui::BeginChild("ExifBody", ImVec2(0.0f, 0.0f), true);

    if (!m_cleanMessage.empty())
    {
        Components::StatusBadge(m_cleanMessage.c_str(), ImVec4(0.20f, 0.86f, 0.54f, 1.00f));
        ImGui::Spacing();
    }

    if (m_previewSrv && m_previewW > 0 && m_previewH > 0)
    {
        const float maxBox = 136.0f;
        float scale = std::min(maxBox / static_cast<float>(m_previewW), maxBox / static_cast<float>(m_previewH));
        ImVec2 dispSz(m_previewW * scale, m_previewH * scale);

        ImVec2 p = ImGui::GetCursorScreenPos();
        ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(p.x - 3.0f, p.y - 3.0f),
                                                  ImVec2(p.x + dispSz.x + 3.0f, p.y + dispSz.y + 3.0f),
                                                  IM_COL32(18, 28, 46, 240), 10.0f);
        ImGui::Image(reinterpret_cast<ImTextureID>(m_previewSrv), dispSz);
        ImGui::SameLine(0.0f, 16.0f);
    }

    ImGui::BeginGroup();
    ImGui::PushFont(Theme::MonoFont());
    ImGui::TextColored(ImVec4(0.97f, 0.98f, 1.00f, 1.00f), "File: %s", m_result.filepath.c_str());
    ImGui::PopFont();
    ImGui::Spacing();

    if (m_result.has_gps)
    {
        char gps_buf[160];
        std::snprintf(gps_buf, sizeof(gps_buf), "[PRIVACY ALERT] GPS Coordinates: %.6f, %.6f (Alt: %.1f m)",
                      m_result.latitude, m_result.longitude, m_result.altitude);
        Components::StatusBadge(gps_buf, ImVec4(0.96f, 0.32f, 0.36f, 1.00f));

        char coordsPlain[64];
        std::snprintf(coordsPlain, sizeof(coordsPlain), "%.6f, %.6f", m_result.latitude, m_result.longitude);
        ImGui::SameLine();
        Components::CopyButton("copy_gps_coords", coordsPlain);

        if (ImGui::SmallButton("Open in Google Maps ->"))
        {
            char maps_url[256];
            std::snprintf(maps_url, sizeof(maps_url), "https://www.google.com/maps?q=%.6f,%.6f", m_result.latitude,
                          m_result.longitude);
            ShellExecuteA(nullptr, "open", maps_url, nullptr, nullptr, SW_SHOWNORMAL);
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Open in OpenStreetMap ->"))
        {
            char osm_url[256];
            std::snprintf(osm_url, sizeof(osm_url),
                          "https://www.openstreetmap.org/?mlat=%.6f&mlon=%.6f#map=16/%.6f/%.6f", m_result.latitude,
                          m_result.longitude, m_result.latitude, m_result.longitude);
            ShellExecuteA(nullptr, "open", osm_url, nullptr, nullptr, SW_SHOWNORMAL);
        }
    }
    else if (m_result.tags.empty())
    {
        Components::StatusBadge("[CLEAN] Zero EXIF, GPS, XMP or embedded comment metadata found.",
                                ImVec4(0.20f, 0.86f, 0.54f, 1.00f));
    }

    if (!m_result.make.empty() || !m_result.model.empty() || !m_result.software.empty())
    {
        ImGui::Spacing();
        ImGui::BulletText("Device: %s %s   |   Software: %s", m_result.make.c_str(), m_result.model.c_str(),
                          m_result.software.empty() ? "N/A" : m_result.software.c_str());
    }
    ImGui::EndGroup();

    ImGui::Spacing();
    if (!m_result.tags.empty() && ImGui::BeginTable("ExifTable", 3,
                                                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                                        ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                                                    ImVec2(0.0f, 0.0f)))
    {
        ImGui::TableSetupColumn("Group", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Metadata Tag", ImGuiTableColumnFlags_WidthFixed, 210.0f);
        ImGui::TableSetupColumn("Extracted Value", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableHeadersRow();

        for (const auto &t : m_result.tags)
        {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushFont(Theme::MonoFont());
            ImGui::TextDisabled("%s", t.group.c_str());
            ImGui::PopFont();

            ImGui::TableSetColumnIndex(1);
            ImGui::PushFont(Theme::MonoFont());
            ImGui::TextColored(ImVec4(0.65f, 0.85f, 1.00f, 1.00f), "%s", t.name.c_str());
            ImGui::PopFont();

            ImGui::TableSetColumnIndex(2);
            ImGui::PushFont(Theme::MonoFont());
            ImGui::TextUnformatted(t.value.c_str());
            if (ImGui::IsItemHovered())
            {
                ImGui::SetTooltip("%s", t.value.c_str());
            }
            ImGui::PopFont();
        }
        ImGui::EndTable();
    }

    ImGui::EndChild();
}

} // namespace ui::views