#include "Application.hpp"
#include "../core/ConfigLoader.hpp"
#include "../ui/Components.hpp"
#include "../ui/Theme.hpp"
#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <dwmapi.h>
#include <filesystem>
#include <shellapi.h>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace app
{

namespace
{

constexpr int kAppIconResourceId = 101;
Application *g_appInstance = nullptr;

bool IsImageExtension(const std::string &filepath)
{
    size_t dotPos = filepath.find_last_of('.');
    if (dotPos == std::string::npos)
        return false;
    std::string ext = filepath.substr(dotPos);
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".tif" || ext == ".tiff" || ext == ".webp";
}

void DrawAmbientBackdrop(ImDrawList *dl, ImVec2 pos, ImVec2 size, float time, bool scanning)
{
    ImVec2 end(pos.x + size.x, pos.y + size.y);

    dl->AddRectFilledMultiColor(pos, end, IM_COL32(6, 9, 16, 255), IM_COL32(9, 14, 25, 255), IM_COL32(5, 8, 14, 255),
                                IM_COL32(8, 12, 21, 255));

    float pulse = 0.5f + 0.5f * std::sin(time * 1.2f);
    dl->AddCircleFilled(ImVec2(pos.x + size.x * 0.52f, pos.y - 40.0f), 380.0f,
                        IM_COL32(20, 115, 210, static_cast<int>(13 + 5 * pulse)), 40);
    dl->AddCircleFilled(ImVec2(end.x - 160.0f, end.y - 100.0f), 260.0f,
                        IM_COL32(34, 195, 225, static_cast<int>(9 + 4 * pulse)), 32);

    const float step = 32.0f;
    ImU32 dotCol = IM_COL32(72, 108, 165, 24);
    for (float x = pos.x + 24.0f; x < end.x; x += step)
    {
        for (float y = pos.y + 24.0f; y < end.y; y += step)
        {
            dl->AddCircleFilled(ImVec2(x, y), 1.0f, dotCol, 6);
        }
    }

    if (scanning)
    {
        float scanPos = std::fmod(time * 0.70f, 1.0f);
        float beamX = pos.x + size.x * scanPos;
        dl->AddRectFilledMultiColor(ImVec2(beamX - 140.0f, pos.y), ImVec2(beamX, pos.y + 3.0f),
                                    IM_COL32(34, 211, 238, 0), IM_COL32(34, 211, 238, 240), IM_COL32(34, 211, 238, 240),
                                    IM_COL32(34, 211, 238, 0));
    }
}

void LoadFontSet(ImGuiIO &io)
{
    ImFontConfig cfg;
    cfg.OversampleH = 3;
    cfg.OversampleV = 2;
    cfg.PixelSnapH = true;

    const ImWchar *glyphRanges = io.Fonts->GetGlyphRangesDefault();

    const char *regPath = (GetFileAttributesA("fonts\\Inter-Regular.ttf") != INVALID_FILE_ATTRIBUTES)
                              ? "fonts\\Inter-Regular.ttf"
                              : "C:\\Windows\\Fonts\\segoeui.ttf";
    const char *boldPath = (GetFileAttributesA("fonts\\Inter-Bold.ttf") != INVALID_FILE_ATTRIBUTES)
                               ? "fonts\\Inter-Bold.ttf"
                               : "C:\\Windows\\Fonts\\segoeuib.ttf";
    const char *monoPath = (GetFileAttributesA("C:\\Windows\\Fonts\\CascadiaCode.ttf") != INVALID_FILE_ATTRIBUTES)
                               ? "C:\\Windows\\Fonts\\CascadiaCode.ttf"
                               : "C:\\Windows\\Fonts\\consola.ttf";

    ImFont *fReg = nullptr;
    ImFont *fBold = nullptr;
    ImFont *fTitle = nullptr;
    ImFont *fMono = nullptr;

    if (GetFileAttributesA(regPath) != INVALID_FILE_ATTRIBUTES)
        fReg = io.Fonts->AddFontFromFileTTF(regPath, 16.5f, &cfg, glyphRanges);
    if (GetFileAttributesA(boldPath) != INVALID_FILE_ATTRIBUTES)
    {
        fBold = io.Fonts->AddFontFromFileTTF(boldPath, 16.5f, &cfg, glyphRanges);
        fTitle = io.Fonts->AddFontFromFileTTF(boldPath, 22.0f, &cfg, glyphRanges);
    }
    if (GetFileAttributesA(monoPath) != INVALID_FILE_ATTRIBUTES)
        fMono = io.Fonts->AddFontFromFileTTF(monoPath, 15.0f, &cfg, glyphRanges);

    ui::Theme::SetFonts(fReg, fBold, fTitle, fMono);
}

} // namespace

Application::Application(HINSTANCE hInstance) : m_hInstance(hInstance)
{
    g_appInstance = this;
}

Application::~Application()
{
    m_textureCache.reset();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDirectX();
    if (m_hwnd)
    {
        DestroyWindow(m_hwnd);
    }
    UnregisterClassW(L"FootprintAuditWindowClass", m_hInstance);
    g_appInstance = nullptr;
}

bool Application::InitWindow()
{
    HICON hIconBig = static_cast<HICON>(
        LoadImageW(m_hInstance, MAKEINTRESOURCEW(kAppIconResourceId), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED));
    HICON hIconSmall = static_cast<HICON>(
        LoadImageW(m_hInstance, MAKEINTRESOURCEW(kAppIconResourceId), IMAGE_ICON, 16, 16, LR_SHARED));

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = Application::WndProc;
    wc.hInstance = m_hInstance;
    wc.hIcon = hIconBig;
    wc.hIconSm = hIconSmall;
    wc.lpszClassName = L"FootprintAuditWindowClass";
    RegisterClassExW(&wc);

    m_hwnd = CreateWindowW(wc.lpszClassName, L"Footprint Audit - OSINT & Privacy Suite", WS_OVERLAPPEDWINDOW, 80, 50,
                           1380, 860, nullptr, nullptr, wc.hInstance, nullptr);
    if (!m_hwnd)
        return false;

    if (hIconBig)
        SendMessageW(m_hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(hIconBig));
    if (hIconSmall)
        SendMessageW(m_hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(hIconSmall));

    DragAcceptFiles(m_hwnd, TRUE);

    BOOL darkMode = TRUE;
    DwmSetWindowAttribute(m_hwnd, 20, &darkMode, sizeof(darkMode));
    DwmSetWindowAttribute(m_hwnd, 19, &darkMode, sizeof(darkMode));

    return true;
}

bool Application::InitDirectX()
{
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = m_hwnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};

    HRESULT res =
        D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray,
                                      2, D3D11_SDK_VERSION, &sd, &m_swapChain, &m_device, &featureLevel, &m_context);
    if (res == DXGI_ERROR_UNSUPPORTED)
    {
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags,
                                            featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &m_swapChain, &m_device,
                                            &featureLevel, &m_context);
    }
    if (FAILED(res))
        return false;

    CreateRenderTarget();
    return true;
}

void Application::CreateRenderTarget()
{
    ID3D11Texture2D *pBackBuffer = nullptr;
    m_swapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer)
    {
        m_device->CreateRenderTargetView(pBackBuffer, nullptr, &m_mainRenderTargetView);
        pBackBuffer->Release();
    }
}

void Application::CleanupRenderTarget()
{
    if (m_mainRenderTargetView)
    {
        m_mainRenderTargetView->Release();
        m_mainRenderTargetView = nullptr;
    }
}

void Application::CleanupDirectX()
{
    CleanupRenderTarget();
    if (m_swapChain)
    {
        m_swapChain->Release();
        m_swapChain = nullptr;
    }
    if (m_context)
    {
        m_context->Release();
        m_context = nullptr;
    }
    if (m_device)
    {
        m_device->Release();
        m_device = nullptr;
    }
}

void Application::HandleDroppedFile(const std::string &filepath)
{
    if (IsImageExtension(filepath))
    {
        m_activeTab = Tab::Exif;
        m_exifView.LoadFile(filepath, m_statusText);
    }
    else
    {
        m_activeTab = Tab::FileAnalyzer;
        m_fileAnalyzerView.LoadFile(filepath, m_statusText);
    }
}

int Application::Run()
{
    if (!InitWindow() || !InitDirectX())
    {
        return 1;
    }

    ShowWindow(m_hwnd, SW_SHOWDEFAULT);
    UpdateWindow(m_hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    io.IniFilename = nullptr;
    LoadFontSet(io);

    ui::Theme::Apply();

    ImGui_ImplWin32_Init(m_hwnd);
    ImGui_ImplDX11_Init(m_device, m_context);

    m_textureCache = std::make_unique<ui::TextureCache>(m_device);
    m_platforms = core::ConfigLoader::LoadPlatforms("data/platforms.json");
    m_statusText = "Ready - " + std::to_string(m_platforms.size()) + " direct platform detectors active.";

    bool done = false;
    while (!done)
    {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
            {
                done = true;
            }
        }
        if (done)
            break;

        RenderFrame();
    }

    return 0;
}

void Application::RenderFrame()
{
    if (m_pivot.pending)
    {
        m_activeTab = static_cast<Tab>(m_pivot.target_tab);
        if (m_pivot.target_tab == 6)
        {
            m_pivot.pending = false;
            if (!m_isScanning.load() && !m_pivot.payload.empty())
            {
                m_sslView.SetTargetAndScan(m_pivot.payload, m_isScanning, m_statusText);
            }
        }
    }

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    const ImGuiViewport *viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::Begin("MainRoot", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);

    float now = static_cast<float>(ImGui::GetTime());
    bool busy = m_isScanning.load();
    DrawAmbientBackdrop(ImGui::GetWindowDrawList(), viewport->WorkPos, viewport->WorkSize, now, busy);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.038f, 0.054f, 0.088f, 0.96f));
    ImGui::BeginChild("Sidebar", ImVec2(276.0f, -44.0f), true);
    {
        ImVec2 sMin = ImGui::GetWindowPos();
        ImVec2 sMax(sMin.x + ImGui::GetWindowWidth(), sMin.y + ImGui::GetWindowHeight());
        ui::Theme::DrawGlassRim(ImGui::GetWindowDrawList(), sMin, sMax, 14.0f);
    }

    ui::Components::BrandHeader();
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::PushFont(ui::Theme::MonoFont());
    ImGui::TextDisabled("RECONNAISSANCE");
    ImGui::PopFont();
    ImGui::Dummy(ImVec2(0.0f, 2.0f));

    const float navH = 40.0f;
    std::string platCountTag = std::to_string(m_platforms.size());
    if (ui::Components::NavButton("Username Scan", platCountTag.c_str(), m_activeTab == Tab::Username, navH))
    {
        m_activeTab = Tab::Username;
    }
    if (ui::Components::NavButton("Email Breach Audit", "12 SRC", m_activeTab == Tab::Email, navH))
    {
        m_activeTab = Tab::Email;
    }
    if (ui::Components::NavButton("Domain & DNS Recon", "5 SRC", m_activeTab == Tab::Domain, navH))
    {
        m_activeTab = Tab::Domain;
    }
    if (ui::Components::NavButton("IP & Server Recon", "SHODAN", m_activeTab == Tab::IpRecon, navH))
    {
        m_activeTab = Tab::IpRecon;
    }
    if (ui::Components::NavButton("SSL & HTTP Headers", "TLS", m_activeTab == Tab::Ssl, navH))
    {
        m_activeTab = Tab::Ssl;
    }

    ImGui::Spacing();
    ImGui::PushFont(ui::Theme::MonoFont());
    ImGui::TextDisabled("PRIVACY & FORENSICS");
    ImGui::PopFont();
    ImGui::Dummy(ImVec2(0.0f, 2.0f));

    if (ui::Components::NavButton("Password Exposure", "HIBP", m_activeTab == Tab::Password, navH))
    {
        m_activeTab = Tab::Password;
    }
    if (ui::Components::NavButton("EXIF Privacy Tool", "IMAGE", m_activeTab == Tab::Exif, navH))
    {
        m_activeTab = Tab::Exif;
    }
    if (ui::Components::NavButton("File Hash & Entropy", "SHA256", m_activeTab == Tab::FileAnalyzer, navH))
    {
        m_activeTab = Tab::FileAnalyzer;
    }

    float bottomSpace = ImGui::GetContentRegionAvail().y - 88.0f;
    if (bottomSpace > 0.0f)
    {
        ImGui::Dummy(ImVec2(0.0f, bottomSpace));
    }
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextDisabled("Enjoying Footprint Audit?");
    if (ui::Components::KofiButton("Support on Ko-fi", 40.0f))
    {
        ShellExecuteA(nullptr, "open", "https://ko-fi.com/drjhn291", nullptr, nullptr, SW_SHOWNORMAL);
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::SameLine(0.0f, 14.0f);

    ImGui::BeginChild("ContentArea", ImVec2(0.0f, -44.0f), false);

    const char *tabNames[] = {"Username Intelligence",  "Email Breach Audit",       "Password Exposure Audit",
                              "Domain & DNS Recon",     "IP & Server Recon",        "EXIF Metadata Privacy",
                              "SSL/TLS & HTTP Headers", "File Hash & Entropy Audit"};
    const char *tabCodes[] = {"MOD-01 | OSINT",  "MOD-02 | BREACH", "MOD-03 | K-ANON",   "MOD-04 | DNS/CT",
                              "MOD-05 | SHODAN", "MOD-06 | EXIF",   "MOD-07 | TLS/HTTP", "MOD-08 | CNG/HASH"};
    int tabIdx = static_cast<int>(m_activeTab);
    ui::Components::TopBar(tabNames[tabIdx], tabCodes[tabIdx], busy);
    ImGui::Dummy(ImVec2(0.0f, 6.0f));

    if (m_activeTab == Tab::Username)
    {
        m_usernameView.Render(m_platforms, *m_textureCache, m_isScanning, m_statusText, m_pivot);
    }
    else if (m_activeTab == Tab::Email)
    {
        m_emailView.Render(m_isScanning, m_statusText, m_pivot);
    }
    else if (m_activeTab == Tab::Password)
    {
        m_passwordView.Render(m_isScanning, m_statusText);
    }
    else if (m_activeTab == Tab::Domain)
    {
        m_domainView.Render(m_isScanning, m_statusText, m_pivot);
    }
    else if (m_activeTab == Tab::IpRecon)
    {
        m_ipReconView.Render(m_isScanning, m_statusText, m_pivot);
    }
    else if (m_activeTab == Tab::Exif)
    {
        m_exifView.Render(m_device, m_statusText);
    }
    else if (m_activeTab == Tab::Ssl)
    {
        m_sslView.Render(m_isScanning, m_statusText);
    }
    else if (m_activeTab == Tab::FileAnalyzer)
    {
        m_fileAnalyzerView.Render(m_statusText);
    }
    ImGui::EndChild();

    ImGui::Dummy(ImVec2(0.0f, 2.0f));
    ImVec2 fAvail = ImGui::GetContentRegionAvail();
    ImVec2 fMin = ImGui::GetCursorScreenPos();
    const float footerH = 32.0f;
    ImVec2 fMax(fMin.x + fAvail.x, fMin.y + footerH);

    ImDrawList *dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(fMin, fMax, IM_COL32(10, 15, 25, 240), 9.0f);
    dl->AddRect(fMin, fMax, IM_COL32(30, 44, 68, 175), 9.0f, 0, 1.0f);

    ImU32 dotColor = busy ? IM_COL32(251, 191, 36, 255) : IM_COL32(52, 211, 153, 255);
    float ringScale = std::fmod(now * (busy ? 1.8f : 0.7f), 1.0f);
    ImU32 ringColor = busy ? IM_COL32(251, 191, 36, static_cast<int>(160 * (1.0f - ringScale)))
                           : IM_COL32(52, 211, 153, static_cast<int>(120 * (1.0f - ringScale)));

    ImVec2 ledCenter(fMin.x + 16.0f, fMin.y + footerH * 0.5f);
    dl->AddCircle(ledCenter, 4.0f + 6.5f * ringScale, ringColor, 20, 1.2f);
    dl->AddCircleFilled(ledCenter, 4.0f, dotColor);

    ImVec2 stSize = ImGui::CalcTextSize(m_statusText.c_str());
    dl->AddText(ImVec2(fMin.x + 30.0f, fMin.y + (footerH - stSize.y) * 0.5f), IM_COL32(168, 186, 212, 240),
                m_statusText.c_str());

    if (busy)
    {
        float barW = 140.0f;
        float barH = 4.0f;
        ImVec2 b1(fMax.x - barW - 14.0f, fMin.y + (footerH - barH) * 0.5f);
        ImVec2 b2(b1.x + barW, b1.y + barH);
        dl->AddRectFilled(b1, b2, IM_COL32(28, 42, 66, 255), 2.0f);

        float phase = std::fmod(now * 1.1f, 1.0f);
        float segW = 46.0f;
        float sx1 = std::max(b1.x, b1.x + (barW + segW) * phase - segW);
        float sx2 = std::min(b2.x, b1.x + (barW + segW) * phase);
        if (sx2 > sx1)
        {
            dl->AddRectFilled(ImVec2(sx1, b1.y), ImVec2(sx2, b2.y), IM_COL32(34, 211, 238, 255), 2.0f);
        }
    }
    else
    {
        ImGui::PushFont(ui::Theme::MonoFont());
        const char *verTxt = "NATIVE C++20 | DX11";
        ImVec2 vSz = ImGui::CalcTextSize(verTxt);
        dl->AddText(ImVec2(fMax.x - vSz.x - 14.0f, fMin.y + (footerH - vSz.y) * 0.5f), IM_COL32(95, 115, 148, 210),
                    verTxt);
        ImGui::PopFont();
    }

    ImGui::Dummy(ImVec2(fAvail.x, footerH));
    ImGui::End();

    ImGui::Render();
    const float clearColor[4] = {0.024f, 0.035f, 0.058f, 1.00f};
    m_context->OMSetRenderTargets(1, &m_mainRenderTargetView, nullptr);
    m_context->ClearRenderTargetView(m_mainRenderTargetView, clearColor);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

    m_swapChain->Present(1, 0);
}

LRESULT WINAPI Application::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_DROPFILES:
        if (g_appInstance)
        {
            HDROP hDrop = reinterpret_cast<HDROP>(wParam);
            char pathBuf[MAX_PATH]{};
            if (DragQueryFileA(hDrop, 0, pathBuf, MAX_PATH) > 0)
            {
                g_appInstance->HandleDroppedFile(pathBuf);
            }
            DragFinish(hDrop);
        }
        return 0;
    case WM_SIZE:
        if (g_appInstance && g_appInstance->m_device && wParam != SIZE_MINIMIZED)
        {
            g_appInstance->CleanupRenderTarget();
            g_appInstance->m_swapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam),
                                                      DXGI_FORMAT_UNKNOWN, 0);
            g_appInstance->CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

} // namespace app