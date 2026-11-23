#pragma once

#include "../core/Models.hpp"
#include "../ui/TextureCache.hpp"
#include "../ui/views/DomainView.hpp"
#include "../ui/views/EmailView.hpp"
#include "../ui/views/ExifView.hpp"
#include "../ui/views/FileAnalyzerView.hpp"
#include "../ui/views/IpReconView.hpp"
#include "../ui/views/PasswordView.hpp"
#include "../ui/views/SslView.hpp"
#include "../ui/views/UsernameView.hpp"
#include <atomic>
#include <d3d11.h>
#include <memory>
#include <string>
#include <vector>
#include <windows.h>

namespace app
{

class Application
{
  public:
    explicit Application(HINSTANCE hInstance);
    ~Application();

    int Run();

  private:
    enum class Tab
    {
        Username = 0,
        Email = 1,
        Password = 2,
        Domain = 3,
        IpRecon = 4,
        Exif = 5,
        Ssl = 6,
        FileAnalyzer = 7
    };

    bool InitWindow();
    bool InitDirectX();
    void CreateRenderTarget();
    void CleanupRenderTarget();
    void CleanupDirectX();
    void RenderFrame();
    void HandleDroppedFile(const std::string &filepath);

    static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

    HINSTANCE m_hInstance = nullptr;
    HWND m_hwnd = nullptr;
    ID3D11Device *m_device = nullptr;
    ID3D11DeviceContext *m_context = nullptr;
    IDXGISwapChain *m_swapChain = nullptr;
    ID3D11RenderTargetView *m_mainRenderTargetView = nullptr;

    std::unique_ptr<ui::TextureCache> m_textureCache;
    std::vector<core::PlatformRule> m_platforms;

    Tab m_activeTab = Tab::Username;
    std::atomic<bool> m_isScanning{false};
    std::string m_statusText;
    core::PivotAction m_pivot;

    ui::views::UsernameView m_usernameView;
    ui::views::EmailView m_emailView;
    ui::views::PasswordView m_passwordView;
    ui::views::DomainView m_domainView;
    ui::views::IpReconView m_ipReconView;
    ui::views::ExifView m_exifView;
    ui::views::SslView m_sslView;
    ui::views::FileAnalyzerView m_fileAnalyzerView;
};

} // namespace app