#include "TextureCache.hpp"
#include "../network/HttpClient.hpp"
#include <thread>
#include <vector>
#include <wincodec.h>

namespace ui
{

TextureCache::TextureCache(ID3D11Device *device) : m_device(device) {}

TextureCache::~TextureCache()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto &[_, srv] : m_cache)
    {
        if (srv)
            srv->Release();
    }
}

ID3D11ShaderResourceView *TextureCache::CreateTextureFromBytes(const unsigned char *data, size_t size)
{
    if (!m_device || !data || size == 0)
        return nullptr;

    IWICImagingFactory *factory = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory))))
    {
        return nullptr;
    }

    IWICStream *stream = nullptr;
    IWICBitmapDecoder *decoder = nullptr;
    IWICBitmapFrameDecode *frame = nullptr;
    IWICFormatConverter *converter = nullptr;
    ID3D11ShaderResourceView *srv = nullptr;

    if (SUCCEEDED(factory->CreateStream(&stream)) &&
        SUCCEEDED(stream->InitializeFromMemory(const_cast<BYTE *>(data), (DWORD)size)) &&
        SUCCEEDED(factory->CreateDecoderFromStream(stream, nullptr, WICDecodeMetadataCacheOnLoad, &decoder)) &&
        SUCCEEDED(decoder->GetFrame(0, &frame)) && SUCCEEDED(factory->CreateFormatConverter(&converter)) &&
        SUCCEEDED(converter->Initialize(frame, GUID_WICPixelFormat32bppRGBA, WICBitmapDitherTypeNone, nullptr, 0.0,
                                        WICBitmapPaletteTypeCustom)))
    {

        UINT width = 0, height = 0;
        converter->GetSize(&width, &height);
        if (width > 0 && height > 0)
        {
            std::vector<BYTE> pixels(width * height * 4);
            if (SUCCEEDED(converter->CopyPixels(nullptr, width * 4, (UINT)pixels.size(), pixels.data())))
            {
                D3D11_TEXTURE2D_DESC desc{};
                desc.Width = width;
                desc.Height = height;
                desc.MipLevels = 1;
                desc.ArraySize = 1;
                desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
                desc.SampleDesc.Count = 1;
                desc.Usage = D3D11_USAGE_DEFAULT;
                desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

                D3D11_SUBRESOURCE_DATA sub{};
                sub.pSysMem = pixels.data();
                sub.SysMemPitch = width * 4;

                ID3D11Texture2D *tex = nullptr;
                if (SUCCEEDED(m_device->CreateTexture2D(&desc, &sub, &tex)))
                {
                    m_device->CreateShaderResourceView(tex, nullptr, &srv);
                    tex->Release();
                }
            }
        }
    }

    if (converter)
        converter->Release();
    if (frame)
        frame->Release();
    if (decoder)
        decoder->Release();
    if (stream)
        stream->Release();
    factory->Release();
    return srv;
}

ID3D11ShaderResourceView *TextureCache::GetDomainIcon(const std::string &domain)
{
    if (domain.empty())
        return nullptr;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_cache.find(domain);
        if (it != m_cache.end())
            return it->second;
        if (m_pending.count(domain))
            return nullptr;
        m_pending.insert(domain);
    }

    std::thread([this, domain]() {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        std::string url = "https://www.google.com/s2/favicons?domain=" + domain + "&sz=64";
        auto raw = network::HttpClient::GetBytes(url, 6000);
        ID3D11ShaderResourceView *srv = CreateTextureFromBytes(raw.data(), raw.size());
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_cache[domain] = srv;
            m_pending.erase(domain);
        }
        CoUninitialize();
    }).detach();

    return nullptr;
}

} // namespace ui