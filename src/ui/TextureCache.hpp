#pragma once
#include <d3d11.h>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace ui
{

class TextureCache
{
  public:
    explicit TextureCache(ID3D11Device *device);
    ~TextureCache();

    ID3D11ShaderResourceView *GetDomainIcon(const std::string &domain);

  private:
    ID3D11Device *m_device;
    std::mutex m_mutex;
    std::unordered_map<std::string, ID3D11ShaderResourceView *> m_cache;
    std::unordered_set<std::string> m_pending;

    ID3D11ShaderResourceView *CreateTextureFromBytes(const unsigned char *data, size_t size);
};

} // namespace ui