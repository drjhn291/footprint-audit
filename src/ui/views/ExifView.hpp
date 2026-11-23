#pragma once

#include "../../core/ExifHandler.hpp"
#include <d3d11.h>
#include <string>

namespace ui::views
{

class ExifView
{
  public:
    ~ExifView();

    void Render(ID3D11Device *device, std::string &status_text);
    void LoadFile(const std::string &filepath, std::string &status_text);

  private:
    void ReleasePreview();
    void EnsurePreviewTexture(ID3D11Device *device);

    core::ExifInspectResult m_result;
    std::string m_cleanMessage;

    ID3D11ShaderResourceView *m_previewSrv = nullptr;
    int m_previewW = 0;
    int m_previewH = 0;
    bool m_previewDirty = false;
};

} // namespace ui::views