#pragma once

#include "../core/Models.hpp"
#include "TextureCache.hpp"
#include "imgui.h"
#include <string>

namespace ui
{

class Components
{
  public:
    static void BrandHeader();
    static void TopBar(const char *moduleName, const char *moduleCode, bool isScanning);
    static bool NavButton(const char *label, const char *tag, bool active, float height = 44.0f);
    static bool KofiButton(const char *label, float height = 42.0f);
    static void SectionHeader(const char *title, const char *subtitle);
    static void MetricCard(const char *id, const char *label, const char *value, const ImVec4 &accent, float width);
    static void StatusBadge(const char *text, const ImVec4 &color);
    static void EmptyState(const char *iconHint, const char *title, const char *subtitle);
    static bool CopyButton(const char *id, const std::string &text);
    static bool PlatformCard(const core::UsernameFinding &finding, TextureCache &icons, float width, float height);
};

} // namespace ui