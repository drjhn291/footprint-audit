#pragma once

#include "imgui.h"

namespace ui
{

class Theme
{
  public:
    static void Apply();

    static void SetFonts(ImFont *regular, ImFont *bold, ImFont *title, ImFont *mono);
    static ImFont *RegularFont();
    static ImFont *BoldFont();
    static ImFont *TitleFont();
    static ImFont *MonoFont();

    // Dibuja un reflejo sutil de cristal en el borde superior de tarjetas y paneles
    static void DrawGlassRim(ImDrawList *dl, const ImVec2 &pMin, const ImVec2 &pMax, float rounding = 14.0f,
                             ImU32 rimColor = IM_COL32(180, 215, 255, 28));
};

} // namespace ui