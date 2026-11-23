#include "Theme.hpp"

namespace ui
{

namespace
{
ImFont *g_regularFont = nullptr;
ImFont *g_boldFont = nullptr;
ImFont *g_titleFont = nullptr;
ImFont *g_monoFont = nullptr;
} // namespace

void Theme::SetFonts(ImFont *regular, ImFont *bold, ImFont *title, ImFont *mono)
{
    g_regularFont = regular;
    g_boldFont = bold;
    g_titleFont = title;
    g_monoFont = mono;
}

ImFont *Theme::RegularFont()
{
    return g_regularFont ? g_regularFont : ImGui::GetFont();
}

ImFont *Theme::BoldFont()
{
    return g_boldFont ? g_boldFont : RegularFont();
}

ImFont *Theme::TitleFont()
{
    return g_titleFont ? g_titleFont : BoldFont();
}

ImFont *Theme::MonoFont()
{
    return g_monoFont ? g_monoFont : RegularFont();
}

void Theme::DrawGlassRim(ImDrawList *dl, const ImVec2 &pMin, const ImVec2 &pMax, float rounding, ImU32 rimColor)
{
    float inset = rounding * 0.65f;
    if (pMax.x - pMin.x > inset * 2.0f)
    {
        dl->AddLine(ImVec2(pMin.x + inset, pMin.y + 1.0f), ImVec2(pMax.x - inset, pMin.y + 1.0f), rimColor, 1.0f);
    }
}

void Theme::Apply()
{
    ImGuiStyle &style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    style.ChildRounding = 14.0f;
    style.FrameRounding = 9.0f;
    style.PopupRounding = 12.0f;
    style.ScrollbarRounding = 8.0f;
    style.GrabRounding = 8.0f;
    style.TabRounding = 9.0f;

    style.WindowPadding = ImVec2(20.0f, 18.0f);
    style.FramePadding = ImVec2(14.0f, 10.0f);
    style.CellPadding = ImVec2(14.0f, 10.0f);
    style.ItemSpacing = ImVec2(12.0f, 11.0f);
    style.ItemInnerSpacing = ImVec2(8.0f, 6.0f);
    style.ScrollbarSize = 7.0f;
    style.ChildBorderSize = 1.0f;
    style.FrameBorderSize = 1.0f;
    style.PopupBorderSize = 1.0f;

    ImVec4 *colors = style.Colors;
    colors[ImGuiCol_Text] = ImVec4(0.95f, 0.97f, 1.00f, 1.00f);
    colors[ImGuiCol_TextDisabled] = ImVec4(0.47f, 0.56f, 0.70f, 1.00f);

    colors[ImGuiCol_WindowBg] = ImVec4(0.024f, 0.035f, 0.058f, 1.00f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.047f, 0.067f, 0.108f, 0.94f);
    colors[ImGuiCol_PopupBg] = ImVec4(0.062f, 0.086f, 0.138f, 0.98f);

    colors[ImGuiCol_Border] = ImVec4(0.13f, 0.19f, 0.30f, 0.82f);
    colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);

    colors[ImGuiCol_FrameBg] = ImVec4(0.068f, 0.095f, 0.150f, 0.98f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.095f, 0.132f, 0.205f, 1.00f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.118f, 0.165f, 0.255f, 1.00f);

    colors[ImGuiCol_Button] = ImVec4(0.14f, 0.45f, 0.96f, 1.00f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.20f, 0.54f, 1.00f, 1.00f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.11f, 0.37f, 0.84f, 1.00f);

    colors[ImGuiCol_CheckMark] = ImVec4(0.13f, 0.85f, 0.95f, 1.00f);
    colors[ImGuiCol_SliderGrab] = ImVec4(0.18f, 0.52f, 0.98f, 1.00f);
    colors[ImGuiCol_SliderGrabActive] = ImVec4(0.26f, 0.62f, 1.00f, 1.00f);

    colors[ImGuiCol_Header] = ImVec4(0.11f, 0.16f, 0.25f, 1.00f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.14f, 0.72f, 0.92f, 0.16f);
    colors[ImGuiCol_HeaderActive] = ImVec4(0.14f, 0.72f, 0.92f, 0.28f);

    colors[ImGuiCol_Separator] = ImVec4(0.14f, 0.20f, 0.32f, 0.65f);
    colors[ImGuiCol_PlotHistogram] = ImVec4(0.13f, 0.85f, 0.95f, 1.00f);

    colors[ImGuiCol_ScrollbarBg] = ImVec4(0.03f, 0.045f, 0.075f, 0.40f);
    colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.16f, 0.24f, 0.36f, 0.90f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.22f, 0.34f, 0.50f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.14f, 0.75f, 0.92f, 1.00f);

    colors[ImGuiCol_TableHeaderBg] = ImVec4(0.072f, 0.102f, 0.162f, 1.00f);
    colors[ImGuiCol_TableBorderStrong] = ImVec4(0.13f, 0.19f, 0.30f, 0.85f);
    colors[ImGuiCol_TableBorderLight] = ImVec4(0.11f, 0.16f, 0.25f, 0.45f);
    colors[ImGuiCol_TableRowBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt] = ImVec4(0.16f, 0.45f, 0.92f, 0.035f);
}

} // namespace ui