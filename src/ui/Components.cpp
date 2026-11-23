#include "Components.hpp"
#include "Theme.hpp"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <unordered_map>

namespace ui
{

namespace
{

float AnimateValue(ImGuiID id, float target, float speed = 12.0f)
{
    static std::unordered_map<ImGuiID, float> state;
    float &current = state[id];
    float dt = std::min(ImGui::GetIO().DeltaTime, 0.05f);
    current += (target - current) * std::min(1.0f, dt * speed);
    if (std::fabs(target - current) < 0.001f)
        current = target;
    return current;
}

bool ContainsICase(const char *haystack, const char *needle)
{
    if (!haystack || !needle)
        return false;
    std::string h(haystack);
    std::string n(needle);
    std::transform(h.begin(), h.end(), h.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return h.find(n) != std::string::npos;
}

// Iconografia vectorial anti-aliasing dibujada por codigo
void DrawModuleVectorIcon(ImDrawList *dl, ImVec2 c, const char *hint, ImU32 col)
{
    if (ContainsICase(hint, "user"))
    {
        // Silueta de usuario + anillo de escaneo
        dl->AddCircle(ImVec2(c.x, c.y - 2.6f), 3.1f, col, 18, 1.5f);
        dl->PathClear();
        dl->PathArcTo(ImVec2(c.x, c.y + 6.8f), 5.6f, 3.45f, 5.97f, 14);
        dl->PathStroke(col, 0, 1.5f);
    }
    else if (ContainsICase(hint, "email") || ContainsICase(hint, "breach") || ContainsICase(hint, "spf") ||
             ContainsICase(hint, "dmarc"))
    {
        // Sobre minimalista
        ImVec2 p1(c.x - 6.8f, c.y - 4.6f);
        ImVec2 p2(c.x + 6.8f, c.y + 4.6f);
        dl->AddRect(p1, p2, col, 2.2f, 0, 1.45f);
        dl->AddLine(ImVec2(p1.x + 1.0f, p1.y + 1.0f), ImVec2(c.x, c.y + 1.0f), col, 1.45f);
        dl->AddLine(ImVec2(p2.x - 1.0f, p1.y + 1.0f), ImVec2(c.x, c.y + 1.0f), col, 1.45f);
    }
    else if (ContainsICase(hint, "pass") || ContainsICase(hint, "hibp"))
    {
        // Candado de seguridad
        dl->AddRect(ImVec2(c.x - 5.5f, c.y - 1.0f), ImVec2(c.x + 5.5f, c.y + 6.5f), col, 2.2f, 0, 1.5f);
        dl->PathClear();
        dl->PathArcTo(ImVec2(c.x, c.y - 1.2f), 3.4f, 3.14159f, 6.28318f, 14);
        dl->PathStroke(col, 0, 1.5f);
        dl->AddCircleFilled(ImVec2(c.x, c.y + 2.6f), 1.3f, col);
    }
    else if (ContainsICase(hint, "domain") || ContainsICase(hint, "dns") || ContainsICase(hint, "sub"))
    {
        // Globo terraqueo / red
        dl->AddCircle(c, 6.6f, col, 22, 1.45f);
        dl->AddLine(ImVec2(c.x - 6.4f, c.y), ImVec2(c.x + 6.4f, c.y), col, 1.2f);
        dl->AddBezierCubic(ImVec2(c.x, c.y - 6.4f), ImVec2(c.x - 3.6f, c.y - 2.0f), ImVec2(c.x - 3.6f, c.y + 2.0f),
                           ImVec2(c.x, c.y + 6.4f), col, 1.2f);
        dl->AddBezierCubic(ImVec2(c.x, c.y - 6.4f), ImVec2(c.x + 3.6f, c.y - 2.0f), ImVec2(c.x + 3.6f, c.y + 2.0f),
                           ImVec2(c.x, c.y + 6.4f), col, 1.2f);
    }
    else if (ContainsICase(hint, "ip") || ContainsICase(hint, "server") || ContainsICase(hint, "port") ||
             ContainsICase(hint, "vuln"))
    {
        // Nodos de servidor / rack
        dl->AddRect(ImVec2(c.x - 6.5f, c.y - 5.8f), ImVec2(c.x + 6.5f, c.y - 1.0f), col, 1.8f, 0, 1.4f);
        dl->AddRect(ImVec2(c.x - 6.5f, c.y + 1.0f), ImVec2(c.x + 6.5f, c.y + 5.8f), col, 1.8f, 0, 1.4f);
        dl->AddCircleFilled(ImVec2(c.x - 3.8f, c.y - 3.4f), 1.1f, col);
        dl->AddCircleFilled(ImVec2(c.x - 3.8f, c.y + 3.4f), 1.1f, col);
    }
    else if (ContainsICase(hint, "exif") || ContainsICase(hint, "image") || ContainsICase(hint, "gps") ||
             ContainsICase(hint, "tag"))
    {
        // Lente de camara / visor de imagen
        dl->AddRect(ImVec2(c.x - 6.8f, c.y - 5.2f), ImVec2(c.x + 6.8f, c.y + 5.2f), col, 2.2f, 0, 1.45f);
        dl->AddCircle(c, 2.7f, col, 16, 1.4f);
        dl->AddCircleFilled(ImVec2(c.x + 4.2f, c.y - 2.8f), 1.0f, col);
    }
    else
    {
        // Pulso / radar generico
        dl->AddCircle(c, 6.2f, col, 20, 1.4f);
        dl->AddCircleFilled(c, 2.2f, col);
    }
}

} // namespace

void Components::BrandHeader()
{
    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float t = static_cast<float>(ImGui::GetTime());

    ImVec2 center(p.x + 21.0f, p.y + 22.0f);
    float pulse = 0.5f + 0.5f * std::sin(t * 2.4f);

    // Halo exterior y anillos de radar
    dl->AddCircleFilled(center, 22.0f, IM_COL32(28, 135, 235, static_cast<int>(22 + 16 * pulse)), 32);
    dl->AddCircle(center, 19.0f, IM_COL32(56, 189, 248, 190), 36, 1.5f);
    dl->AddCircle(center, 12.0f, IM_COL32(34, 211, 238, 115), 28, 1.0f);

    // Marcas cardinales en el radar
    dl->AddLine(ImVec2(center.x - 19.0f, center.y), ImVec2(center.x - 15.0f, center.y), IM_COL32(56, 189, 248, 140),
                1.0f);
    dl->AddLine(ImVec2(center.x + 15.0f, center.y), ImVec2(center.x + 19.0f, center.y), IM_COL32(56, 189, 248, 140),
                1.0f);
    dl->AddLine(ImVec2(center.x, center.y - 19.0f), ImVec2(center.x, center.y - 15.0f), IM_COL32(56, 189, 248, 140),
                1.0f);
    dl->AddLine(ImVec2(center.x, center.y + 15.0f), ImVec2(center.x, center.y + 19.0f), IM_COL32(56, 189, 248, 140),
                1.0f);

    // Barrido luminoso
    float sweep = t * 2.1f;
    dl->PathClear();
    dl->PathLineTo(center);
    dl->PathArcTo(center, 18.0f, sweep - 0.90f, sweep, 16);
    dl->PathFillConvex(IM_COL32(34, 211, 238, 60));

    ImVec2 tip(center.x + std::cos(sweep) * 18.0f, center.y + std::sin(sweep) * 18.0f);
    dl->AddLine(center, tip, IM_COL32(140, 246, 255, 240), 1.6f);
    dl->AddCircleFilled(center, 3.4f, IM_COL32(34, 211, 238, 255));

    ImGui::Dummy(ImVec2(48.0f, 44.0f));
    ImGui::SameLine(0.0f, 11.0f);
    ImGui::BeginGroup();
    ImGui::PushFont(Theme::BoldFont());
    ImGui::TextColored(ImVec4(0.97f, 0.98f, 1.00f, 1.00f), "FOOTPRINT AUDIT");
    ImGui::PopFont();
    ImGui::TextColored(ImVec4(0.20f, 0.84f, 0.95f, 0.95f), "OSINT & Privacy Suite");
    ImGui::EndGroup();
}

void Components::TopBar(const char *moduleName, const char *moduleCode, bool isScanning)
{
    ImVec2 avail = ImGui::GetContentRegionAvail();
    ImVec2 pMin = ImGui::GetCursorScreenPos();
    const float barH = 38.0f;
    ImVec2 pMax(pMin.x + avail.x, pMin.y + barH);

    ImDrawList *dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(pMin, pMax, IM_COL32(11, 16, 27, 235), 11.0f);
    dl->AddRect(pMin, pMax, IM_COL32(32, 46, 72, 180), 11.0f, 0, 1.0f);
    Theme::DrawGlassRim(dl, pMin, pMax, 11.0f);

    // Breadcrumb izquierdo
    ImGui::PushFont(Theme::MonoFont());
    const char *rootTxt = "WORKSPACE";
    ImVec2 rootSz = ImGui::CalcTextSize(rootTxt);
    dl->AddText(ImVec2(pMin.x + 14.0f, pMin.y + (barH - rootSz.y) * 0.5f), IM_COL32(105, 125, 158, 220), rootTxt);
    dl->AddText(ImVec2(pMin.x + 14.0f + rootSz.x + 10.0f, pMin.y + (barH - rootSz.y) * 0.5f),
                IM_COL32(65, 86, 118, 200), "/");
    ImGui::PopFont();

    ImGui::PushFont(Theme::BoldFont());
    ImVec2 modSz = ImGui::CalcTextSize(moduleName);
    dl->AddText(ImVec2(pMin.x + 14.0f + rootSz.x + 26.0f, pMin.y + (barH - modSz.y) * 0.5f),
                IM_COL32(238, 245, 255, 255), moduleName);
    ImGui::PopFont();

    // Pildora derecha de estado del motor
    ImGui::PushFont(Theme::MonoFont());
    const char *stateLabel = isScanning ? "SCANNING ACTIVE" : moduleCode;
    ImVec2 stSz = ImGui::CalcTextSize(stateLabel);
    float pillW = stSz.x + 28.0f;
    float pillH = 22.0f;
    ImVec2 b1(pMax.x - pillW - 10.0f, pMin.y + (barH - pillH) * 0.5f);
    ImVec2 b2(b1.x + pillW, b1.y + pillH);

    ImU32 pillBg = isScanning ? IM_COL32(245, 158, 11, 34) : IM_COL32(34, 211, 238, 24);
    ImU32 pillBorder = isScanning ? IM_COL32(245, 158, 11, 130) : IM_COL32(34, 211, 238, 95);
    ImU32 dotCol = isScanning ? IM_COL32(251, 191, 36, 255) : IM_COL32(52, 211, 153, 255);
    ImU32 txtCol = isScanning ? IM_COL32(253, 224, 130, 255) : IM_COL32(145, 238, 255, 240);

    dl->AddRectFilled(b1, b2, pillBg, 7.0f);
    dl->AddRect(b1, b2, pillBorder, 7.0f, 0, 1.0f);
    dl->AddCircleFilled(ImVec2(b1.x + 10.0f, b1.y + pillH * 0.5f), 3.2f, dotCol);
    dl->AddText(ImVec2(b1.x + 18.0f, b1.y + (pillH - stSz.y) * 0.5f), txtCol, stateLabel);
    ImGui::PopFont();

    ImGui::Dummy(ImVec2(avail.x, barH));
}

bool Components::NavButton(const char *label, const char *tag, bool active, float height)
{
    ImGui::PushID(label);
    ImGuiID id = ImGui::GetID("nav_btn");

    ImVec2 avail = ImGui::GetContentRegionAvail();
    ImVec2 pMin = ImGui::GetCursorScreenPos();
    ImVec2 pMax(pMin.x + avail.x, pMin.y + height);

    bool clicked = ImGui::InvisibleButton("##nav_hit", ImVec2(avail.x, height));
    bool hovered = ImGui::IsItemHovered();
    if (hovered)
    {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    }

    float anim = AnimateValue(id, active ? 1.0f : (hovered ? 0.48f : 0.0f), 13.0f);
    ImDrawList *dl = ImGui::GetWindowDrawList();

    if (anim > 0.01f)
    {
        ImU32 bgLeft = IM_COL32(static_cast<int>(15 + 16 * anim), static_cast<int>(22 + 44 * anim),
                                static_cast<int>(36 + 78 * anim), static_cast<int>(110 + 135 * anim));
        ImU32 bgRight = IM_COL32(static_cast<int>(13 + 8 * anim), static_cast<int>(19 + 22 * anim),
                                 static_cast<int>(31 + 42 * anim), static_cast<int>(90 + 125 * anim));
        dl->AddRectFilledMultiColor(pMin, pMax, bgLeft, bgRight, bgRight, bgLeft);

        ImU32 borderCol = IM_COL32(34, 211, 238, static_cast<int>(25 + 145 * anim));
        dl->AddRect(pMin, pMax, borderCol, 10.0f, 0, active ? 1.25f : 1.0f);

        if (active)
        {
            Theme::DrawGlassRim(dl, pMin, pMax, 10.0f, IM_COL32(140, 242, 255, 55));
        }

        float barH = (height - 18.0f) * std::min(1.0f, anim * 1.15f);
        float barY = pMin.y + (height - barH) * 0.5f;
        dl->AddRectFilled(ImVec2(pMin.x + 2.5f, barY), ImVec2(pMin.x + 5.5f, barY + barH),
                          IM_COL32(34, 211, 238, static_cast<int>(255 * anim)), 3.0f);
    }

    // Icono vectorial izquierdo
    ImU32 iconCol =
        active ? IM_COL32(56, 225, 248, 255) : (hovered ? IM_COL32(195, 218, 248, 245) : IM_COL32(120, 142, 174, 220));
    DrawModuleVectorIcon(dl, ImVec2(pMin.x + 22.0f + 2.0f * anim, pMin.y + height * 0.5f), label, iconCol);

    // Texto de pestana
    if (active)
        ImGui::PushFont(Theme::BoldFont());
    float textOffsetX = 39.0f + 2.5f * anim;
    ImVec2 textSize = ImGui::CalcTextSize(label);
    ImU32 textCol =
        active ? IM_COL32(250, 253, 255, 255) : (hovered ? IM_COL32(230, 240, 255, 250) : IM_COL32(176, 192, 216, 235));
    dl->AddText(ImVec2(pMin.x + textOffsetX, pMin.y + (height - textSize.y) * 0.5f), textCol, label);
    if (active)
        ImGui::PopFont();

    // Pildora derecha
    if (tag && tag[0] != '\0')
    {
        ImGui::PushFont(Theme::MonoFont());
        ImVec2 tagSize = ImGui::CalcTextSize(tag);
        float badgeW = tagSize.x + 12.0f;
        float badgeH = 19.0f;
        ImVec2 b1(pMax.x - badgeW - 9.0f, pMin.y + (height - badgeH) * 0.5f);
        ImVec2 b2(b1.x + badgeW, b1.y + badgeH);
        ImU32 badgeBg = active ? IM_COL32(34, 211, 238, 42) : IM_COL32(255, 255, 255, 11);
        ImU32 badgeBorder = active ? IM_COL32(34, 211, 238, 110) : IM_COL32(255, 255, 255, 18);
        ImU32 badgeFg = active ? IM_COL32(145, 244, 255, 255) : IM_COL32(132, 152, 182, 220);
        dl->AddRectFilled(b1, b2, badgeBg, 6.0f);
        dl->AddRect(b1, b2, badgeBorder, 6.0f, 0, 1.0f);
        dl->AddText(ImVec2(b1.x + 6.0f, b1.y + (badgeH - tagSize.y) * 0.5f), badgeFg, tag);
        ImGui::PopFont();
    }

    ImGui::PopID();
    return clicked;
}

bool Components::KofiButton(const char *label, float height)
{
    ImGui::PushID("kofi_btn");
    ImGuiID id = ImGui::GetID("kofi_anim");

    ImVec2 avail = ImGui::GetContentRegionAvail();
    ImVec2 pMin = ImGui::GetCursorScreenPos();
    ImVec2 pMax(pMin.x + avail.x, pMin.y + height);

    bool clicked = ImGui::InvisibleButton("##kofi_hit", ImVec2(avail.x, height));
    bool hovered = ImGui::IsItemHovered();
    float hoverAnim = AnimateValue(id, hovered ? 1.0f : 0.0f, 12.0f);

    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImU32 cLeft = IM_COL32(248, static_cast<int>(82 + 18 * hoverAnim), static_cast<int>(86 + 18 * hoverAnim), 255);
    ImU32 cRight = IM_COL32(226, static_cast<int>(58 + 18 * hoverAnim), static_cast<int>(96 + 18 * hoverAnim), 255);
    dl->AddRectFilledMultiColor(pMin, pMax, cLeft, cRight, cRight, cLeft);

    float t = static_cast<float>(ImGui::GetTime());
    float cycle = std::fmod(t * 0.42f, 1.0f);
    if (cycle < 0.32f)
    {
        float norm = cycle / 0.32f;
        float sx = pMin.x + (pMax.x - pMin.x) * norm;
        dl->AddLine(ImVec2(sx - 12.0f, pMax.y - 3.0f), ImVec2(sx + 12.0f, pMin.y + 3.0f), IM_COL32(255, 255, 255, 50),
                    14.0f);
    }

    dl->AddRect(pMin, pMax, IM_COL32(255, 185, 185, static_cast<int>(110 + 90 * hoverAnim)), 10.0f, 0, 1.1f);
    Theme::DrawGlassRim(dl, pMin, pMax, 10.0f, IM_COL32(255, 255, 255, 75));

    float cx = pMin.x + 28.0f;
    float cy = pMin.y + height * 0.5f;
    dl->AddRectFilled(ImVec2(cx - 8.0f, cy - 5.0f), ImVec2(cx + 6.0f, cy + 7.0f), IM_COL32(255, 255, 255, 250), 3.0f);
    dl->AddCircle(ImVec2(cx + 7.0f, cy + 0.5f), 3.8f, IM_COL32(255, 255, 255, 250), 16, 1.8f);
    dl->AddCircleFilled(ImVec2(cx - 2.6f, cy + 0.2f), 2.1f, IM_COL32(244, 76, 84, 255));
    dl->AddCircleFilled(ImVec2(cx + 0.6f, cy + 0.2f), 2.1f, IM_COL32(244, 76, 84, 255));
    dl->AddTriangleFilled(ImVec2(cx - 4.5f, cy + 1.0f), ImVec2(cx + 2.5f, cy + 1.0f), ImVec2(cx - 1.0f, cy + 4.8f),
                          IM_COL32(244, 76, 84, 255));

    ImGui::PushFont(Theme::BoldFont());
    ImVec2 txtSz = ImGui::CalcTextSize(label);
    float txtX = pMin.x + 48.0f + (avail.x - 56.0f - txtSz.x) * 0.5f;
    dl->AddText(ImVec2(txtX, pMin.y + (height - txtSz.y) * 0.5f), IM_COL32(255, 255, 255, 255), label);
    ImGui::PopFont();

    if (hovered)
    {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        ImGui::SetTooltip("Support development at ko-fi.com/drjhn291");
    }

    ImGui::PopID();
    return clicked;
}

void Components::SectionHeader(const char *title, const char *subtitle)
{
    ImGui::PushFont(Theme::TitleFont());
    ImGui::TextColored(ImVec4(0.97f, 0.98f, 1.00f, 1.00f), "%s", title);
    ImGui::PopFont();

    ImGui::TextDisabled("%s", subtitle);

    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = std::min(ImGui::GetContentRegionAvail().x, 420.0f);
    ImDrawList *dl = ImGui::GetWindowDrawList();
    dl->AddRectFilledMultiColor(ImVec2(p.x, p.y + 4.0f), ImVec2(p.x + w, p.y + 6.0f), IM_COL32(34, 211, 238, 220),
                                IM_COL32(59, 130, 246, 0), IM_COL32(59, 130, 246, 0), IM_COL32(34, 211, 238, 220));
    ImGui::Dummy(ImVec2(0.0f, 10.0f));
}

void Components::MetricCard(const char *id, const char *label, const char *value, const ImVec4 &accent, float width)
{
    ImGui::PushID(id);
    ImGuiID animId = ImGui::GetID("kpi_hover");

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.056f, 0.080f, 0.128f, 0.96f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(accent.x, accent.y, accent.z, 0.34f));
    ImGui::BeginChild("MetricTile", ImVec2(width, 76.0f), true,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    bool hovered = ImGui::IsWindowHovered();
    float hAnim = AnimateValue(animId, hovered ? 1.0f : 0.0f, 12.0f);

    ImVec2 cMin = ImGui::GetWindowPos();
    ImVec2 cMax(cMin.x + ImGui::GetWindowWidth(), cMin.y + ImGui::GetWindowHeight());
    ImDrawList *dl = ImGui::GetWindowDrawList();

    ImU32 topGlow = IM_COL32(static_cast<int>(accent.x * 255), static_cast<int>(accent.y * 255),
                             static_cast<int>(accent.z * 255), static_cast<int>(24 + 24 * hAnim));
    ImU32 botGlow = IM_COL32(static_cast<int>(accent.x * 255), static_cast<int>(accent.y * 255),
                             static_cast<int>(accent.z * 255), 0);
    dl->AddRectFilledMultiColor(ImVec2(cMin.x + 1.0f, cMin.y + 1.0f), ImVec2(cMax.x - 1.0f, cMax.y - 1.0f), topGlow,
                                topGlow, botGlow, botGlow);

    // Acento superior y reflejo de cristal
    ImU32 barCol = IM_COL32(static_cast<int>(accent.x * 255), static_cast<int>(accent.y * 255),
                            static_cast<int>(accent.z * 255), 245);
    dl->AddRectFilled(ImVec2(cMin.x + 14.0f, cMin.y + 1.5f), ImVec2(cMin.x + 56.0f, cMin.y + 4.0f), barCol, 2.0f);
    Theme::DrawGlassRim(dl, cMin, cMax, 14.0f);

    // Insignia con icono vectorial arriba a la derecha
    ImVec2 badgeCenter(cMax.x - 24.0f, cMin.y + 23.0f);
    dl->AddCircleFilled(badgeCenter, 13.0f,
                        IM_COL32(static_cast<int>(accent.x * 255), static_cast<int>(accent.y * 255),
                                 static_cast<int>(accent.z * 255), 32),
                        24);
    dl->AddCircle(badgeCenter, 13.0f,
                  IM_COL32(static_cast<int>(accent.x * 255), static_cast<int>(accent.y * 255),
                           static_cast<int>(accent.z * 255), 85),
                  24, 1.0f);
    DrawModuleVectorIcon(dl, badgeCenter, label, barCol);

    if (hAnim > 0.02f)
    {
        ImU32 hoverBorder = IM_COL32(static_cast<int>(accent.x * 255), static_cast<int>(accent.y * 255),
                                     static_cast<int>(accent.z * 255), static_cast<int>(185 * hAnim));
        dl->AddRect(cMin, cMax, hoverBorder, 14.0f, 0, 1.4f);
    }

    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 2.0f);
    ImGui::TextDisabled("%s", label);

    ImGui::PushFont(Theme::TitleFont());
    ImGui::TextColored(accent, "%s", value);
    ImGui::PopFont();

    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopID();
}

void Components::StatusBadge(const char *text, const ImVec4 &color)
{
    ImGui::PushFont(Theme::BoldFont());
    ImVec2 txtSz = ImGui::CalcTextSize(text);
    ImVec2 pMin = ImGui::GetCursorScreenPos();
    const float padX = 10.0f;
    const float padY = 3.5f;
    const float dotSpace = 11.0f;
    ImVec2 pMax(pMin.x + txtSz.x + padX * 2.0f + dotSpace, pMin.y + txtSz.y + padY * 2.0f);

    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImU32 fillCol =
        IM_COL32(static_cast<int>(color.x * 255), static_cast<int>(color.y * 255), static_cast<int>(color.z * 255), 30);
    ImU32 borderCol = IM_COL32(static_cast<int>(color.x * 255), static_cast<int>(color.y * 255),
                               static_cast<int>(color.z * 255), 115);
    ImU32 solidCol = IM_COL32(static_cast<int>(color.x * 255), static_cast<int>(color.y * 255),
                              static_cast<int>(color.z * 255), 255);

    dl->AddRectFilled(pMin, pMax, fillCol, 8.0f);
    dl->AddRect(pMin, pMax, borderCol, 8.0f, 0, 1.0f);
    dl->AddCircleFilled(ImVec2(pMin.x + padX + 2.0f, (pMin.y + pMax.y) * 0.5f), 3.2f, solidCol);
    dl->AddText(ImVec2(pMin.x + padX + dotSpace, pMin.y + padY), solidCol, text);

    ImGui::Dummy(ImVec2(pMax.x - pMin.x, pMax.y - pMin.y));
    ImGui::PopFont();
}

void Components::EmptyState(const char *iconHint, const char *title, const char *subtitle)
{
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float h = std::max(175.0f, avail.y);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.052f, 0.075f, 0.122f, 0.92f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.14f, 0.21f, 0.34f, 0.75f));
    ImGui::BeginChild("EmptyStateBox", ImVec2(0.0f, h), true,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    ImVec2 wMin = ImGui::GetWindowPos();
    ImVec2 wMax(wMin.x + ImGui::GetWindowWidth(), wMin.y + ImGui::GetWindowHeight());
    ImDrawList *dl = ImGui::GetWindowDrawList();
    Theme::DrawGlassRim(dl, wMin, wMax, 14.0f);

    float cx = (wMin.x + wMax.x) * 0.5f;
    float cy = (wMin.y + wMax.y) * 0.5f - 24.0f;

    dl->AddCircleFilled(ImVec2(cx, cy), 24.0f, IM_COL32(34, 211, 238, 24), 32);
    dl->AddCircle(ImVec2(cx, cy), 24.0f, IM_COL32(34, 211, 238, 90), 32, 1.2f);
    DrawModuleVectorIcon(dl, ImVec2(cx, cy), iconHint, IM_COL32(56, 225, 248, 245));

    ImGui::PushFont(Theme::BoldFont());
    ImVec2 titleSz = ImGui::CalcTextSize(title);
    dl->AddText(ImVec2(cx - titleSz.x * 0.5f, cy + 34.0f), IM_COL32(236, 244, 255, 250), title);
    ImGui::PopFont();

    ImVec2 subSz = ImGui::CalcTextSize(subtitle);
    dl->AddText(ImVec2(cx - subSz.x * 0.5f, cy + 56.0f), IM_COL32(138, 158, 188, 225), subtitle);

    ImGui::EndChild();
    ImGui::PopStyleColor(2);
}

bool Components::CopyButton(const char *id, const std::string &text)
{
    static std::unordered_map<ImGuiID, double> copiedUntil;
    ImGui::PushID(id);
    ImGuiID btnId = ImGui::GetID("copy_btn");

    double now = ImGui::GetTime();
    bool isCopied = copiedUntil[btnId] > now;

    ImGui::PushFont(Theme::MonoFont());
    if (isCopied)
    {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.14f, 0.56f, 0.38f, 0.90f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.16f, 0.64f, 0.44f, 0.95f));
    }
    else
    {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.10f, 0.16f, 0.27f, 0.95f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.14f, 0.24f, 0.40f, 1.00f));
    }

    bool clicked = ImGui::SmallButton(isCopied ? "Copied!" : "Copy");
    if (clicked && !text.empty())
    {
        ImGui::SetClipboardText(text.c_str());
        copiedUntil[btnId] = now + 1.5;
    }

    ImGui::PopStyleColor(2);
    ImGui::PopFont();
    ImGui::PopID();
    return clicked;
}

bool Components::PlatformCard(const core::UsernameFinding &finding, TextureCache &icons, float width, float height)
{
    bool clicked = false;
    ImGui::PushID(finding.platform.c_str());
    ImGuiID animId = ImGui::GetID("card_hover");

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.060f, 0.086f, 0.136f, 0.96f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.14f, 0.21f, 0.34f, 0.85f));
    ImGui::BeginChild("AppCard", ImVec2(width, height), true,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    bool hovered = ImGui::IsWindowHovered();
    float hAnim = AnimateValue(animId, hovered ? 1.0f : 0.0f, 13.0f);

    ImVec2 wMin = ImGui::GetWindowPos();
    ImVec2 wMax(wMin.x + ImGui::GetWindowWidth(), wMin.y + ImGui::GetWindowHeight());
    ImDrawList *dl = ImGui::GetWindowDrawList();

    Theme::DrawGlassRim(dl, wMin, wMax, 14.0f);

    if (hAnim > 0.01f)
    {
        ImU32 washLeft = IM_COL32(34, 211, 238, static_cast<int>(22 * hAnim));
        ImU32 washRight = IM_COL32(59, 130, 246, static_cast<int>(10 * hAnim));
        dl->AddRectFilledMultiColor(wMin, wMax, washLeft, washRight, washRight, washLeft);
        dl->AddRect(wMin, wMax, IM_COL32(34, 211, 238, static_cast<int>(220 * hAnim)), 14.0f, 0, 1.4f);
    }

    dl->AddRectFilled(ImVec2(wMin.x + 2.0f, wMin.y + 13.0f), ImVec2(wMin.x + 5.2f, wMax.y - 13.0f),
                      IM_COL32(34, 211, 153, static_cast<int>(190 + 65 * hAnim)), 2.5f);

    ID3D11ShaderResourceView *tex = icons.GetDomainIcon(finding.domain);
    if (tex)
    {
        ImVec2 ip = ImGui::GetCursorScreenPos();
        dl->AddRectFilled(ImVec2(ip.x - 2.0f, ip.y - 2.0f), ImVec2(ip.x + 44.0f, ip.y + 44.0f),
                          IM_COL32(18, 28, 46, 220), 11.0f);
        ImGui::Image(reinterpret_cast<ImTextureID>(tex), ImVec2(42.0f, 42.0f));
    }
    else
    {
        ImVec2 ip = ImGui::GetCursorScreenPos();
        dl->AddRectFilled(ip, ImVec2(ip.x + 42.0f, ip.y + 42.0f), IM_COL32(22, 52, 108, 230), 11.0f);
        dl->AddRect(ip, ImVec2(ip.x + 42.0f, ip.y + 42.0f), IM_COL32(56, 189, 248, 175), 11.0f);
        char initial[2] = {
            finding.platform.empty() ? '?' : static_cast<char>(std::toupper((unsigned char)finding.platform[0])), '\0'};
        ImGui::PushFont(Theme::BoldFont());
        ImVec2 tsz = ImGui::CalcTextSize(initial);
        dl->AddText(ImVec2(ip.x + (42.0f - tsz.x) * 0.5f, ip.y + (42.0f - tsz.y) * 0.5f), IM_COL32(232, 245, 255, 255),
                    initial);
        ImGui::PopFont();
        ImGui::Dummy(ImVec2(42.0f, 42.0f));
    }

    ImGui::SameLine(0.0f, 12.0f);
    ImGui::BeginGroup();
    ImGui::PushFont(Theme::BoldFont());
    ImGui::TextColored(ImVec4(0.97f, 0.98f, 1.00f, 1.00f), "%s", finding.platform.c_str());
    ImGui::PopFont();

    ImGui::PushFont(Theme::MonoFont());
    if (!finding.matched_handle.empty())
    {
        ImGui::TextColored(ImVec4(0.20f, 0.88f, 0.56f, 1.00f), "@%s", finding.matched_handle.c_str());
    }
    else
    {
        ImGui::TextColored(ImVec4(0.20f, 0.88f, 0.56f, 1.00f), "VERIFIED");
    }
    ImGui::PopFont();

    ImGui::SameLine(0.0f, 6.0f);
    ImGui::TextDisabled("| %s", finding.category.c_str());
    ImGui::EndGroup();

    if (hAnim > 0.05f)
    {
        ImGui::PushFont(Theme::MonoFont());
        const char *openTag = "OPEN";
        ImVec2 tagSz = ImGui::CalcTextSize(openTag);
        ImVec2 b1(wMax.x - tagSz.x - 24.0f, wMin.y + (height - 23.0f) * 0.5f);
        ImVec2 b2(wMax.x - 10.0f, b1.y + 23.0f);
        dl->AddRectFilled(b1, b2, IM_COL32(34, 211, 238, static_cast<int>(42 * hAnim)), 7.0f);
        dl->AddRect(b1, b2, IM_COL32(34, 211, 238, static_cast<int>(140 * hAnim)), 7.0f);
        dl->AddText(ImVec2(b1.x + 7.0f, b1.y + (23.0f - tagSz.y) * 0.5f),
                    IM_COL32(145, 245, 255, static_cast<int>(255 * hAnim)), openTag);
        ImGui::PopFont();
    }

    if (hovered)
    {
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        ImGui::SetTooltip("Open direct profile: %s", finding.url.c_str());
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
        {
            clicked = true;
        }
    }

    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopID();
    return clicked;
}

} // namespace ui