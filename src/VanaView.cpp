#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "Ashita.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

#pragma comment(linker, "/EXPORT:expCreatePlugin=_expCreatePlugin@4")
#pragma comment(linker, "/EXPORT:expGetInterfaceVersion=_expGetInterfaceVersion@0")

namespace
{
    struct BytesPatchSite
    {
        uintptr_t address = 0;
        uint8_t original[16]{};
        uint32_t length = 0;
        bool patched = false;
    };

    template<typename T>
    bool safe_read(const uintptr_t address, T& value)
    {
        __try
        {
            value = *reinterpret_cast<const T*>(address);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    template<typename T>
    bool safe_write(const uintptr_t address, const T& value)
    {
        DWORD oldProtect = 0;
        if (!::VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        __try
        {
            *reinterpret_cast<T*>(address) = value;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DWORD unused = 0;
            ::VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), oldProtect, &unused);
            return false;
        }

        DWORD unused = 0;
        ::VirtualProtect(reinterpret_cast<void*>(address), sizeof(T), oldProtect, &unused);
        return true;
    }

    bool get_module_range(const char* moduleName, uintptr_t& base, uint32_t& size)
    {
        const auto module = ::GetModuleHandleA(moduleName);
        if (module == nullptr)
            return false;

        IMAGE_DOS_HEADER dos{};
        if (!safe_read(reinterpret_cast<uintptr_t>(module), dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        IMAGE_NT_HEADERS32 nt{};
        if (!safe_read(reinterpret_cast<uintptr_t>(module) + static_cast<uintptr_t>(dos.e_lfanew), nt) ||
            nt.Signature != IMAGE_NT_SIGNATURE)
            return false;

        base = reinterpret_cast<uintptr_t>(module);
        size = nt.OptionalHeader.SizeOfImage;
        return size != 0;
    }

    uintptr_t find_bytes(const uintptr_t base, const uint32_t size, const uint8_t* pattern, const size_t length)
    {
        if (base == 0 || size < length)
            return 0;

        for (uint32_t i = 0; i <= size - length; ++i)
        {
            bool match = true;
            __try
            {
                for (size_t j = 0; j < length; ++j)
                {
                    if (*reinterpret_cast<const uint8_t*>(base + i + j) != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                match = false;
            }

            if (match)
                return base + i;
        }

        return 0;
    }

    bool bytes_match(const uintptr_t address, const uint8_t* expected, const uint32_t length)
    {
        __try
        {
            return std::memcmp(reinterpret_cast<const void*>(address), expected, length) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool write_bytes_patch(BytesPatchSite& site, const uintptr_t address, const uint8_t* patch, const uint32_t length)
    {
        if (site.patched)
            return true;
        if (patch == nullptr || length == 0 || length > sizeof(site.original))
            return false;

        __try
        {
            std::memcpy(site.original, reinterpret_cast<const void*>(address), length);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }

        DWORD oldProtect = 0;
        if (!::VirtualProtect(reinterpret_cast<void*>(address), length, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        std::memcpy(reinterpret_cast<void*>(address), patch, length);
        ::FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<void*>(address), length);

        DWORD unused = 0;
        ::VirtualProtect(reinterpret_cast<void*>(address), length, oldProtect, &unused);

        site.address = address;
        site.length = length;
        site.patched = true;
        return true;
    }

    bool write_jump_patch(BytesPatchSite& site, const uintptr_t address, void* destination, const uint32_t length)
    {
        if (site.patched)
            return true;
        if (destination == nullptr || length < 5 || length > sizeof(site.original))
            return false;

        __try
        {
            std::memcpy(site.original, reinterpret_cast<const void*>(address), length);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }

        DWORD oldProtect = 0;
        if (!::VirtualProtect(reinterpret_cast<void*>(address), length, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        const intptr_t relative = reinterpret_cast<uintptr_t>(destination) - (address + 5);
        auto* out = reinterpret_cast<uint8_t*>(address);
        out[0] = 0xE9;
        std::memcpy(out + 1, &relative, sizeof(int32_t));
        for (uint32_t i = 5; i < length; ++i)
            out[i] = 0x90;

        ::FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<void*>(address), length);

        DWORD unused = 0;
        ::VirtualProtect(reinterpret_cast<void*>(address), length, oldProtect, &unused);

        site.address = address;
        site.length = length;
        site.patched = true;
        return true;
    }

    bool restore_patch(BytesPatchSite& site)
    {
        if (!site.patched)
            return true;

        DWORD oldProtect = 0;
        if (!::VirtualProtect(reinterpret_cast<void*>(site.address), site.length, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        std::memcpy(reinterpret_cast<void*>(site.address), site.original, site.length);
        ::FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<void*>(site.address), site.length);

        DWORD unused = 0;
        ::VirtualProtect(reinterpret_cast<void*>(site.address), site.length, oldProtect, &unused);
        site = {};
        return true;
    }

    bool iequals(const char* a, const char* b)
    {
        return _stricmp(a, b) == 0;
    }

    float clamp_float(float value, const float lo, const float hi)
    {
        if (value < lo)
            return lo;
        if (value > hi)
            return hi;
        return value;
    }

    DWORD float_to_dword(const float value)
    {
        DWORD out = 0;
        std::memcpy(&out, &value, sizeof(out));
        return out;
    }

    float dword_to_float(const DWORD value)
    {
        float out = 0.0f;
        std::memcpy(&out, &value, sizeof(out));
        return out;
    }

    constexpr float kDefaultDrawDistance = 1.0f;
    constexpr float kMaxDrawDistance = 100.0f;
    constexpr float kDrawDistanceSliderPower = 2.0f;
    constexpr float kDefaultDrawDistanceSlider = 20.0f;
    constexpr float kDefaultFogStart = 20.0f;
    constexpr float kDefaultFogEnd = 120.0f;
    constexpr float kMaxFogDistance = 1000.0f;
    constexpr float kLodRangeMin = 0.25f;
    constexpr float kLodRangeMax = 10.0f;
    constexpr int kConfigVersion = 9;
    constexpr const char* kZoneProfilesHelp =
        "When enabled, VanaView loads a profile for the current zone if one exists. "
        "Zones without a saved profile use the global profile until you save settings for that zone.";
    constexpr const char* kDistanceHelp =
        "Raises the game's world and entity draw distance. In Distance fog mode, "
        "the game's fog range is still linked to this raised distance.";
    constexpr const char* kLodModeHelp =
        "Range scales the map LoD checks. Full keeps high-detail map models visible "
        "and ignores the LoD range slider.";
    constexpr const char* kLodRangeHelp =
        "Scales the distance used by the Range LoD patch.";
    constexpr const char* kLodRangeDisabledHelp =
        "Disabled while LoD is Full. Switch LoD to Range to tune this value.";
    constexpr const char* kFogModeHelp =
        "Distance uses the game's fog exactly as emitted, so it follows raised draw distance. "
        "Game uses the last natural fog range captured from the game and reapplies it with raised distance; "
        "it refreshes when the game sends new fog values, such as on zone or weather updates. "
        "Custom forces the Fog start/end sliders.";
    float g_lodRangeScaleSq = 1.0f;
    uintptr_t g_lodRangeReturn0 = 0;
    uintptr_t g_lodRangeReturn1 = 0;
    uintptr_t g_lodRangeReturn2 = 0;
    uintptr_t g_lodRangeReturn3 = 0;

    float draw_distance_to_slider(const float value)
    {
        const float normalized = clamp_float((value - kDefaultDrawDistance) / (kMaxDrawDistance - kDefaultDrawDistance), 0.0f, 1.0f);
        return 1.0f + (std::pow(normalized, 1.0f / kDrawDistanceSliderPower) * 99.0f);
    }

    float slider_to_draw_distance(const float value)
    {
        const float normalized = clamp_float((value - 1.0f) / 99.0f, 0.0f, 1.0f);
        return kDefaultDrawDistance + (std::pow(normalized, kDrawDistanceSliderPower) * (kMaxDrawDistance - kDefaultDrawDistance));
    }

    float default_draw_distance()
    {
        return slider_to_draw_distance(kDefaultDrawDistanceSlider);
    }
}

extern "C" __declspec(naked) void vanaview_lod_range0_hook()
{
    __asm
    {
        fld dword ptr [esp + 14h]
        fdiv dword ptr [g_lodRangeScaleSq]
        fcomp dword ptr [ecx + 0CCh]
        jmp dword ptr [g_lodRangeReturn0]
    }
}

extern "C" __declspec(naked) void vanaview_lod_range1_hook()
{
    __asm
    {
        fld dword ptr [esp + 14h]
        fdiv dword ptr [g_lodRangeScaleSq]
        fcomp dword ptr [ecx + 0C8h]
        jmp dword ptr [g_lodRangeReturn1]
    }
}

extern "C" __declspec(naked) void vanaview_lod_range2_hook()
{
    __asm
    {
        fld dword ptr [esp + 58h]
        fdiv dword ptr [g_lodRangeScaleSq]
        fcomp dword ptr [edi + 0CCh]
        jmp dword ptr [g_lodRangeReturn2]
    }
}

extern "C" __declspec(naked) void vanaview_lod_range3_hook()
{
    __asm
    {
        fld dword ptr [esp + 58h]
        fdiv dword ptr [g_lodRangeScaleSq]
        fcomp dword ptr [edi + 0C8h]
        jmp dword ptr [g_lodRangeReturn3]
    }
}

class VanaView final : public IPlugin
{
public:
    const char* GetName(void) const override { return "VanaView"; }
    const char* GetAuthor(void) const override { return "rockmizx"; }
    const char* GetDescription(void) const override { return "Tunes world draw distance, map LoD, and fog distance."; }
    const char* GetLink(void) const override { return ""; }
    double GetVersion(void) const override { return 1.0; }

    uint32_t GetFlags(void) const override
    {
        return static_cast<uint32_t>(Ashita::PluginFlags::UseCommands) |
            static_cast<uint32_t>(Ashita::PluginFlags::UseDirect3D);
    }

    bool Initialize(IAshitaCore* core, ILogManager*, const uint32_t) override
    {
        m_core = core;
        build_config_path();
        load_config();
        update_current_zone();
        load_active_profile();
        refresh_ffximain();
        refresh_drawdistance_pointers();
        capture_original_draw_distances();
        apply_draw_distances();
        apply_lod_mode();
        chat("VanaView loaded. Use /vv to configure.");
        return true;
    }

    void Release(void) override
    {
        save_config(false);
        m_gameFogSampling = false;
        restore_draw_distances();
        restore_lod_patches();
        m_fogMode = FogMode::DistanceLinked;
        restore_fog_state();
        m_device = nullptr;
    }

    bool Direct3DInitialize(IDirect3DDevice8* device) override
    {
        m_device = device;
        return true;
    }

    bool HandleCommand(int32_t, const char* command, bool) override
    {
        if (command == nullptr)
            return false;

        char buffer[512]{};
        std::snprintf(buffer, sizeof(buffer), "%s", command);

        char* context = nullptr;
        char* token = strtok_s(buffer, " \t", &context);
        if (token == nullptr || (!iequals(token, "/vanaview") && !iequals(token, "/vv")))
            return false;

        const char* sub = strtok_s(nullptr, " \t", &context);
        if (sub == nullptr)
        {
            m_windowOpen = !m_windowOpen;
            return true;
        }

        if (iequals(sub, "help"))
        {
            print_help();
            return true;
        }

        if (iequals(sub, "status"))
        {
            print_status();
            return true;
        }

        if (iequals(sub, "reset"))
        {
            restore_default_runtime();
            save_config();
            chat("Default restored.");
            return true;
        }

        if (iequals(sub, "zone"))
        {
            const char* value = strtok_s(nullptr, " \t", &context);
            if (value == nullptr || iequals(value, "status"))
            {
                chat(
                    "Zone profiles: %s zone=%u profile=%s",
                    m_useZoneProfiles ? "on" : "off",
                    static_cast<unsigned int>(m_currentZoneId),
                    m_activeZoneHasProfile ? "zone" : "global");
                return true;
            }
            if (iequals(value, "on"))
            {
                set_zone_profiles_enabled(true);
                chat("Zone profiles enabled.");
                return true;
            }
            if (iequals(value, "off"))
            {
                set_zone_profiles_enabled(false);
                chat("Zone profiles disabled.");
                return true;
            }
            chat("Usage: /vv zone on | off | status");
            return true;
        }

        if (iequals(sub, "distance"))
        {
            const char* value = strtok_s(nullptr, " \t", &context);
            if (value == nullptr)
            {
                chat("Distance: %.0f", static_cast<double>(draw_distance_to_slider(m_drawDistance)));
                return true;
            }
            if (iequals(value, "default"))
            {
                restore_draw_distances();
                sync_default_draw_distance();
                save_config();
                chat("Draw distance restored to default.");
                return true;
            }
            char* end = nullptr;
            const float parsed = std::strtof(value, &end);
            if (end == value)
            {
                chat("Usage: /vv distance <1-100> | default");
                return true;
            }
            if (parsed <= 0.0f)
            {
                restore_draw_distances();
                sync_default_draw_distance();
                save_config();
                chat("Draw distance restored to default.");
                return true;
            }
            const float distance = slider_to_draw_distance(parsed);
            m_drawDistance = distance;
            apply_draw_distances();
            save_config();
            chat("Distance set to %.0f.", static_cast<double>(clamp_float(parsed, 1.0f, kMaxDrawDistance)));
            return true;
        }

        if (iequals(sub, "lod"))
        {
            const char* mode = strtok_s(nullptr, " \t", &context);
            if (mode == nullptr || iequals(mode, "status"))
            {
                print_lod_status();
                return true;
            }
            if (std::isdigit(static_cast<unsigned char>(mode[0])) || mode[0] == '.')
            {
                m_lodRangeScale = clamp_float(std::strtof(mode, nullptr), kLodRangeMin, kLodRangeMax);
                m_lodMode = LodMode::Range;
                const bool ok = apply_lod_mode();
                save_config();
                chat(ok ? "LoD range %.2fx." : "LoD range failed. Signature mismatch.", static_cast<double>(m_lodRangeScale));
                return true;
            }
            if (iequals(mode, "full") || iequals(mode, "high"))
            {
                m_lodMode = LodMode::High;
                const bool ok = apply_lod_mode();
                save_config();
                chat(ok ? "LoD mode: full." : "LoD full failed. Signature mismatch.");
                return true;
            }
            if (iequals(mode, "default"))
            {
                m_lodMode = LodMode::Off;
                m_lodRangeScale = 1.0f;
                restore_lod_patches();
                save_config();
                chat("LoD restored to default.");
                return true;
            }
            chat("Usage: /vv lod <scale> | full | default");
            return true;
        }

        if (iequals(sub, "fog"))
        {
            const char* mode = strtok_s(nullptr, " \t", &context);
            if (mode == nullptr || iequals(mode, "status"))
            {
                print_fog_status();
                return true;
            }
            if (iequals(mode, "default"))
            {
                set_fog_mode(FogMode::DistanceLinked);
                sync_default_fog_range();
                restore_fog_state();
                save_config();
                chat("Fog mode: distance-linked.");
                return true;
            }
            if (iequals(mode, "distance") || iequals(mode, "linked"))
            {
                set_fog_mode(FogMode::DistanceLinked);
                save_config();
                chat("Fog mode: distance-linked.");
                return true;
            }
            if (iequals(mode, "game") || iequals(mode, "natural"))
            {
                set_fog_mode(FogMode::Game);
                save_config();
                chat("Fog mode: game values.");
                return true;
            }
            if (iequals(mode, "custom"))
            {
                set_fog_mode(FogMode::Custom);
                save_config();
                chat("Fog mode: custom %.1f-%.1f.", static_cast<double>(m_fogStart), static_cast<double>(m_fogEnd));
                return true;
            }
            if (std::isdigit(static_cast<unsigned char>(mode[0])) || mode[0] == '.')
            {
                const char* start = mode;
                const char* end = strtok_s(nullptr, " \t", &context);
                if (start == nullptr || end == nullptr)
                {
                    chat("Usage: /vv fog <start> <end>");
                    return true;
                }
                m_fogStart = clamp_float(std::strtof(start, nullptr), 0.0f, kMaxFogDistance);
                const float requestedEnd = std::strtof(end, nullptr);
                m_fogEnd = clamp_float(requestedEnd, m_fogStart + 1.0f, kMaxFogDistance);
                set_fog_mode(FogMode::Custom);
                save_config();
                chat("Fog range set to %.1f-%.1f.", static_cast<double>(m_fogStart), static_cast<double>(m_fogEnd));
                return true;
            }
            chat("Usage: /vv fog <start> <end> | custom | game | distance | default");
            return true;
        }

        print_help();
        return true;
    }

    void Direct3DBeginScene(bool isRenderingBackBuffer) override
    {
        begin_game_fog_sample(isRenderingBackBuffer);
    }

    void Direct3DEndScene(bool isRenderingBackBuffer) override
    {
        if (isRenderingBackBuffer)
            finish_game_fog_sample();
    }

    void Direct3DPresent(const RECT* pSourceRect, const RECT* pDestRect, HWND hDestWindowOverride, const RGNDATA* pDirtyRegion) override
    {
        UNREFERENCED_PARAMETER(pSourceRect);
        UNREFERENCED_PARAMETER(pDestRect);
        UNREFERENCED_PARAMETER(hDestWindowOverride);
        UNREFERENCED_PARAMETER(pDirtyRegion);

        update_zone_profile();
        render_window();
    }

    bool Direct3DSetRenderState(D3DRENDERSTATETYPE state, DWORD* value) override
    {
        if (value == nullptr)
            return false;
        if (m_applyingForcedFogState)
            return false;

        if (state == D3DRS_FOGSTART)
        {
            capture_original_fog_start(dword_to_float(*value));
            finish_game_fog_sample_if_ready();
            if (should_force_fog_state())
                *value = float_to_dword(m_fogStart);
        }
        else if (state == D3DRS_FOGEND)
        {
            capture_original_fog_end(dword_to_float(*value));
            finish_game_fog_sample_if_ready();
            if (should_force_fog_state())
                *value = float_to_dword(m_fogEnd);
        }
        else if (should_force_fog_state() && state == D3DRS_FOGVERTEXMODE)
        {
            *value = D3DFOG_LINEAR;
        }
        else if (should_force_fog_state() && state == D3DRS_FOGTABLEMODE)
        {
            *value = D3DFOG_NONE;
        }
        else if (should_force_fog_state() && state == D3DRS_RANGEFOGENABLE)
        {
            *value = FALSE;
        }

        return false;
    }

    bool Direct3DDrawPrimitive(D3DPRIMITIVETYPE primitiveType, UINT startVertex, UINT primitiveCount) override
    {
        UNREFERENCED_PARAMETER(primitiveType);
        UNREFERENCED_PARAMETER(startVertex);
        UNREFERENCED_PARAMETER(primitiveCount);

        apply_fog_state_before_draw();
        return false;
    }

    bool Direct3DDrawIndexedPrimitive(D3DPRIMITIVETYPE primitiveType, UINT minIndex, UINT numVertices, UINT startIndex, UINT primCount) override
    {
        UNREFERENCED_PARAMETER(primitiveType);
        UNREFERENCED_PARAMETER(minIndex);
        UNREFERENCED_PARAMETER(numVertices);
        UNREFERENCED_PARAMETER(startIndex);
        UNREFERENCED_PARAMETER(primCount);

        apply_fog_state_before_draw();
        return false;
    }

    bool Direct3DDrawPrimitiveUP(D3DPRIMITIVETYPE primitiveType, UINT primitiveCount, CONST void* vertexStreamZeroData, UINT vertexStreamZeroStride) override
    {
        UNREFERENCED_PARAMETER(primitiveType);
        UNREFERENCED_PARAMETER(primitiveCount);
        UNREFERENCED_PARAMETER(vertexStreamZeroData);
        UNREFERENCED_PARAMETER(vertexStreamZeroStride);

        apply_fog_state_before_draw();
        return false;
    }

    bool Direct3DDrawIndexedPrimitiveUP(D3DPRIMITIVETYPE primitiveType, UINT minVertexIndex, UINT numVertexIndices, UINT primitiveCount, CONST void* indexData, D3DFORMAT indexDataFormat, CONST void* vertexStreamZeroData, UINT vertexStreamZeroStride) override
    {
        UNREFERENCED_PARAMETER(primitiveType);
        UNREFERENCED_PARAMETER(minVertexIndex);
        UNREFERENCED_PARAMETER(numVertexIndices);
        UNREFERENCED_PARAMETER(primitiveCount);
        UNREFERENCED_PARAMETER(indexData);
        UNREFERENCED_PARAMETER(indexDataFormat);
        UNREFERENCED_PARAMETER(vertexStreamZeroData);
        UNREFERENCED_PARAMETER(vertexStreamZeroStride);

        apply_fog_state_before_draw();
        return false;
    }

private:
    enum class FogMode : int
    {
        DistanceLinked = 0,
        Custom = 1,
        Game = 2,
    };

    void print_help()
    {
        chat("/vv opens the configuration window");
        chat("/vv distance <1-100> | default");
        chat("/vv lod <scale> | full | default");
        chat("/vv fog <start> <end> | custom | game | distance | default");
        chat("/vv zone on | off | status");
        chat("/vv reset");
        chat("/vv status");
    }

    void print_status()
    {
        chat(
            "VanaView: distance=%.0f lod=%s %.2fx ptr=%s",
            static_cast<double>(draw_distance_to_slider(m_drawDistance)),
            lod_mode_name(),
            static_cast<double>(m_lodRangeScale),
            (m_worldDistanceAddress != 0 && m_entityDistanceAddress != 0) ? "ok" : "missing");
        print_fog_status();
    }

    void print_lod_status()
    {
        chat("LoD mode: %s range=%.2fx", lod_mode_name(), static_cast<double>(m_lodRangeScale));
    }

    const char* lod_mode_name() const
    {
        if (m_lodMode == LodMode::High)
            return "full";
        if (m_lodMode == LodMode::Range)
            return "range";
        return "default";
    }

    FogMode parse_fog_mode(const int value) const
    {
        if (value == static_cast<int>(FogMode::Custom))
            return FogMode::Custom;
        if (value == static_cast<int>(FogMode::Game))
            return FogMode::Game;
        return FogMode::DistanceLinked;
    }

    bool should_force_fog_state() const
    {
        return m_fogMode == FogMode::Custom || m_fogMode == FogMode::Game;
    }

    void set_fog_mode(const FogMode mode)
    {
        if (m_fogMode == mode)
            return;

        finish_game_fog_sample();
        m_fogMode = mode;
        apply_active_fog_mode();
    }

    void apply_active_fog_mode()
    {
        if (m_fogMode == FogMode::DistanceLinked)
        {
            reset_game_fog_sample(false);
            restore_fog_state();
            return;
        }
        if (m_fogMode == FogMode::Game)
        {
            reset_game_fog_sample(true);
            apply_forced_fog_state();
            return;
        }

        reset_game_fog_sample(false);
        apply_forced_fog_state();
    }

    void show_help_marker(IGuiManager* gui, const char* text)
    {
        if (gui == nullptr || text == nullptr)
            return;

        gui->SameLine(0.0f, 4.0f);
        gui->TextDisabled("(?)");
        if (!gui->IsItemHovered())
            return;

        gui->BeginTooltip();
        gui->PushTextWrapPos(gui->GetFontSize() * 35.0f);
        gui->TextWrapped("%s", text);
        gui->PopTextWrapPos();
        gui->EndTooltip();
    }

    int push_theme(IGuiManager* gui)
    {
        if (gui == nullptr)
            return 0;

        int count = 0;
        auto push = [&](const ImGuiCol idx, const float r, const float g, const float b, const float a)
        {
            gui->PushStyleColor(idx, ImVec4(r, g, b, a));
            ++count;
        };

        push(ImGuiCol_WindowBg, 0.10f, 0.10f, 0.10f, 0.94f);
        push(ImGuiCol_ChildBg, 0.12f, 0.12f, 0.12f, 0.60f);
        push(ImGuiCol_PopupBg, 0.10f, 0.10f, 0.10f, 0.96f);
        push(ImGuiCol_Border, 0.30f, 0.30f, 0.30f, 0.50f);
        push(ImGuiCol_FrameBg, 0.18f, 0.18f, 0.18f, 0.82f);
        push(ImGuiCol_FrameBgHovered, 0.28f, 0.28f, 0.28f, 0.88f);
        push(ImGuiCol_FrameBgActive, 0.36f, 0.36f, 0.36f, 0.95f);
        push(ImGuiCol_TitleBg, 0.08f, 0.08f, 0.08f, 1.00f);
        push(ImGuiCol_TitleBgActive, 0.14f, 0.14f, 0.14f, 1.00f);
        push(ImGuiCol_Button, 0.24f, 0.24f, 0.24f, 0.82f);
        push(ImGuiCol_ButtonHovered, 0.34f, 0.34f, 0.34f, 0.90f);
        push(ImGuiCol_ButtonActive, 0.44f, 0.44f, 0.44f, 0.96f);
        push(ImGuiCol_Header, 0.24f, 0.24f, 0.24f, 0.82f);
        push(ImGuiCol_HeaderHovered, 0.34f, 0.34f, 0.34f, 0.90f);
        push(ImGuiCol_HeaderActive, 0.44f, 0.44f, 0.44f, 0.96f);
        push(ImGuiCol_ScrollbarBg, 0.05f, 0.05f, 0.05f, 0.35f);
        push(ImGuiCol_ScrollbarGrab, 0.42f, 0.42f, 0.42f, 0.72f);
        push(ImGuiCol_ScrollbarGrabHovered, 0.56f, 0.56f, 0.56f, 0.86f);
        push(ImGuiCol_ScrollbarGrabActive, 0.70f, 0.70f, 0.70f, 0.96f);
        push(ImGuiCol_CheckMark, 0.82f, 0.82f, 0.82f, 1.00f);
        push(ImGuiCol_SliderGrab, 0.58f, 0.58f, 0.58f, 0.92f);
        push(ImGuiCol_SliderGrabActive, 0.78f, 0.78f, 0.78f, 1.00f);
        push(ImGuiCol_Tab, 0.18f, 0.18f, 0.18f, 0.86f);
        push(ImGuiCol_TabHovered, 0.36f, 0.36f, 0.36f, 0.90f);
        push(ImGuiCol_TabActive, 0.30f, 0.30f, 0.30f, 1.00f);
        push(ImGuiCol_TextSelectedBg, 0.55f, 0.55f, 0.55f, 0.45f);
        return count;
    }

    void render_window()
    {
        if (!m_windowOpen || m_core == nullptr || m_core->GetGuiManager() == nullptr)
            return;

        auto* gui = m_core->GetGuiManager();
        const int themeCount = push_theme(gui);
        gui->SetNextWindowSize(ImVec2(455.0f, 390.0f), ImGuiCond_Always);

        bool open = m_windowOpen;
        if (gui->Begin("VanaView", &open, ImGuiWindowFlags_NoResize))
        {
            gui->Text("Visual distance and LoD");
            gui->Separator();

            bool changed = false;

            bool useZoneProfiles = m_useZoneProfiles;
            if (gui->Checkbox("Use zone profiles", &useZoneProfiles))
            {
                set_zone_profiles_enabled(useZoneProfiles);
                changed = false;
            }
            show_help_marker(gui, kZoneProfilesHelp);
            gui->SameLine(0.0f, 12.0f);
            if (m_useZoneProfiles)
            {
                if (m_activeZoneHasProfile)
                    gui->TextDisabled("| Profile: Zone %u", static_cast<unsigned int>(m_currentZoneId));
                else
                    gui->TextDisabled("| Profile: Global fallback (zone %u)", static_cast<unsigned int>(m_currentZoneId));
            }
            else
            {
                gui->TextDisabled("| Profile: Global");
            }

            float distance = draw_distance_to_slider(m_drawDistance);
            gui->SetNextItemWidth(260.0f);
            if (gui->SliderFloat("Distance", &distance, 1.0f, kMaxDrawDistance, "%.0f"))
            {
                m_drawDistance = slider_to_draw_distance(distance);
                apply_draw_distances();
                changed = true;
            }
            show_help_marker(gui, kDistanceHelp);

            gui->Separator();
            gui->Text("Map LoD");
            show_help_marker(gui, kLodModeHelp);

            int lodMode = static_cast<int>(m_lodMode);
            bool lodChanged = false;
            lodChanged = gui->RadioButton("Range##lod", &lodMode, static_cast<int>(LodMode::Range)) || lodChanged;
            gui->SameLine();
            lodChanged = gui->RadioButton("Full##lod", &lodMode, static_cast<int>(LodMode::High)) || lodChanged;
            if (lodChanged)
            {
                m_lodMode = static_cast<LodMode>(lodMode);
                apply_lod_mode();
                changed = true;
            }

            float lodScale = m_lodRangeScale;
            if (m_lodMode == LodMode::High)
            {
                char lodOverlay[32]{};
                std::snprintf(lodOverlay, sizeof(lodOverlay), "%.2fx", static_cast<double>(lodScale));
                const float lodProgress = clamp_float((lodScale - kLodRangeMin) / (kLodRangeMax - kLodRangeMin), 0.0f, 1.0f);
                gui->PushStyleVar(ImGuiStyleVar_Alpha, 0.45f);
                gui->ProgressBar(lodProgress, ImVec2(260.0f, 0.0f), lodOverlay);
                gui->SameLine();
                gui->Text("LoD range");
                gui->PopStyleVar();
                show_help_marker(gui, kLodRangeDisabledHelp);
            }
            else
            {
                gui->SetNextItemWidth(260.0f);
                if (gui->SliderFloat("LoD range", &lodScale, kLodRangeMin, kLodRangeMax, "%.2fx"))
                {
                    m_lodRangeScale = clamp_float(lodScale, kLodRangeMin, kLodRangeMax);
                    if (m_lodMode == LodMode::Range)
                        apply_lod_mode();
                    changed = true;
                }
                show_help_marker(gui, kLodRangeHelp);
            }

            gui->Separator();
            gui->Text("Fog");
            show_help_marker(gui, kFogModeHelp);

            int fogMode = static_cast<int>(m_fogMode);
            bool fogModeChanged = false;
            fogModeChanged = gui->RadioButton("Distance##fog", &fogMode, static_cast<int>(FogMode::DistanceLinked)) || fogModeChanged;
            gui->SameLine();
            fogModeChanged = gui->RadioButton("Game##fog", &fogMode, static_cast<int>(FogMode::Game)) || fogModeChanged;
            gui->SameLine();
            fogModeChanged = gui->RadioButton("Custom##fog", &fogMode, static_cast<int>(FogMode::Custom)) || fogModeChanged;
            if (fogModeChanged)
            {
                set_fog_mode(parse_fog_mode(fogMode));
                changed = true;
            }

            float fogStart = m_fogStart;
            float fogEnd = m_fogEnd;
            gui->SetNextItemWidth(260.0f);
            const bool fogStartSliderChanged = gui->SliderFloat("Fog start", &fogStart, 0.0f, kMaxFogDistance, "%.0f");
            gui->SetNextItemWidth(260.0f);
            const bool fogEndSliderChanged = gui->SliderFloat("Fog end", &fogEnd, 1.0f, kMaxFogDistance, "%.0f");
            if (fogStartSliderChanged || fogEndSliderChanged)
            {
                m_fogStart = clamp_float(fogStart, 0.0f, kMaxFogDistance);
                m_fogEnd = clamp_float(fogEnd, m_fogStart + 1.0f, kMaxFogDistance);
                set_fog_mode(FogMode::Custom);
                changed = true;
            }

            gui->Separator();
            if (gui->Button("Default", ImVec2(90.0f, 0.0f)))
            {
                restore_default_runtime();
                changed = true;
            }

            gui->SameLine();
            if (gui->Button("Save", ImVec2(80.0f, 0.0f)))
            {
                save_config();
                chat("Settings saved.");
            }

            if (changed)
                save_config();
        }
        gui->End();

        m_windowOpen = open;
        if (themeCount > 0)
            gui->PopStyleColor(themeCount);
    }

    void print_fog_status()
    {
        if (m_fogMode == FogMode::DistanceLinked)
        {
            chat("Fog: distance-linked %.1f-%.1f", static_cast<double>(m_fogStart), static_cast<double>(m_fogEnd));
            return;
        }
        if (m_fogMode == FogMode::Game)
        {
            chat("Fog: game %.1f-%.1f", static_cast<double>(m_fogStart), static_cast<double>(m_fogEnd));
            return;
        }
        chat("Fog: custom %.1f-%.1f", static_cast<double>(m_fogStart), static_cast<double>(m_fogEnd));
    }

    void chat(const char* format, ...)
    {
        if (m_core == nullptr || m_core->GetChatManager() == nullptr)
            return;

        char message[512]{};
        va_list args;
        va_start(args, format);
        std::vsnprintf(message, sizeof(message), format, args);
        va_end(args);

        char output[640]{};
        std::snprintf(output, sizeof(output), "[VanaView] %s", message);
        m_core->GetChatManager()->Write(1, false, output);
    }

    void build_config_path()
    {
        const char* installPath = (m_core != nullptr && m_core->GetInstallPath() != nullptr) ? m_core->GetInstallPath() : ".";
        char parent[MAX_PATH]{};
        std::snprintf(parent, sizeof(parent), "%sconfig", installPath);
        ::CreateDirectoryA(parent, nullptr);
        char dir[MAX_PATH]{};
        std::snprintf(dir, sizeof(dir), "%sconfig\\plugins", installPath);
        ::CreateDirectoryA(dir, nullptr);
        std::snprintf(m_configPath, sizeof(m_configPath), "%s\\VanaView.ini", dir);
    }

    void load_config()
    {
        const int configVersion = ::GetPrivateProfileIntA("general", "version", 0, m_configPath);
        if (configVersion < 1)
        {
            reset_config_to_defaults();
            cleanup_old_config_sections();
            save_config();
            return;
        }

        m_useZoneProfiles = ::GetPrivateProfileIntA("general", "use_zone_profiles", 0, m_configPath) != 0;
        load_global_profile(configVersion);
        save_config(false);
    }

    void load_global_profile(const int configVersion)
    {
        m_drawDistance = clamp_float(read_profile_float("draw", "distance", read_profile_float("draw", "world", default_draw_distance())), 1.0f, kMaxDrawDistance);
        if (configVersion < 8)
            m_drawDistance = default_draw_distance();
        m_lodMode = static_cast<LodMode>(::GetPrivateProfileIntA("lod", "mode", static_cast<int>(LodMode::High), m_configPath));
        m_lodRangeScale = clamp_float(read_profile_float("lod", "range_scale", 1.0f), kLodRangeMin, kLodRangeMax);
        const int rawFogMode = ::GetPrivateProfileIntA("fog", "mode", static_cast<int>(FogMode::Game), m_configPath);
        m_fogMode = parse_fog_mode(rawFogMode);
        m_fogStart = clamp_float(read_profile_float("fog", "start", kDefaultFogStart), 0.0f, kMaxFogDistance);
        m_fogEnd = clamp_float(read_profile_float("fog", "end", kDefaultFogEnd), m_fogStart + 1.0f, kMaxFogDistance);

        if (m_lodMode != LodMode::Off && m_lodMode != LodMode::High && m_lodMode != LodMode::Range)
            m_lodMode = LodMode::Range;
    }

    void save_config(const bool createZoneProfile = true)
    {
        char version[16]{};
        std::snprintf(version, sizeof(version), "%d", kConfigVersion);
        ::WritePrivateProfileStringA("general", "version", version, m_configPath);
        ::WritePrivateProfileStringA("general", "use_zone_profiles", m_useZoneProfiles ? "1" : "0", m_configPath);
        if (m_useZoneProfiles && m_currentZoneId != 0)
        {
            if (createZoneProfile || m_activeZoneHasProfile)
            {
                save_zone_profile(m_currentZoneId);
                m_activeZoneHasProfile = true;
                return;
            }
        }
        save_global_profile();
    }

    void save_global_profile()
    {
        ::WritePrivateProfileStringA("draw", "enabled", nullptr, m_configPath);
        ::WritePrivateProfileStringA("draw", "world", nullptr, m_configPath);
        ::WritePrivateProfileStringA("draw", "entity", nullptr, m_configPath);
        write_profile_float("draw", "distance", m_drawDistance);
        char lodMode[16]{};
        std::snprintf(lodMode, sizeof(lodMode), "%d", static_cast<int>(m_lodMode));
        ::WritePrivateProfileStringA("lod", "mode", lodMode, m_configPath);
        write_profile_float("lod", "range_scale", m_lodRangeScale);
        char mode[16]{};
        std::snprintf(mode, sizeof(mode), "%d", static_cast<int>(m_fogMode));
        ::WritePrivateProfileStringA("fog", "mode", mode, m_configPath);
        write_profile_float("fog", "start", m_fogStart);
        write_profile_float("fog", "end", m_fogEnd);
    }

    bool profile_section_exists(const char* section) const
    {
        char buffer[8]{};
        return ::GetPrivateProfileStringA(section, nullptr, "", buffer, sizeof(buffer), m_configPath) > 0;
    }

    void zone_section_name(const uint16_t zoneId, char* buffer, const size_t bufferSize) const
    {
        std::snprintf(buffer, bufferSize, "zone.%u", static_cast<unsigned int>(zoneId));
    }

    bool load_zone_profile(const uint16_t zoneId)
    {
        char section[32]{};
        zone_section_name(zoneId, section, sizeof(section));
        if (!profile_section_exists(section))
            return false;

        m_drawDistance = clamp_float(read_profile_float(section, "distance", m_drawDistance), 1.0f, kMaxDrawDistance);
        m_lodMode = static_cast<LodMode>(::GetPrivateProfileIntA(section, "lod_mode", static_cast<int>(m_lodMode == LodMode::Off ? LodMode::Range : m_lodMode), m_configPath));
        m_lodRangeScale = clamp_float(read_profile_float(section, "lod_range", m_lodRangeScale), kLodRangeMin, kLodRangeMax);
        const int rawFogMode = ::GetPrivateProfileIntA(section, "fog_mode", static_cast<int>(m_fogMode), m_configPath);
        m_fogMode = parse_fog_mode(rawFogMode);
        m_fogStart = clamp_float(read_profile_float(section, "fog_start", m_fogStart), 0.0f, kMaxFogDistance);
        m_fogEnd = clamp_float(read_profile_float(section, "fog_end", m_fogEnd), m_fogStart + 1.0f, kMaxFogDistance);
        if (m_lodMode != LodMode::Off && m_lodMode != LodMode::High && m_lodMode != LodMode::Range)
            m_lodMode = LodMode::Range;
        return true;
    }

    void save_zone_profile(const uint16_t zoneId)
    {
        char section[32]{};
        zone_section_name(zoneId, section, sizeof(section));
        write_profile_float(section, "distance", m_drawDistance);
        char lodMode[16]{};
        std::snprintf(lodMode, sizeof(lodMode), "%d", static_cast<int>(m_lodMode));
        ::WritePrivateProfileStringA(section, "lod_mode", lodMode, m_configPath);
        write_profile_float(section, "lod_range", m_lodRangeScale);
        char fogMode[16]{};
        std::snprintf(fogMode, sizeof(fogMode), "%d", static_cast<int>(m_fogMode));
        ::WritePrivateProfileStringA(section, "fog_mode", fogMode, m_configPath);
        write_profile_float(section, "fog_start", m_fogStart);
        write_profile_float(section, "fog_end", m_fogEnd);
    }

    void reset_config_to_defaults()
    {
        m_useZoneProfiles = false;
        m_activeZoneHasProfile = false;
        m_drawDistance = default_draw_distance();
        m_lodMode = LodMode::High;
        m_lodRangeScale = 1.0f;
        m_fogMode = FogMode::Game;
        m_fogStart = kDefaultFogStart;
        m_fogEnd = kDefaultFogEnd;
    }

    void cleanup_old_config_sections()
    {
        ::WritePrivateProfileStringA("distance", nullptr, nullptr, m_configPath);
        ::WritePrivateProfileStringA("draw", "enabled", nullptr, m_configPath);
        ::WritePrivateProfileStringA("draw", "world", nullptr, m_configPath);
        ::WritePrivateProfileStringA("draw", "entity", nullptr, m_configPath);
        ::WritePrivateProfileStringA("fog", "scale", nullptr, m_configPath);
    }

    float read_profile_float(const char* section, const char* key, const float fallback)
    {
        char text[64]{};
        char def[64]{};
        std::snprintf(def, sizeof(def), "%.3f", static_cast<double>(fallback));
        ::GetPrivateProfileStringA(section, key, def, text, sizeof(text), m_configPath);
        return std::strtof(text, nullptr);
    }

    void write_profile_float(const char* section, const char* key, const float value)
    {
        char text[64]{};
        std::snprintf(text, sizeof(text), "%.3f", static_cast<double>(value));
        ::WritePrivateProfileStringA(section, key, text, m_configPath);
    }

    void refresh_ffximain()
    {
        get_module_range("FFXiMain.dll", m_ffxiMainBase, m_ffxiMainSize);
    }

    bool refresh_drawdistance_pointers()
    {
        if (m_worldDistanceAddress != 0 && m_entityDistanceAddress != 0)
            return true;

        if (m_ffxiMainBase == 0 || m_ffxiMainSize == 0)
            refresh_ffximain();
        if (m_ffxiMainBase == 0)
            return false;

        const uint8_t signature[] = { 0x8B, 0xC1, 0x48, 0x74, 0x08, 0xD8, 0x0D };
        const uintptr_t found = find_bytes(m_ffxiMainBase, m_ffxiMainSize, signature, sizeof(signature));
        if (found == 0)
            return false;

        uint32_t worldPtr = 0;
        uint32_t entityPtr = 0;
        if (!safe_read(found + 0x07, worldPtr) || !safe_read(found + 0x0F, entityPtr))
            return false;

        m_worldDistanceAddress = worldPtr;
        m_entityDistanceAddress = entityPtr;
        return true;
    }

    bool apply_draw_distances()
    {
        if (!refresh_drawdistance_pointers())
            return false;

        capture_original_draw_distances();
        return safe_write(m_worldDistanceAddress, m_drawDistance) &&
            safe_write(m_entityDistanceAddress, m_drawDistance);
    }

    bool capture_original_draw_distances()
    {
        if (m_originalDrawCaptured)
            return true;
        if (!refresh_drawdistance_pointers())
            return false;
        if (!safe_read(m_worldDistanceAddress, m_originalWorldDistance) ||
            !safe_read(m_entityDistanceAddress, m_originalEntityDistance))
        {
            return false;
        }
        m_originalDrawCaptured = true;
        return true;
    }

    bool restore_draw_distances()
    {
        if (!m_originalDrawCaptured)
            return true;
        if (m_worldDistanceAddress == 0 || m_entityDistanceAddress == 0)
            return true;
        return safe_write(m_worldDistanceAddress, m_originalWorldDistance) &&
            safe_write(m_entityDistanceAddress, m_originalEntityDistance);
    }

    void sync_default_draw_distance()
    {
        if (!m_originalDrawCaptured)
            return;

        m_drawDistance = clamp_float(m_originalWorldDistance, 1.0f, kMaxDrawDistance);
    }

    void capture_original_fog_start(const float value)
    {
        if (value < 0.0f || value > 100000.0f)
            return;

        m_originalFogStart = clamp_float(value, 0.0f, kMaxFogDistance);
        m_originalFogStartCaptured = true;
        if (m_gameFogSampling && m_fogMode == FogMode::Game)
        {
            m_fogStart = m_originalFogStart;
            m_gameFogSawStart = true;
            if (m_gameFogSawEnd)
                m_fogEnd = clamp_float(m_fogEnd, m_fogStart + 1.0f, kMaxFogDistance);
            return;
        }
        if (m_fogMode == FogMode::DistanceLinked)
            m_fogStart = m_originalFogStart;
    }

    void capture_original_fog_end(const float value)
    {
        if (value < 0.0f || value > 100000.0f)
            return;

        m_originalFogEnd = clamp_float(value, 1.0f, kMaxFogDistance);
        m_originalFogEndCaptured = true;
        if (m_gameFogSampling && m_fogMode == FogMode::Game)
        {
            m_fogEnd = clamp_float(m_originalFogEnd, m_fogStart + 1.0f, kMaxFogDistance);
            m_gameFogSawEnd = true;
            return;
        }
        if (m_fogMode == FogMode::DistanceLinked)
            m_fogEnd = clamp_float(m_originalFogEnd, m_fogStart + 1.0f, kMaxFogDistance);
    }

    void sync_default_fog_range()
    {
        if (m_originalFogStartCaptured)
            m_fogStart = m_originalFogStart;
        if (m_originalFogEndCaptured)
            m_fogEnd = clamp_float(m_originalFogEnd, m_fogStart + 1.0f, kMaxFogDistance);
    }

    void restore_fog_state()
    {
        if (m_device == nullptr)
            return;

        m_applyingForcedFogState = true;
        if (m_originalFogStartCaptured)
            m_device->SetRenderState(D3DRS_FOGSTART, float_to_dword(m_originalFogStart));
        if (m_originalFogEndCaptured)
            m_device->SetRenderState(D3DRS_FOGEND, float_to_dword(m_originalFogEnd));
        m_applyingForcedFogState = false;
    }

    void reset_game_fog_sample(const bool syncFromOriginal)
    {
        m_gameFogSampling = false;
        m_gameFogSawStart = false;
        m_gameFogSawEnd = false;
        if (syncFromOriginal)
            sync_default_fog_range();
    }

    void begin_game_fog_sample(const bool isRenderingBackBuffer)
    {
        if (!isRenderingBackBuffer || m_fogMode != FogMode::Game || m_gameFogSampling)
            return;

        if (!capture_original_draw_distances())
            return;
        if (!restore_draw_distances())
            return;

        m_gameFogSampling = true;
        m_gameFogSawStart = false;
        m_gameFogSawEnd = false;
    }

    void finish_game_fog_sample()
    {
        if (!m_gameFogSampling)
            return;

        m_gameFogSampling = false;
        apply_draw_distances();
    }

    void finish_game_fog_sample_if_ready()
    {
        if (m_gameFogSampling && m_gameFogSawStart && m_gameFogSawEnd)
            finish_game_fog_sample();
    }

    void apply_fog_state_before_draw()
    {
        finish_game_fog_sample();
        apply_forced_fog_state();
    }

    void apply_forced_fog_state()
    {
        if (m_device == nullptr || !should_force_fog_state() || m_applyingForcedFogState)
            return;

        struct ShaderFogConstant
        {
            float scale;
            float unused0;
            float end;
            float unused1;
        };

        const float range = std::max(m_fogEnd - m_fogStart, 1.0f);
        const ShaderFogConstant shaderFog{ 1.0f / range, 0.0f, m_fogEnd, 0.0f };

        m_applyingForcedFogState = true;
        m_device->SetRenderState(D3DRS_FOGSTART, float_to_dword(m_fogStart));
        m_device->SetRenderState(D3DRS_FOGEND, float_to_dword(m_fogEnd));
        m_device->SetRenderState(D3DRS_FOGVERTEXMODE, D3DFOG_LINEAR);
        m_device->SetRenderState(D3DRS_FOGTABLEMODE, D3DFOG_NONE);
        m_device->SetRenderState(D3DRS_RANGEFOGENABLE, FALSE);
        m_device->SetVertexShaderConstant(9, &shaderFog, 1);
        m_applyingForcedFogState = false;
    }

    void restore_default_runtime()
    {
        finish_game_fog_sample();
        reset_config_to_defaults();
        apply_draw_distances();
        apply_lod_mode();
        apply_active_fog_mode();
    }

    uint16_t get_current_zone() const
    {
        if (m_core == nullptr || m_core->GetMemoryManager() == nullptr || m_core->GetMemoryManager()->GetParty() == nullptr)
            return 0;
        return m_core->GetMemoryManager()->GetParty()->GetMemberZone(0);
    }

    void update_current_zone()
    {
        const uint16_t zoneId = get_current_zone();
        if (zoneId != 0)
            m_currentZoneId = zoneId;
    }

    void load_active_profile()
    {
        load_global_profile(kConfigVersion);
        m_activeZoneHasProfile = false;
        if (m_useZoneProfiles && m_currentZoneId != 0)
            m_activeZoneHasProfile = load_zone_profile(m_currentZoneId);
    }

    void apply_loaded_profile()
    {
        apply_draw_distances();
        apply_lod_mode();
        apply_active_fog_mode();
    }

    void update_zone_profile()
    {
        const uint16_t zoneId = get_current_zone();
        if (zoneId == 0 || zoneId == m_currentZoneId)
            return;

        if (m_useZoneProfiles && m_currentZoneId != 0 && m_activeZoneHasProfile)
            save_zone_profile(m_currentZoneId);

        m_currentZoneId = zoneId;
        if (m_useZoneProfiles)
        {
            load_active_profile();
            apply_loaded_profile();
        }
    }

    void set_zone_profiles_enabled(const bool enabled)
    {
        if (m_useZoneProfiles == enabled)
            return;

        update_current_zone();
        if (m_useZoneProfiles && m_currentZoneId != 0)
            save_zone_profile(m_currentZoneId);
        if (!m_useZoneProfiles)
            save_global_profile();

        m_useZoneProfiles = enabled;
        if (m_useZoneProfiles && m_currentZoneId != 0)
        {
            load_active_profile();
            apply_loaded_profile();
        }
        else
        {
            load_global_profile(kConfigVersion);
            m_activeZoneHasProfile = false;
            apply_loaded_profile();
        }
        save_config(false);
    }

    bool apply_lod_mode()
    {
        restore_lod_patches();
        if (m_lodMode == LodMode::Off)
            return true;
        if (m_lodMode == LodMode::High)
            return install_lod_high();
        if (m_lodMode == LodMode::Range)
            return install_lod_range();
        return true;
    }

    bool install_lod_high()
    {
        if (m_lodPatchSites[0].patched && m_lodPatchSites[1].patched)
            return true;

        if (m_ffxiMainBase == 0 || m_ffxiMainSize == 0)
            refresh_ffximain();
        if (m_ffxiMainBase == 0)
            return false;

        const uintptr_t site0 = m_ffxiMainBase + 0x0017B63A;
        const uintptr_t site1 = m_ffxiMainBase + 0x0017CAAF;
        const uint8_t expected0[] = { 0x75, 0x05 };
        const uint8_t expected1[] = { 0x75, 0x09 };
        const uint8_t patch0[] = { 0xEB, 0x1D };
        const uint8_t patch1[] = { 0xEB, 0x25 };

        if (!bytes_match(site0, expected0, sizeof(expected0)) ||
            !bytes_match(site1, expected1, sizeof(expected1)))
        {
            return false;
        }

        if (!write_bytes_patch(m_lodPatchSites[0], site0, patch0, sizeof(patch0)))
            return false;
        if (!write_bytes_patch(m_lodPatchSites[1], site1, patch1, sizeof(patch1)))
        {
            restore_patch(m_lodPatchSites[0]);
            return false;
        }
        return true;
    }

    bool install_lod_range()
    {
        if (m_lodRangePatchSites[0].patched && m_lodRangePatchSites[1].patched &&
            m_lodRangePatchSites[2].patched && m_lodRangePatchSites[3].patched)
        {
            g_lodRangeScaleSq = m_lodRangeScale * m_lodRangeScale;
            return true;
        }

        if (m_ffxiMainBase == 0 || m_ffxiMainSize == 0)
            refresh_ffximain();
        if (m_ffxiMainBase == 0)
            return false;

        g_lodRangeScaleSq = m_lodRangeScale * m_lodRangeScale;

        const uintptr_t sites[] = {
            m_ffxiMainBase + 0x0017B629,
            m_ffxiMainBase + 0x0017B641,
            m_ffxiMainBase + 0x0017CA9E,
            m_ffxiMainBase + 0x0017CABA,
        };
        const uintptr_t returns[] = {
            m_ffxiMainBase + 0x0017B633,
            m_ffxiMainBase + 0x0017B64B,
            m_ffxiMainBase + 0x0017CAA8,
            m_ffxiMainBase + 0x0017CAC4,
        };
        void* hooks[] = {
            reinterpret_cast<void*>(&vanaview_lod_range0_hook),
            reinterpret_cast<void*>(&vanaview_lod_range1_hook),
            reinterpret_cast<void*>(&vanaview_lod_range2_hook),
            reinterpret_cast<void*>(&vanaview_lod_range3_hook),
        };
        const uint8_t expected[][10] = {
            { 0xD9, 0x44, 0x24, 0x14, 0xD8, 0x99, 0xCC, 0x00, 0x00, 0x00 },
            { 0xD9, 0x44, 0x24, 0x14, 0xD8, 0x99, 0xC8, 0x00, 0x00, 0x00 },
            { 0xD9, 0x44, 0x24, 0x58, 0xD8, 0x9F, 0xCC, 0x00, 0x00, 0x00 },
            { 0xD9, 0x44, 0x24, 0x58, 0xD8, 0x9F, 0xC8, 0x00, 0x00, 0x00 },
        };

        g_lodRangeReturn0 = returns[0];
        g_lodRangeReturn1 = returns[1];
        g_lodRangeReturn2 = returns[2];
        g_lodRangeReturn3 = returns[3];

        for (int i = 0; i < 4; ++i)
        {
            if (!bytes_match(sites[i], expected[i], sizeof(expected[i])))
                return false;
        }

        for (int i = 0; i < 4; ++i)
        {
            if (!write_jump_patch(m_lodRangePatchSites[i], sites[i], hooks[i], sizeof(expected[i])))
            {
                restore_lod_patches();
                return false;
            }
        }

        return true;
    }

    bool restore_lod_patches()
    {
        const bool a = restore_patch(m_lodPatchSites[0]);
        const bool b = restore_patch(m_lodPatchSites[1]);
        bool range = true;
        for (auto& site : m_lodRangePatchSites)
            range = restore_patch(site) && range;
        return a && b && range;
    }

    IAshitaCore* m_core = nullptr;
    IDirect3DDevice8* m_device = nullptr;
    uintptr_t m_ffxiMainBase = 0;
    uint32_t m_ffxiMainSize = 0;
    uintptr_t m_worldDistanceAddress = 0;
    uintptr_t m_entityDistanceAddress = 0;
    bool m_originalDrawCaptured = false;
    float m_originalWorldDistance = 0.0f;
    float m_originalEntityDistance = 0.0f;
    BytesPatchSite m_lodPatchSites[2]{};
    BytesPatchSite m_lodRangePatchSites[4]{};
    float m_drawDistance = default_draw_distance();
    enum class LodMode : int
    {
        Off = 0,
        High = 1,
        Range = 2,
    };
    LodMode m_lodMode = LodMode::High;
    float m_lodRangeScale = 1.0f;
    FogMode m_fogMode = FogMode::Game;
    float m_fogStart = kDefaultFogStart;
    float m_fogEnd = kDefaultFogEnd;
    bool m_originalFogStartCaptured = false;
    bool m_originalFogEndCaptured = false;
    float m_originalFogStart = kDefaultFogStart;
    float m_originalFogEnd = kDefaultFogEnd;
    bool m_applyingForcedFogState = false;
    bool m_gameFogSampling = false;
    bool m_gameFogSawStart = false;
    bool m_gameFogSawEnd = false;
    bool m_activeZoneHasProfile = false;
    bool m_useZoneProfiles = false;
    uint16_t m_currentZoneId = 0;
    bool m_windowOpen = false;
    char m_configPath[MAX_PATH]{};
};

extern "C" __declspec(dllexport) double __stdcall expGetInterfaceVersion(void)
{
    return ASHITA_INTERFACE_VERSION;
}

extern "C" __declspec(dllexport) IPlugin* __stdcall expCreatePlugin(const char*)
{
    return new VanaView();
}
