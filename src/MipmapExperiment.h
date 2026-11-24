#pragma once

#include "AutoColorMipmaps.h"

#include <wrl/client.h>
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

// Scoped draw substitution for precomputed DXT3 pairs or automatic color mips.
class MipmapExperiment
{
    template<class T> using ComPtr = Microsoft::WRL::ComPtr<T>;

    struct Chain
    {
        UINT width = 0, height = 0, levels = 0;
        std::vector<uint8_t> data;
        ComPtr<IDirect3DTexture8> texture;
    };

    struct Pair { Chain color, detail; };
    struct Match
    {
        ComPtr<IDirect3DBaseTexture8> original;
        uint64_t frame = 0;
        bool same = false;
    };

public:
    enum class Mode { Off, Color, Pair, Auto };
    struct Stats
    {
        uint64_t frames = 0, color = 0, detail = 0, checks = 0;
        uint64_t failures = 0, smooth = 0, blend = 0, blendDetail = 0, linear = 0, linearDetail = 0;
    };

    Mode mode() const { return m_mode; }
    const Stats& stats() const { return m_stats; }
    size_t pairs() const { return m_pairs.size(); }
    const AutoColorMipmaps& automatic() const { return m_auto; }
    void set_disk_directory(std::filesystem::path path) { m_auto.set_disk_directory(std::move(path)); }
    void zone_changed() { m_auto.clear(); }
    bool paused() const { return m_paused; }
    bool detail_enabled() const { return m_autoDetail; }
    bool smoothing() const { return m_smooth; }
    bool blend_enabled() const { return m_autoBlend; }
    bool linear_enabled() const { return m_linear; }

    bool set_linear(IDirect3DDevice8* device, bool enable)
    {
        if (m_mode != Mode::Auto) return false;
        D3DCAPS8 caps{};
        if (enable && (!device || FAILED(device->GetDeviceCaps(&caps)) ||
                       !(caps.TextureFilterCaps & D3DPTFILTERCAPS_MINFLINEAR))) return false;
        m_linear = enable;
        return true;
    }

    bool set_blend(bool enable)
    {
        if (m_mode != Mode::Auto) return false;
        m_autoBlend = enable;
        return true;
    }

    bool set_smoothing(IDirect3DDevice8* device, bool enable)
    {
        if (m_mode != Mode::Auto) return false;
        D3DCAPS8 caps{};
        if (enable && (!device || FAILED(device->GetDeviceCaps(&caps)) || !(caps.RasterCaps & D3DPRASTERCAPS_MIPMAPLODBIAS)))
            return false;
        m_smooth = enable;
        return true;
    }

    bool set_detail(bool enable)
    {
        if (m_mode != Mode::Auto) return false;
        if (!enable) m_auto.cancel_detail();
        m_autoDetail = enable;
        return true;
    }

    bool set_paused(bool paused)
    {
        if (m_mode != Mode::Auto) return false;
        if (paused && !m_paused) m_auto.cancel_pending();
        m_paused = paused;
        return true;
    }

    void set_cache_only(bool enabled) { m_cacheOnly = enabled; }

    void stop()
    {
        m_mode = Mode::Off;
        m_paused = false;
        m_cacheOnly = false;
        m_autoDetail = false;
        m_smooth = false;
        m_autoBlend = false;
        m_linear = false;
        m_pairs.clear();
        m_matches = {};
        m_misses = {};
        m_checksThisFrame = 0;
        m_auto.clear();
    }

    bool start_ground_mipmaps(IDirect3DDevice8* device, std::string& message)
    {
        if (m_mode != Mode::Auto && !start(device, {}, Mode::Auto, message)) return false;
        set_paused(false);
        set_smoothing(device, false);
        set_detail(true);
        set_blend(true);
        message = set_linear(device, true)
            ? "Ground mipmaps enabled with linear filtering."
            : "Ground mipmaps enabled. The device does not support linear minification.";
        return true;
    }

    bool start(IDirect3DDevice8* device, const std::filesystem::path& folder, Mode mode, std::string& message)
    {
        if (mode == Mode::Auto) {
            if (!device || !is_native_draw(device, message)) return false;
            stop();
            m_auto.start();
            m_stats = {};
            m_mode = Mode::Auto;
            message = "Automatic color mipmaps enabled.";
            return true;
        }
        if (m_mode == Mode::Auto) stop();
        // Change mode in place for a second A/B pass. Chains are uploaded only once.
        if (m_mode != Mode::Off) {
            m_mode = mode;
            m_stats = {};
            m_matches = {};
            m_misses = {};
            m_checksThisFrame = 0;
            message = "Mipmap experiment enabled.";
            return true;
        }
        if (!device || !is_native_draw(device, message)) return false;

        std::vector<Pair> pairs;
        for (const auto& entry : std::filesystem::directory_iterator(folder)) {
            if (!entry.is_regular_file()) continue;
            const auto name = entry.path().filename().wstring();
            constexpr wchar_t suffix[] = L"-color.dds";
            if (!name.ends_with(suffix)) continue;
            if (pairs.size() >= MaxPairs) {
                message = "Too many DDS pairs (limit: 4).";
                return false;
            }
            const auto prefix = name.substr(0, name.size() - (std::size(suffix) - 1));
            Pair pair;
            if (!load_chain(device, entry.path(), pair.color) ||
                !load_chain(device, folder / (prefix + L"-detail.dds"), pair.detail)) {
                message = "Could not load a complete DXT3 color/detail pair. Check DDS files and D3D support.";
                return false;
            }
            for (const auto& existing : pairs) {
                if (existing.color.width == pair.color.width && existing.color.height == pair.color.height &&
                    existing.color.data == pair.color.data) {
                    message = "DDS pairs must have distinct level-zero color textures.";
                    return false;
                }
            }
            pairs.push_back(std::move(pair));
        }
        if (pairs.empty()) {
            message = "No DDS pairs in plugins/VanaView-mips.";
            return false;
        }
        m_pairs = std::move(pairs);
        m_stats = {};
        m_mode = mode;
        message = "Mipmap experiment enabled.";
        return true;
    }

    void present(IDirect3DDevice8* device)
    {
        if (m_mode == Mode::Off) return;
        ++m_stats.frames;
        m_checksThisFrame = 0;
        if (m_mode == Mode::Auto) m_auto.present(device);
    }

    bool draw(IDirect3DDevice8* device, D3DPRIMITIVETYPE type, UINT startVertex, UINT count)
    {
        if (m_mode == Mode::Off || m_paused || m_inDraw ||
            (type != D3DPT_TRIANGLELIST && !(m_mode == Mode::Auto && type == D3DPT_TRIANGLESTRIP))) return false;
        ComPtr<IDirect3DBaseTexture8> color;
        if (FAILED(device->GetTexture(0, color.GetAddressOf())) || !color) return false;
        if (m_mode == Mode::Auto) {
            const auto selected = m_auto.select(device, type, color.Get(), m_cacheOnly, m_autoDetail, m_autoBlend);
            if (!selected.texture) return false;
            const auto start = selected.firstUse ? AutoColorMipmaps::Clock::now() : AutoColorMipmaps::Clock::time_point{};
            const bool drawn = replace_draw(device, type, startVertex, count, color.Get(), selected.texture,
                                            selected.originalDetail, selected.detail);
            if (selected.firstUse) m_auto.finish_first_use(color.Get(), start, drawn, selected.detail != nullptr);
            if (drawn) {
                if (selected.blended) {
                    ++m_stats.blend;
                    if (selected.detail) ++m_stats.blendDetail;
                }
            }
            return drawn;
        }

        // Short negative cache avoids repeated locks on unrelated textures.
        // Positive matches retain a reference and are checked again next frame.
        auto& miss = m_misses[(reinterpret_cast<uintptr_t>(color.Get()) >> 4) % m_misses.size()];
        if (miss.texture == color.Get() && miss.retryFrame > m_stats.frames) return false;
        size_t i = 0;
        for (; i < m_pairs.size(); ++i) {
            if (matches(color.Get(), m_pairs[i].color, m_matches[i][0])) break;
        }
        if (i == m_pairs.size()) {
            const auto delay = m_checksThisFrame >= MaxChecksPerFrame ? 1u : 60u;
            miss = {color.Get(), m_stats.frames + delay};
            return false;
        }

        if (!AutoColorMipmaps::opaque_shader(device)) return false;

        auto& pair = m_pairs[i];
        ComPtr<IDirect3DBaseTexture8> detail;
        if (FAILED(device->GetTexture(1, detail.GetAddressOf())) ||
            !matches(detail.Get(), pair.detail, m_matches[i][1])) return false;

        return replace_draw(device, type, startVertex, count, color.Get(), pair.color.texture.Get(),
                            detail.Get(), m_mode == Mode::Pair ? pair.detail.texture.Get() : nullptr);
    }

private:
    // A draw may change stage 0's bias and each replaced stage's min filter.
    // Record a state before writing so even a failed setter can be rolled back.
    struct SamplerEdits
    {
        struct State { DWORD stage; D3DTEXTURESTAGESTATETYPE name; DWORD original; };
        std::array<State, 3> saved;
        size_t count = 0;

        bool write(IDirect3DDevice8* device, DWORD stage, D3DTEXTURESTAGESTATETYPE name, DWORD original, DWORD value)
        {
            saved[count++] = {stage, name, original};
            return SUCCEEDED(device->SetTextureStageState(stage, name, value));
        }

        bool restore(IDirect3DDevice8* device)
        {
            bool ok = true;
            while (count) {
                const auto& state = saved[--count];
                if (FAILED(device->SetTextureStageState(state.stage, state.name, state.original))) ok = false;
            }
            return ok;
        }
    };

    static bool linear_min(IDirect3DDevice8* device, DWORD stage, SamplerEdits& edits, bool& changed)
    {
        DWORD filter = 0;
        if (FAILED(device->GetTextureStageState(stage, D3DTSS_MINFILTER, &filter))) return false;
        if (filter != D3DTEXF_POINT) return true;
        changed = edits.write(device, stage, D3DTSS_MINFILTER, filter, D3DTEXF_LINEAR);
        return changed;
    }

    bool replace_draw(IDirect3DDevice8* device, D3DPRIMITIVETYPE type, UINT startVertex, UINT count,
                      IDirect3DBaseTexture8* color, IDirect3DTexture8* replacement,
                      IDirect3DBaseTexture8* detail = nullptr, IDirect3DTexture8* detailReplacement = nullptr)
    {
        if (FAILED(device->SetTexture(0, replacement))) {
            ++m_stats.failures;
            return false;
        }
        const bool useDetail = detailReplacement != nullptr;
        if (useDetail && FAILED(device->SetTexture(1, detailReplacement))) {
            ++m_stats.failures;
            restore(device, color, detail, true);
            return false;
        }

        SamplerEdits edits;
        bool setupOk = true, biased = false, linearColor = false, linearDetail = false;
        if (m_smooth) {
            DWORD savedBias = 0;
            if (FAILED(device->GetTextureStageState(0, D3DTSS_MIPMAPLODBIAS, &savedBias))) {
                setupOk = false;
            } else {
                const float original = std::bit_cast<float>(savedBias);
                const float coarser = original + 0.5f;
                if (std::isfinite(original) && std::isfinite(coarser) && coarser != original) {
                    biased = setupOk = edits.write(device, 0, D3DTSS_MIPMAPLODBIAS,
                                                   savedBias, std::bit_cast<DWORD>(coarser));
                }
            }
            if (!setupOk) m_smooth = false;
        }
        if (setupOk && m_linear) {
            setupOk = linear_min(device, 0, edits, linearColor) &&
                (!useDetail || linear_min(device, 1, edits, linearDetail));
            if (!setupOk) m_linear = false;
        }
        if (!setupOk) {
            ++m_stats.failures;
            biased = linearColor = linearDetail = false;
            if (!edits.restore(device)) {
                restore(device, color, detail, useDetail);
                stop();
                return false;
            }
        }

        m_inDraw = true;
        const HRESULT hr = device->DrawPrimitive(type, startVertex, count);
        m_inDraw = false;
        const bool samplerRestored = edits.restore(device);
        restore(device, color, detail, useDetail);
        if (!samplerRestored) {
            ++m_stats.failures;
            stop();
        }
        if (FAILED(hr)) {
            ++m_stats.failures;
            return false;
        }
        ++m_stats.color;
        if (useDetail) ++m_stats.detail;
        if (biased) ++m_stats.smooth;
        if (linearColor || linearDetail) ++m_stats.linear;
        if (linearDetail) ++m_stats.linearDetail;
        return true; // Already rendered. Ashita must skip the original call.
    }

    static constexpr size_t MaxPairs = 4;
    static constexpr uintmax_t MaxDdsBytes = 384 * 1024;
    static constexpr unsigned MaxChecksPerFrame = 16;
    struct Miss { IDirect3DBaseTexture8* texture = nullptr; uint64_t retryFrame = 0; };

    static bool is_native_draw(IDirect3DDevice8* device, std::string& message)
    {
        // IDirect3DDevice8 SDK vtable, including the 3 IUnknown slots.
        constexpr size_t DrawPrimitiveSlot = 70;
        const auto vtable = *reinterpret_cast<void***>(device);
        const auto entry = reinterpret_cast<LPCWSTR>(vtable[DrawPrimitiveSlot]);
        HMODULE owner = nullptr;
        wchar_t path[MAX_PATH]{};
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, entry, &owner) &&
            GetModuleFileNameW(owner, path, MAX_PATH)) {
            const auto name = std::filesystem::path(path).filename().wstring();
            if (_wcsicmp(name.c_str(), L"d3d8.dll") == 0) return true;
            message = "Mipmap experiment requires the underlying D3D8 device. Draw module: " +
                std::filesystem::path(path).filename().string();
            return false;
        }
        message = "Could not identify the D3D8 draw module.";
        return false;
    }

    static bool load_chain(IDirect3DDevice8* device, const std::filesystem::path& path, Chain& out)
    {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file || file.tellg() < 128 || file.tellg() > static_cast<std::streamoff>(MaxDdsBytes)) return false;
        const auto size = static_cast<size_t>(file.tellg());
        file.seekg(0);
        uint32_t header[32]{};
        if (!file.read(reinterpret_cast<char*>(header), sizeof(header))) return false;
        const UINT width = header[4], height = header[3], levels = header[7];
        const auto supported = [](UINT n) { return n > 0 && n <= 512 && (n & (n - 1)) == 0; };
        if (header[0] != MAKEFOURCC('D','D','S',' ') || header[1] != 124 ||
            (header[2] & 0x20000) == 0 || header[6] || header[28] ||
            header[19] != 32 || header[20] != 4 || header[21] != D3DFMT_DXT3 ||
            !supported(width) || !supported(height) || levels < 2) return false;
        const Dxt3::Layout layout(width, height);
        if (levels != layout.levels || layout.bytes != size - sizeof(header)) return false;
        out.width = width;
        out.height = height;
        out.levels = levels;
        out.data.resize(layout.bytes);
        if (!file.read(reinterpret_cast<char*>(out.data.data()), layout.bytes) ||
            !Dxt3::upload(device, layout, out.data.data(), out.texture)) return false;
        // Keep only level zero in CPU memory for content matching.
        out.data.resize(layout.top_bytes());
        out.data.shrink_to_fit();
        return true;
    }

    bool matches(IDirect3DBaseTexture8* base, const Chain& chain, Match& match)
    {
        if (!base) return false;
        if (match.original.Get() == base && match.frame == m_stats.frames) return match.same;
        D3DSURFACE_DESC desc{};
        if (!Dxt3::describe(base, desc) || desc.Width != chain.width || desc.Height != chain.height)
            return false;
        if (m_checksThisFrame >= MaxChecksPerFrame) return false;
        ++m_checksThisFrame;
        ++m_stats.checks;
        bool same = true;
        const size_t rowBytes = Dxt3::pitch(desc.Width);
        if (!Dxt3::visit_top(base, desc.Width, [&](const auto* data, size_t stride) {
            for (UINT row = 0; same && row < Dxt3::rows(desc.Height); ++row)
                same = std::memcmp(data + row * stride, chain.data.data() + row * rowBytes, rowBytes) == 0;
        })) {
            ++m_stats.failures;
            return false;
        }
        if (same || match.original.Get() == base) {
            match.original = base;
            match.frame = m_stats.frames;
            match.same = same;
        }
        return same;
    }

    void restore(IDirect3DDevice8* device, IDirect3DBaseTexture8* color, IDirect3DBaseTexture8* detail, bool usedDetail)
    {
        const HRESULT detailResult = usedDetail ? device->SetTexture(1, detail) : S_OK;
        if (FAILED(device->SetTexture(0, color)) || FAILED(detailResult)) {
            ++m_stats.failures;
            stop();
        }
    }

    Mode m_mode = Mode::Off;
    bool m_paused = false, m_cacheOnly = false, m_autoDetail = false, m_smooth = false, m_autoBlend = false, m_linear = false;
    Stats m_stats;
    bool m_inDraw = false;
    unsigned m_checksThisFrame = 0;
    std::vector<Pair> m_pairs;
    std::array<std::array<Match, 2>, MaxPairs> m_matches;
    std::array<Miss, 128> m_misses;
    AutoColorMipmaps m_auto;
};
