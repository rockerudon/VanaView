#pragma once

#include <array>
#include <cstring>
#include <optional>

// Remember values from the game's SetRenderState calls before overriding them.
// The Ashita 4.30 SDK has no callback for a write to the shader constant.
class FogDeviceState
{
public:
    enum Index { Start, End, VertexMode, TableMode, RangeEnable };
    using Constant = std::array<float, 4>;

    void observe(Index index, DWORD value) { m_original[index] = value; }

    void apply(IDirect3DDevice8* device, DWORD start, DWORD end, const Constant& shader)
    {
        before_apply(device);
        const DWORD desired[] = {start, end, D3DFOG_LINEAR, D3DFOG_NONE, FALSE};
        for (size_t i = 0; i < States.size(); ++i) {
            DWORD live = 0;
            if (SUCCEEDED(device->GetRenderState(States[i], &live)) && live == desired[i]) continue;
            device->SetRenderState(States[i], desired[i]);
        }
        apply_shader(device, shader);
    }

    void restore(IDirect3DDevice8* device)
    {
        for (size_t i = 0; i < States.size(); ++i)
            if (m_original[i]) device->SetRenderState(States[i], *m_original[i]);

        Constant live{};
        if (m_originalShader && m_appliedShader &&
            SUCCEEDED(device->GetVertexShaderConstant(9, live.data(), 1)) && same_constant(live, *m_appliedShader)) {
            device->SetVertexShaderConstant(9, m_originalShader->data(), 1);
        }
        m_captured = false;
        m_appliedShader.reset();
    }

private:
    void before_apply(IDirect3DDevice8* device)
    {
        if (m_captured) return;
        for (size_t i = 0; i < States.size(); ++i) {
            DWORD value = 0;
            if (!m_original[i] && SUCCEEDED(device->GetRenderState(States[i], &value)))
                m_original[i] = value;
        }
        Constant value{};
        if (SUCCEEDED(device->GetVertexShaderConstant(9, value.data(), 1))) m_originalShader = value;
        else m_originalShader.reset();
        m_captured = true;
    }

    static bool same_constant(const Constant& a, const Constant& b)
    {
        return std::memcmp(a.data(), b.data(), a.size() * sizeof(float)) == 0;
    }

    void apply_shader(IDirect3DDevice8* device, const Constant& value)
    {
        // The game can rewrite c9 within the same scene and shader. Read the
        // device value instead of assuming the previous write is still live.
        Constant live{};
        if (SUCCEEDED(device->GetVertexShaderConstant(9, live.data(), 1))) {
            if (same_constant(live, value)) return;
            if (!m_appliedShader || !same_constant(live, *m_appliedShader)) m_originalShader = live;
        }
        if (SUCCEEDED(device->SetVertexShaderConstant(9, value.data(), 1))) m_appliedShader = value;
    }

    static constexpr std::array States{D3DRS_FOGSTART, D3DRS_FOGEND, D3DRS_FOGVERTEXMODE,
                                       D3DRS_FOGTABLEMODE, D3DRS_RANGEFOGENABLE};
    std::array<std::optional<DWORD>, States.size()> m_original{};
    std::optional<Constant> m_originalShader, m_appliedShader;
    bool m_captured = false;
};
