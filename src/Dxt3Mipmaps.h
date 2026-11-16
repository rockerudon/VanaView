#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>
#include <wrl/client.h>

namespace Dxt3
{
    using Texture = Microsoft::WRL::ComPtr<IDirect3DTexture8>;
    using Pixel = std::array<uint8_t, 4>;

    inline constexpr size_t pitch(UINT width) { return ((width + 3) / 4) * 16; }
    inline constexpr UINT rows(UINT height) { return (height + 3) / 4; }

    struct Layout
    {
        UINT width, height;
        UINT levels = 0;
        size_t bytes = 0;

        constexpr Layout(UINT w, UINT h) : width(w), height(h)
        {
            for (;; w = std::max(1u, w / 2), h = std::max(1u, h / 2)) {
                ++levels;
                bytes += pitch(w) * rows(h);
                if (w == 1 && h == 1) break;
            }
        }

        constexpr size_t top_bytes() const { return pitch(width) * rows(height); }
        size_t level_bytes(UINT level) const
        {
            return pitch(std::max(1u, width >> level)) * rows(std::max(1u, height >> level));
        }
    };

    inline bool describe(IDirect3DBaseTexture8* base, D3DSURFACE_DESC& desc)
    {
        if (!base || base->GetType() != D3DRTYPE_TEXTURE || base->GetLevelCount() != 1) return false;
        return SUCCEEDED(static_cast<IDirect3DTexture8*>(base)->GetLevelDesc(0, &desc)) &&
            desc.Format == D3DFMT_DXT3 && desc.Pool == D3DPOOL_MANAGED && desc.Usage == 0 && base->GetLOD() == 0;
    }

    inline bool create(IDirect3DDevice8* device, const Layout& layout, Texture& texture)
    {
        return SUCCEEDED(device->CreateTexture(layout.width, layout.height, layout.levels, 0, D3DFMT_DXT3,
                                               D3DPOOL_MANAGED, texture.GetAddressOf())) &&
            texture && texture->GetLevelCount() == layout.levels;
    }

    inline bool upload_level(IDirect3DTexture8* texture, const Layout& layout, UINT level, const uint8_t* data)
    {
        const size_t stride = pitch(std::max(1u, layout.width >> level));
        const UINT count = rows(std::max(1u, layout.height >> level));
        D3DLOCKED_RECT lock{};
        if (FAILED(texture->LockRect(level, &lock, nullptr, 0))) return false;
        const bool valid = lock.pBits && lock.Pitch >= static_cast<INT>(stride);
        if (valid) {
            for (UINT row = 0; row < count; ++row)
                std::memcpy(static_cast<uint8_t*>(lock.pBits) + row * lock.Pitch, data + row * stride, stride);
        }
        return SUCCEEDED(texture->UnlockRect(level)) && valid;
    }

    inline bool upload(IDirect3DDevice8* device, const Layout& layout, const uint8_t* data, Texture& texture)
    {
        if (!create(device, layout, texture)) return false;
        for (UINT level = 0; level < layout.levels; ++level) {
            if (!upload_level(texture.Get(), layout, level, data)) return false;
            data += layout.level_bytes(level);
        }
        return true;
    }

    // A managed texture remains locked only during the bounded copy/compare/sample.
    template<class Visit>
    bool visit_top(IDirect3DBaseTexture8* base, UINT width, Visit visit)
    {
        auto* texture = static_cast<IDirect3DTexture8*>(base);
        D3DLOCKED_RECT lock{};
        if (FAILED(texture->LockRect(0, &lock, nullptr, D3DLOCK_READONLY))) return false;
        const bool valid = lock.pBits && lock.Pitch >= static_cast<INT>(pitch(width));
        if (valid) visit(static_cast<const uint8_t*>(lock.pBits), static_cast<size_t>(lock.Pitch));
        return SUCCEEDED(texture->UnlockRect(0)) && valid;
    }

    inline Pixel rgb565(uint16_t value)
    {
        const unsigned r = value >> 11, g = (value >> 5) & 63, b = value & 31;
        return {static_cast<uint8_t>((r << 3) | (r >> 2)),
                static_cast<uint8_t>((g << 2) | (g >> 4)),
                static_cast<uint8_t>((b << 3) | (b >> 2)), 0};
    }

    inline std::array<Pixel, 4> color_palette(uint16_t a, uint16_t b)
    {
        const auto x = rgb565(a), y = rgb565(b);
        std::array<Pixel, 4> colors{x, y, {}, {}};
        for (unsigned c = 0; c < 3; ++c) {
            colors[2][c] = static_cast<uint8_t>((2 * x[c] + y[c]) / 3);
            colors[3][c] = static_cast<uint8_t>((x[c] + 2 * y[c]) / 3);
        }
        return colors;
    }

    inline std::array<Pixel, 4> color_palette(const uint8_t* block)
    {
        uint16_t a, b;
        std::memcpy(&a, block + 8, sizeof(a));
        std::memcpy(&b, block + 10, sizeof(b));
        return color_palette(a, b);
    }

    inline Pixel decode(const uint8_t* block, UINT index, const std::array<Pixel, 4>& colors)
    {
        const unsigned choice = (block[12 + index / 4] >> (2 * (index % 4))) & 3;
        Pixel p = colors[choice];
        p[3] = static_cast<uint8_t>(((block[index / 2] >> (4 * (index % 2))) & 15) * 17);
        return p;
    }

    inline Pixel decode(const uint8_t* block, UINT index) { return decode(block, index, color_palette(block)); }

    inline void encode(const std::array<Pixel, 16>& block, uint8_t* output)
    {
        std::array<unsigned, 3> sum{};
        for (auto& p : block) {
            for (unsigned c = 0; c < 3; ++c) sum[c] += p[c];
        }
        Pixel mean{};
        for (unsigned c = 0; c < 3; ++c) mean[c] = static_cast<uint8_t>(sum[c] / block.size());
        const auto distance = [](const Pixel& a, const Pixel& b) {
            unsigned error = 0;
            for (unsigned c = 0; c < 3; ++c) {
                const int diff = a[c] - b[c];
                error += diff * diff;
            }
            return error;
        };
        // Select actual texels near opposite ends of the block's colors.
        // Independent extrema can turn red and blue into black and magenta.
        const auto farthest = [&](const Pixel& origin) {
            const Pixel* best = &block.front();
            unsigned maxDistance = 0;
            for (const auto& pixel : block) {
                const unsigned error = distance(pixel, origin);
                if (error > maxDistance) {
                    maxDistance = error;
                    best = &pixel;
                }
            }
            return *best;
        };
        const auto pack = [](const Pixel& p) {
            return static_cast<uint16_t>(((p[0] * 31 + 127) / 255) << 11 |
                                         ((p[1] * 63 + 127) / 255) << 5 |
                                         ((p[2] * 31 + 127) / 255));
        };
        const auto first = farthest(mean);
        const auto a = pack(first), b = pack(farthest(first));
        const auto palette = color_palette(a, b);
        uint32_t indices = 0;
        uint64_t alpha = 0;
        for (unsigned i = 0; i < block.size(); ++i) {
            unsigned best = 0, error = UINT_MAX;
            for (unsigned j = 0; j < palette.size(); ++j) {
                const unsigned candidate = distance(block[i], palette[j]);
                if (candidate < error) { best = j; error = candidate; }
            }
            indices |= best << (2 * i);
            alpha |= uint64_t((block[i][3] + 8) / 17) << (4 * i);
        }
        std::memcpy(output, &alpha, sizeof(alpha));
        std::memcpy(output + 8, &a, sizeof(a));
        std::memcpy(output + 10, &b, sizeof(b));
        std::memcpy(output + 12, &indices, sizeof(indices));
    }

    // Incremental numeric RGBA box filter. Intermediate levels stay uncompressed.
    class Builder
    {
    public:
        explicit Builder(Layout layout) : layout(layout), data(layout.bytes),
            m_width(layout.width), m_height(layout.height), m_offset(layout.top_bytes())
        {}

        bool step(unsigned blocks)
        {
            if (blocks && m_offset < data.size() && m_previous.empty()) decode_top();
            while (blocks-- && m_offset < data.size()) {
                const UINT width = std::max(1u, m_width / 2), height = std::max(1u, m_height / 2);
                if (m_block == 0) m_current.resize(size_t(width) * height);
                const UINT columns = (width + 3) / 4;
                const UINT bx = (m_block % columns) * 4, by = (m_block / columns) * 4;
                std::array<Pixel, 16> tile{};
                for (UINT i = 0; i < tile.size(); ++i) {
                    const UINT x = std::min(bx + i % 4, width - 1), y = std::min(by + i / 4, height - 1);
                    const auto& a = sample(x * 2, y * 2);
                    const auto& b = sample(x * 2 + 1, y * 2);
                    const auto& c = sample(x * 2, y * 2 + 1);
                    const auto& d = sample(x * 2 + 1, y * 2 + 1);
                    for (unsigned k = 0; k < 4; ++k)
                        tile[i][k] = static_cast<uint8_t>((a[k] + b[k] + c[k] + d[k] + 2) / 4);
                    m_current[size_t(y) * width + x] = tile[i];
                }
                encode(tile, data.data() + m_offset);
                m_offset += 16;
                if (++m_block == columns * rows(height)) {
                    m_block = 0;
                    m_width = width;
                    m_height = height;
                    m_previous.swap(m_current);
                }
            }
            return m_offset == data.size();
        }

        Layout layout;
        std::vector<uint8_t> data;

    private:
        void decode_top()
        {
            m_previous.resize(size_t(m_width) * m_height);
            const auto* block = data.data();
            for (UINT y = 0; y < m_height; y += 4) {
                for (UINT x = 0; x < m_width; x += 4, block += 16) {
                    const auto colors = color_palette(block);
                    const UINT height = std::min(4u, m_height - y);
                    const UINT width = std::min(4u, m_width - x);
                    for (UINT row = 0; row < height; ++row) {
                        auto* dest = m_previous.data() + size_t(y + row) * m_width + x;
                        for (UINT col = 0; col < width; ++col) dest[col] = decode(block, row * 4 + col, colors);
                    }
                }
            }
        }

        const Pixel& sample(UINT x, UINT y) const
        {
            return m_previous[size_t(std::min(y, m_height - 1)) * m_width + std::min(x, m_width - 1)];
        }

        UINT m_width, m_height, m_block = 0;
        size_t m_offset;
        std::vector<Pixel> m_previous, m_current;
    };
}
