#pragma once

#include "Dxt3Mipmaps.h"
#include "MipmapDiskCache.h"
#include <atomic>
#include <chrono>
#include <optional>
#include <thread>
#include <unordered_map>
#include <unordered_set>

// The cache and D3D objects stay on the render thread. The worker only sees
// a copied BC2 payload and the buffers for its lower levels.
class AutoColorMipmaps
{
    using Source = Microsoft::WRL::ComPtr<IDirect3DBaseTexture8>;
    static constexpr size_t MaxBytes = 8 * 1024 * 1024;
    static constexpr size_t MaxDetailBytes = 4 * 1024 * 1024;

    struct Material
    {
        Source color, detail;
        Dxt3::Layout layout;
        DWORD shader;
    };

    struct Entry
    {
        Material material;
        Dxt3::Texture replacement;
        std::vector<uint8_t> top;
        uint64_t seen, checked;
        bool used = false;
        Dxt3::Texture detailReplacement;
        std::vector<uint8_t> detailTop;
        uint64_t detailRetry = 0;
        bool detailUsed = false;

        size_t bytes() const { return material.layout.bytes + (material.detail ? 3 : 2) * material.layout.top_bytes(); }
        size_t detail_bytes() const { return detailReplacement ? material.layout.bytes + detailTop.size() : 0; }
    };

    struct Skip { IDirect3DBaseTexture8* color = nullptr; uint64_t until = 0; };
    struct DrawPass { DWORD shader = 0; bool blended = false, valid = false; };

    struct Request
    {
        Material material;
        bool detail;

        IDirect3DBaseTexture8* source() const { return detail ? material.detail.Get() : material.color.Get(); }
        bool matches(IDirect3DBaseTexture8* color, bool wantsDetail) const
        {
            return material.color.Get() == color && detail == wantsDetail;
        }
    };

    struct Upload
    {
        Request request;
        std::vector<uint8_t> data;
        Dxt3::Texture texture;
        size_t offset = 0;
        UINT level = 0;
    };

public:
    using Clock = std::chrono::steady_clock;
    static constexpr size_t ReadyBudget = MaxBytes + MaxDetailBytes;
    static constexpr size_t WorkBudget = 8 * 1024 * 1024;

    struct Stats
    {
        uint64_t generated = 0, evicted = 0, invalidated = 0, rejected = 0, peakUs = 0;
        uint64_t snapshotUs = 0, buildUs = 0, createUs = 0, uploadUs = 0, firstUseUs = 0;
        uint64_t paced = 0;
        uint64_t diskHits = 0, diskMisses = 0, diskWrites = 0, diskErrors = 0, diskUs = 0;
        uint64_t overlapFrames = 0;
        unsigned checks = 0, errors = 0;
    };

    struct Selection
    {
        IDirect3DTexture8* texture = nullptr;
        IDirect3DBaseTexture8* originalDetail = nullptr;
        IDirect3DTexture8* detail = nullptr;
        bool firstUse = false;
        bool blended = false;
    };

    const Stats& stats() const { return m_stats; }
    void set_disk_directory(std::filesystem::path path)
    {
        cancel_pending();
        m_diskDirectory = std::move(path);
        m_diskTrimmed = false;
        m_diskUses.clear();
    }
    size_t count() const { return m_cache.size(); }
    size_t bytes() const { return m_bytes + m_detailBytes; }
    size_t detail_count() const
    {
        return std::count_if(m_cache.begin(), m_cache.end(), [](const auto& item) {
            return bool(item.second.detailReplacement);
        });
    }
    size_t waiting() const { return m_waiting.size(); }
    bool preparing() const { return m_candidate.has_value(); }
    bool uploading() const { return m_upload.has_value(); }
    bool pending() const { return waiting() || preparing() || uploading(); }
    void cancel_pending()
    {
        clear_builder();
        m_waiting.clear();
        m_upload.reset();
    }
    void cancel_detail()
    {
        if (m_candidate && m_candidate->detail) clear_builder();
        if (m_upload && m_upload->request.detail) m_upload.reset();
        std::erase_if(m_waiting, [](const Request& request) { return request.detail; });
    }
    void clear()
    {
        cancel_pending();
        m_cache.clear();
        m_skips = {};
        m_bytes = 0;
        m_detailBytes = 0;
        m_attempts = 0;
        m_nextWorkFrame = 0;
        m_nextFirstUseFrame = 0;
        m_firstUseThisFrame = false;
        m_lastPresent = {};
    }

    void start()
    {
        clear();
        m_waiting.reserve(MaxWaiting);
        m_stats = {};
        m_frame = 0;
    }

    static DWORD opaque_shader(IDirect3DDevice8* device)
    {
        return describe_pass(device, D3DPT_TRIANGLELIST, false).shader;
    }

    Selection select(IDirect3DDevice8* device, D3DPRIMITIVETYPE type, IDirect3DBaseTexture8* color, bool cacheOnly,
                     bool useDetail, bool useBlend)
    {
        const auto found = m_cache.find(color);
        if (found == m_cache.end()) {
            if (!cacheOnly && queue_has_space(false) && !requested(color, false)) consider(device, type, color);
            return {};
        }

        auto& entry = found->second;
        if (m_frame - entry.checked > RecheckInterval + MaxEntries) return {};
        const auto pass = describe_pass(device, type, useBlend);
        if (!pass.valid || entry.material.shader != pass.shader || (pass.blended && !entry.used) ||
            !uses_mips(device)) return {};
        Source detail;
        if (FAILED(device->GetTexture(1, detail.GetAddressOf())) || detail.Get() != entry.material.detail.Get())
            return {};
        entry.seen = m_frame;

        IDirect3DTexture8* detailMip = nullptr;
        if (useDetail && detail && uses_mips(device, 1)) {
            if (!pass.blended || entry.detailUsed) detailMip = entry.detailReplacement.Get();
            if (!pass.blended && !detailMip && !cacheOnly && m_frame >= entry.detailRetry &&
                queue_has_space(true) && !requested(color, true)) {
                const auto needed = entry.material.layout.bytes + entry.material.layout.top_bytes();
                if (needed <= MaxDetailBytes - m_detailBytes) {
                    enqueue({entry.material, true});
                } else {
                    entry.detailRetry = m_frame + RecheckInterval;
                }
            }
        }
        if (m_frame < m_nextFirstUseFrame) {
            if (!entry.used) return {};
            if (!entry.detailUsed) detailMip = nullptr;
        }
        const bool firstUse = !entry.used || (detailMip && !entry.detailUsed);
        if (firstUse) {
            m_nextFirstUseFrame = m_frame + FirstUseSpacing;
            m_firstUseThisFrame = true;
        }
        return {entry.replacement.Get(), detailMip ? entry.material.detail.Get() : nullptr,
                detailMip, firstUse, pass.blended};
    }

    void finish_first_use(IDirect3DBaseTexture8* original, Clock::time_point start, bool drawn, bool detailUsed)
    {
        record_peak(m_stats.firstUseUs, start);
        const auto it = m_cache.find(original);
        if (drawn && it != m_cache.end()) {
            it->second.used = true;
            if (detailUsed) it->second.detailUsed = true;
        }
    }

    void present(IDirect3DDevice8* device)
    {
        const auto start = Clock::now();
        const bool slowFrame = m_lastPresent != Clock::time_point{} && start - m_lastPresent > std::chrono::milliseconds(22);
        m_lastPresent = start;
        ++m_frame;
        m_attempts = 0;
        recheck_one();
        if (pending()) {
            if (!m_firstUseThisFrame && (!slowFrame || m_frame >= m_nextWorkFrame)) {
                collect_prepared();
                if (m_upload) advance_upload(device);
                // Bound extra work when a Present also creates or copies a texture.
                if (!m_candidate && !m_waiting.empty() && Clock::now() - start < PipelineBudget)
                    prepare_next();
                m_nextWorkFrame = m_frame + 3;
            } else {
                ++m_stats.paced;
            }
        }
        if (m_candidate && m_upload) ++m_stats.overlapFrames;
        m_firstUseThisFrame = false;
        record_peak(m_stats.peakUs, start);
    }

private:
    static constexpr size_t MaxEntries = 32;
    static constexpr uint64_t FirstUseSpacing = 4;
    static constexpr uint64_t RecheckInterval = 60;
    static constexpr size_t UploadBytesPerFrame = 128 * 1024;
    static constexpr UINT UploadLevelsPerFrame = 4;
    static constexpr size_t MaxWaiting = 4;
    static constexpr size_t MaxRecordedUses = 1024;
    static constexpr UINT MaxDimension = 512;
    static constexpr Dxt3::Layout Largest{MaxDimension, MaxDimension};
    // Source pairs pinned by the queue, builder and upload, plus decoded pixels,
    // encoded buffers, replacement texture and the final level-zero copy.
    static constexpr size_t MaxWorkBytes = (MaxWaiting + 2) * 2 * Largest.top_bytes() +
        size_t(MaxDimension) * MaxDimension * sizeof(Dxt3::Pixel) * 5 / 4 +
        4 * Largest.bytes + Largest.top_bytes();
    static_assert(MaxWorkBytes <= WorkBudget);
    static constexpr auto PipelineBudget = std::chrono::microseconds(250);

    struct DiskWork
    {
        bool hit = false, miss = false, wrote = false, failed = false;
        uint64_t us = 0;
    };

    static bool fixed_function_terrain(IDirect3DDevice8* device)
    {
        DWORD vertex = 0, baseOp = 0, nextOp = 0;
        constexpr DWORD TerrainFVF = D3DFVF_XYZ | D3DFVF_NORMAL | D3DFVF_DIFFUSE | D3DFVF_TEX1;
        return SUCCEEDED(device->GetVertexShader(&vertex)) && vertex == TerrainFVF &&
            SUCCEEDED(device->GetTextureStageState(0, D3DTSS_COLOROP, &baseOp)) && baseOp == D3DTOP_MODULATE2X &&
            SUCCEEDED(device->GetTextureStageState(1, D3DTSS_COLOROP, &nextOp)) && nextOp == D3DTOP_DISABLE;
    }

    static DrawPass describe_pass(IDirect3DDevice8* device, D3DPRIMITIVETYPE type, bool useBlend)
    {
        DWORD ps = 0, depth = 0, write = 0, blend = 0, alpha = 0;
        if (FAILED(device->GetPixelShader(&ps)) ||
            !(ps ? type == D3DPT_TRIANGLELIST :
                   type == D3DPT_TRIANGLESTRIP && fixed_function_terrain(device)) ||
            FAILED(device->GetRenderState(D3DRS_ZENABLE, &depth)) || !depth ||
            FAILED(device->GetRenderState(D3DRS_ZWRITEENABLE, &write))) return {};
        const bool blendedPass = write == FALSE;
        if ((blendedPass && !useBlend) ||
            FAILED(device->GetRenderState(D3DRS_ALPHABLENDENABLE, &blend)) || (blend != FALSE) != blendedPass ||
            FAILED(device->GetRenderState(D3DRS_ALPHATESTENABLE, &alpha)) || alpha) return {};
        if (!blendedPass) return {ps, false, true};

        // Terrain overlay signature observed in South Gustaberg. Only the
        // lookup path enables it, so it cannot classify or warm a new chain.
        DWORD test = 0, bias = 0;
        if (depth != D3DZB_TRUE ||
            FAILED(device->GetRenderState(D3DRS_ZFUNC, &test)) || test != D3DCMP_LESSEQUAL ||
            FAILED(device->GetRenderState(D3DRS_ZBIAS, &bias)) || bias != 8) return {};
        return {ps, true, true};
    }

    static uint64_t record_peak(uint64_t& peak, Clock::time_point start)
    {
        const auto us = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
        peak = std::max(peak, us);
        return us;
    }

    static bool uses_mips(IDirect3DDevice8* device, DWORD stage = 0)
    {
        DWORD filter = 0, maxMip = 0;
        return SUCCEEDED(device->GetTextureStageState(stage, D3DTSS_MIPFILTER, &filter)) &&
            (filter == D3DTEXF_LINEAR || filter == D3DTEXF_POINT) &&
            SUCCEEDED(device->GetTextureStageState(stage, D3DTSS_MAXMIPLEVEL, &maxMip)) && maxMip == 0;
    }

    static bool eligible_dimension(UINT size)
    {
        return size >= 32 && size <= MaxDimension && (size & (size - 1)) == 0;
    }

    Skip& skip_slot(IDirect3DBaseTexture8* key)
    {
        return m_skips[(reinterpret_cast<uintptr_t>(key) >> 4) % m_skips.size()];
    }

    bool requested(IDirect3DBaseTexture8* color, bool detail) const
    {
        return (m_candidate && m_candidate->matches(color, detail)) ||
            (m_upload && m_upload->request.matches(color, detail)) ||
            std::any_of(m_waiting.begin(), m_waiting.end(), [=](const Request& item) {
                return item.matches(color, detail);
            });
    }

    bool queue_has_space(bool detail) const
    {
        return m_waiting.size() < MaxWaiting || (!detail &&
            std::any_of(m_waiting.begin(), m_waiting.end(), [](const Request& item) { return item.detail; }));
    }

    void enqueue(Request item)
    {
        if (m_waiting.size() == MaxWaiting) {
            // A newly visible base texture can use a waiting detail slot.
            const auto low = std::find_if(m_waiting.rbegin(), m_waiting.rend(),
                [](const Request& request) { return request.detail; });
            if (low == m_waiting.rend() || item.detail) return;
            m_waiting.erase(std::next(low).base());
        }
        m_waiting.push_back(std::move(item));
    }

    void consider(IDirect3DDevice8* device, D3DPRIMITIVETYPE type, IDirect3DBaseTexture8* color)
    {
        const auto& skip = skip_slot(color);
        if ((skip.color == color && skip.until > m_frame) || m_attempts >= 4) return;
        D3DSURFACE_DESC colorDesc{}, detailDesc{};
        if (!Dxt3::describe(color, colorDesc) || !eligible_dimension(colorDesc.Width) ||
            !eligible_dimension(colorDesc.Height)) {
            skip_slot(color) = {color, m_frame + 120};
            return;
        }
        const auto pass = describe_pass(device, type, false);
        if (!pass.valid || !uses_mips(device)) return;
        ++m_attempts;
        Source detail;
        if (FAILED(device->GetTexture(1, detail.GetAddressOf()))) return;
        const bool validDetail = pass.shader ?
            detail.Get() != color && Dxt3::describe(detail.Get(), detailDesc) &&
                detailDesc.Width == colorDesc.Width && detailDesc.Height == colorDesc.Height :
            !detail;
        if (!validDetail) {
            skip_slot(color) = {color, m_frame + 120};
            return;
        }
        Source original;
        original = color;
        enqueue({{std::move(original), std::move(detail),
                  Dxt3::Layout(colorDesc.Width, colorDesc.Height), pass.shader}, false});
    }

    static bool normal_like(const Dxt3::Layout& layout, const uint8_t* data, size_t stride)
    {
        constexpr size_t Samples = 64;
        const size_t columns = Dxt3::pitch(layout.width) / 16;
        const size_t blocks = columns * Dxt3::rows(layout.height);
        size_t matches = 0;
        for (size_t i = 0; i < Samples; ++i) {
            const size_t index = i * blocks / Samples;
            const auto p = Dxt3::decode(data + index / columns * stride + index % columns * 16, 5);
            if (p[2] >= 176 && p[0] >= 48 && p[0] <= 208 && p[1] >= 48 && p[1] <= 208) ++matches;
        }
        return matches >= 48;
    }

    bool unchanged(IDirect3DBaseTexture8* source, const Dxt3::Layout& layout, const uint8_t* top)
    {
        ++m_stats.checks;
        bool same = true;
        const size_t rowBytes = Dxt3::pitch(layout.width);
        if (!Dxt3::visit_top(source, layout.width, [&](const auto* data, size_t stride) {
            for (UINT row = 0; same && row < Dxt3::rows(layout.height); ++row)
                same = std::memcmp(data + row * stride, top + row * rowBytes, rowBytes) == 0;
        })) {
            ++m_stats.errors;
            return false;
        }
        return same;
    }

    void recheck_one()
    {
        const auto oldest = std::min_element(m_cache.begin(), m_cache.end(), [](const auto& a, const auto& b) {
            return a.second.checked < b.second.checked;
        });
        if (oldest == m_cache.end() || m_frame - oldest->second.checked < RecheckInterval) return;
        auto& entry = oldest->second;
        if (unchanged(entry.material.color.Get(), entry.material.layout, entry.top.data())) {
            entry.checked = m_frame;
            if (entry.detailReplacement &&
                !unchanged(entry.material.detail.Get(), entry.material.layout, entry.detailTop.data())) {
                ++m_stats.invalidated;
                m_detailBytes -= entry.detail_bytes();
                entry.detailReplacement.Reset();
                std::vector<uint8_t>().swap(entry.detailTop);
                entry.detailUsed = false;
                entry.detailRetry = m_frame + RecheckInterval;
            }
        } else {
            ++m_stats.invalidated;
            skip_slot(oldest->first) = {oldest->first, m_frame + RecheckInterval};
            m_bytes -= entry.bytes();
            m_detailBytes -= entry.detail_bytes();
            m_cache.erase(oldest);
        }
    }

    void retry_later(const Request& request)
    {
        auto* original = request.material.color.Get();
        if (request.detail) {
            const auto found = m_cache.find(original);
            if (found != m_cache.end()) found->second.detailRetry = m_frame + RecheckInterval;
        } else {
            skip_slot(original) = {original, m_frame + 120};
        }
    }

    void clear_builder()
    {
        if (m_worker.joinable()) {
            m_worker.request_stop();
            m_worker.join();
        }
        m_build.reset();
        m_candidate.reset();
    }

    void reject_candidate()
    {
        retry_later(*m_candidate);
        clear_builder();
    }

    void reject_upload()
    {
        retry_later(m_upload->request);
        m_upload.reset();
    }

    Entry* detail_entry(const Request& request)
    {
        const auto found = m_cache.find(request.material.color.Get());
        if (found == m_cache.end()) return nullptr;
        auto& entry = found->second;
        if (entry.detailReplacement || entry.material.detail.Get() != request.material.detail.Get() ||
            entry.material.shader != request.material.shader) return nullptr;
        return &entry;
    }

    void prepare_next()
    {
        const auto color = std::find_if(m_waiting.begin(), m_waiting.end(),
            [](const Request& request) { return !request.detail; });
        const auto next = color != m_waiting.end() ? color : m_waiting.begin();
        m_candidate.emplace(std::move(*next));
        m_waiting.erase(next);
        const auto& request = *m_candidate;
        const auto& layout = request.material.layout;
        if (request.detail && (!detail_entry(request) ||
            layout.bytes + layout.top_bytes() > MaxDetailBytes - m_detailBytes)) {
            reject_candidate();
            return;
        }
        const auto start = Clock::now();
        snapshot();
        record_peak(m_stats.snapshotUs, start);
    }

    bool read_source(IDirect3DBaseTexture8* texture, const Dxt3::Layout& layout, bool& likeNormal, uint8_t* top)
    {
        ++m_stats.checks;
        return Dxt3::visit_top(texture, layout.width, [&](const auto* data, size_t stride) {
            likeNormal = normal_like(layout, data, stride);
            if (!top) return;
            const size_t rowBytes = Dxt3::pitch(layout.width);
            for (UINT row = 0; row < Dxt3::rows(layout.height); ++row)
                std::memcpy(top + row * rowBytes, data + row * stride, rowBytes);
        });
    }

    void build_on_worker(std::stop_token stop)
    {
        const bool diskEnabled = !m_diskDirectory.empty();
        uint64_t id = 0;
        bool firstUse = false;
        if (diskEnabled && !stop.stop_requested()) {
            const auto start = Clock::now();
            id = MipmapDiskCache::key(m_build->layout, m_build->data.data());
            try {
                if (!m_diskTrimmed) m_diskTrimmed = MipmapDiskCache::trim(m_diskDirectory);
                firstUse = m_diskUses.size() < MaxRecordedUses && !m_diskUses.contains(id);
                m_diskWork.hit = MipmapDiskCache::load(m_diskDirectory, id, *m_build, firstUse);
                if (m_diskWork.hit && firstUse) m_diskUses.insert(id);
            } catch (...) {
                m_diskWork.failed = true;
            }
            m_diskWork.miss = !m_diskWork.hit;
            record_peak(m_diskWork.us, start);
        }
        if (m_diskWork.hit || stop.stop_requested()) return;

        const auto generateStart = Clock::now();
        while (!stop.stop_requested() && !m_build->step(64)) {}
        record_peak(m_buildTime, generateStart);

        if (diskEnabled && !stop.stop_requested()) {
            const auto start = Clock::now();
            try {
                m_diskWork.wrote = MipmapDiskCache::store(m_diskDirectory, id, *m_build);
                if (m_diskWork.wrote && firstUse) m_diskUses.insert(id);
            } catch (...) {
                m_diskWork.failed = true;
            }
            m_diskWork.failed = m_diskWork.failed || !m_diskWork.wrote;
            record_peak(m_diskWork.us, start);
        }
    }

    void snapshot()
    {
        const auto& request = *m_candidate;
        const auto& material = request.material;
        const auto& layout = material.layout;
        bool likeNormal = false;
        if (!request.detail && material.detail) {
            if (!read_source(material.detail.Get(), layout, likeNormal, nullptr)) {
                ++m_stats.errors;
                reject_candidate();
                return;
            }
            if (!likeNormal) {
                ++m_stats.rejected;
                reject_candidate();
                return;
            }
        }
        m_build.emplace(layout);
        auto* source = request.source();
        if (!read_source(source, layout, likeNormal, m_build->data.data())) {
            ++m_stats.errors;
            reject_candidate();
        } else if (likeNormal != request.detail) {
            ++m_stats.rejected;
            reject_candidate();
        } else {
            m_buildFailed = false;
            m_buildTime = 0;
            m_diskWork = {};
            m_buildDone.store(false, std::memory_order_relaxed);
            m_worker = std::jthread([this](std::stop_token stop) {
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
                try {
                    build_on_worker(stop);
                } catch (...) {
                    m_buildFailed = true;
                }
                m_buildDone.store(true, std::memory_order_release);
            });
        }
    }

    bool upload_levels(Upload& upload, Clock::time_point start)
    {
        const auto& layout = upload.request.material.layout;
        size_t bytesCopied = 0;
        for (UINT i = 0; i < UploadLevelsPerFrame && upload.level < layout.levels; ++i) {
            const auto bytes = layout.level_bytes(upload.level);
            // A large top level gets a frame to itself.
            if (i && (bytesCopied + bytes > UploadBytesPerFrame ||
                      Clock::now() - start >= std::chrono::microseconds(250))) break;
            if (!Dxt3::upload_level(upload.texture.Get(), layout, upload.level, upload.data.data() + upload.offset))
                return false;
            ++upload.level;
            upload.offset += bytes;
            bytesCopied += bytes;
        }
        return true;
    }

    void collect_prepared()
    {
        if (m_upload || !m_candidate || !m_buildDone.load(std::memory_order_acquire)) return;
        m_worker.join();
        m_stats.buildUs = std::max(m_stats.buildUs, m_buildTime);
        m_stats.diskHits += m_diskWork.hit;
        m_stats.diskMisses += m_diskWork.miss;
        m_stats.diskWrites += m_diskWork.wrote;
        m_stats.diskErrors += m_diskWork.failed;
        m_stats.diskUs = std::max(m_stats.diskUs, m_diskWork.us);
        if (m_buildFailed) {
            ++m_stats.errors;
            reject_candidate();
            return;
        }
        m_upload.emplace(Upload{std::move(*m_candidate), std::move(m_build->data), {}});
        clear_builder();
    }

    void advance_upload(IDirect3DDevice8* device)
    {
        auto& upload = *m_upload;
        auto& request = upload.request;
        auto& material = request.material;
        const auto& layout = material.layout;
        const auto& data = upload.data;
        if (request.detail && (!detail_entry(request) ||
            layout.bytes + layout.top_bytes() > MaxDetailBytes - m_detailBytes)) {
            reject_upload();
            return;
        }
        if (!upload.texture || upload.level < layout.levels) {
            const auto start = Clock::now();
            bool ok;
            if (!upload.texture) {
                ok = Dxt3::create(device, layout, upload.texture);
                record_peak(m_stats.createUs, start);
            } else {
                ok = upload_levels(upload, start);
                record_peak(m_stats.uploadUs, start);
            }
            if (!ok) {
                ++m_stats.errors;
                reject_upload();
            }
            return;
        }
        if (!unchanged(request.source(), layout, data.data())) {
            ++m_stats.invalidated;
            reject_upload();
            return;
        }

        if (request.detail) {
            auto& entry = *detail_entry(request);
            entry.detailTop.assign(data.data(), data.data() + layout.top_bytes());
            entry.detailReplacement = std::move(upload.texture);
            entry.detailUsed = false;
            m_detailBytes += entry.detail_bytes();
            m_upload.reset();
            return;
        }

        const auto topBytes = layout.top_bytes();
        Entry entry{std::move(material), std::move(upload.texture),
            std::vector<uint8_t>(data.data(), data.data() + topBytes), m_frame, m_frame};
        while (m_cache.size() >= MaxEntries || m_bytes + entry.bytes() > MaxBytes) {
            const auto oldest = std::min_element(m_cache.begin(), m_cache.end(), [](const auto& a, const auto& b) {
                return a.second.seen < b.second.seen;
            });
            m_bytes -= oldest->second.bytes();
            m_detailBytes -= oldest->second.detail_bytes();
            m_cache.erase(oldest);
            ++m_stats.evicted;
        }
        auto* key = entry.material.color.Get();
        const size_t bytes = entry.bytes();
        m_cache.emplace(key, std::move(entry));
        m_bytes += bytes;
        ++m_stats.generated;
        m_upload.reset();
    }

    uint64_t m_frame = 0;
    uint64_t m_nextWorkFrame = 0, m_nextFirstUseFrame = 0;
    Clock::time_point m_lastPresent{};
    size_t m_bytes = 0, m_detailBytes = 0;
    unsigned m_attempts = 0;
    Stats m_stats;
    std::unordered_map<IDirect3DBaseTexture8*, Entry> m_cache;
    std::array<Skip, 256> m_skips{};
    std::vector<Request> m_waiting;
    std::optional<Request> m_candidate;
    std::optional<Dxt3::Builder> m_build;
    std::optional<Upload> m_upload;
    std::filesystem::path m_diskDirectory;
    std::unordered_set<uint64_t> m_diskUses;
    bool m_diskTrimmed = false;
    DiskWork m_diskWork;
    uint64_t m_buildTime = 0;
    bool m_buildFailed = false, m_firstUseThisFrame = false;
    std::atomic<bool> m_buildDone{false};
    std::jthread m_worker;
};
