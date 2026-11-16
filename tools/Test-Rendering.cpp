// Standalone x86 D3D8 smoke test; no FFXI process or game files are accessed.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cstdint>
#include <d3d8/includes/d3d8.h>
#include "../src/MipmapExperiment.h"
#include "../src/FogDeviceState.h"
#include <cstdlib>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); std::exit(1); } } while (0)

static void test_bc2_generation()
{
    // Two hand-encoded BC2 blocks: red with alpha 0 and blue with alpha 255.
    const uint8_t original[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 248, 0, 0, 0, 0, 0, 0,
        255, 255, 255, 255, 255, 255, 255, 255, 31, 0, 0, 0, 0, 0, 0, 0
    };
    Dxt3::Builder builder({8, 4});
    CHECK(builder.layout.levels == 4 && builder.data.size() == 80);
    std::memcpy(builder.data.data(), original, sizeof(original));
    CHECK(!builder.step(1));
    CHECK(!builder.step(1));
    CHECK(builder.step(1));
    CHECK(std::memcmp(builder.data.data(), original, sizeof(original)) == 0);
    const Dxt3::Pixel red{255, 0, 0, 0}, blue{0, 0, 255, 255}, average{132, 0, 132, 136};
    CHECK(Dxt3::decode(builder.data.data() + 32, 0) == red);
    CHECK(Dxt3::decode(builder.data.data() + 32, 3) == blue);
    CHECK(Dxt3::decode(builder.data.data() + 64, 0) == average);
}

static void test_disk_cache(const std::filesystem::path& install)
{
    const auto dir = install / ("disk-validation-" + std::to_string(GetCurrentProcessId()) + "-" +
                                std::to_string(GetTickCount64()));
    Dxt3::Builder built({32, 32});
    std::fill_n(built.data.begin(), built.layout.top_bytes(), uint8_t{0x93});
    while (!built.step(64)) {}
    const auto id = MipmapDiskCache::key(built.layout, built.data.data());
    CHECK(MipmapDiskCache::store(dir, id, built));
    const auto bucket = static_cast<unsigned>(id % 80);
    const auto path = dir / ("mip-" + std::to_string(bucket) + "-0.bc2");
    auto usePath = path;
    usePath.replace_extension(".use");
    // A 1.33 payload has no access metadata. Its first hit creates it.
    CHECK(std::filesystem::remove(usePath));
    Dxt3::Builder reopened(built.layout);
    std::copy_n(built.data.begin(), built.layout.top_bytes(), reopened.data.begin());
    CHECK(MipmapDiskCache::load(dir, id, reopened) && reopened.data == built.data);
    CHECK(!std::filesystem::exists(usePath));
    CHECK(MipmapDiskCache::load(dir, id, reopened, true) && std::filesystem::exists(usePath));
    CHECK(std::filesystem::remove(usePath));

    // A valid name/hash lookup never bypasses the byte comparison of level zero.
    reopened.data[0] ^= 1;
    CHECK(!MipmapDiskCache::load(dir, id, reopened));
    reopened.data[0] ^= 1;
    std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
    CHECK(file.seekp(-1, std::ios::end));
    file.put(static_cast<char>(built.data.back() ^ 1));
    CHECK(file.good());
    file.close();
    CHECK(!MipmapDiskCache::load(dir, id, reopened));

    const uint64_t hot = id + 80;
    CHECK(MipmapDiskCache::store(dir, hot, built));
    CHECK(MipmapDiskCache::load(dir, hot, reopened, true));
    CHECK(MipmapDiskCache::load(dir, hot, reopened, true));
    for (unsigned i = 2; i <= 4; ++i) CHECK(MipmapDiskCache::store(dir, id + i * 80, built));
    // The legacy/corrupted slot has the lowest score in this bucket.
    CHECK(MipmapDiskCache::load(dir, id + 320, reopened));
    CHECK(MipmapDiskCache::store(dir, id + 5 * 80, built));
    CHECK(MipmapDiskCache::load(dir, hot, reopened));
    unsigned remaining = 0;
    for (unsigned i = 1; i <= 5; ++i)
        remaining += MipmapDiskCache::load(dir, id + i * 80, reopened);
    CHECK(remaining == 4);

    const auto oversized = dir / ("mip-" + std::to_string((bucket + 1) % 80) + "-0.bc2");
    std::ofstream(oversized, std::ios::binary).close();
    std::filesystem::resize_file(oversized, MipmapDiskCache::Budget);
    CHECK(MipmapDiskCache::trim(dir) && !std::filesystem::exists(oversized));
    CHECK(MipmapDiskCache::load(dir, hot, reopened));
    for (const auto& entry : std::filesystem::directory_iterator(dir))
        CHECK(std::filesystem::remove(entry.path()));
    CHECK(std::filesystem::remove(dir));
    std::puts("PASS: legacy disk reload, integrity checks, frequency eviction and size cap.");
}

static IDirect3DTexture8* original_from_chain(IDirect3DDevice8* device, const std::filesystem::path& file)
{
    std::ifstream stream(file, std::ios::binary);
    uint32_t header[32]{};
    CHECK(stream.read(reinterpret_cast<char*>(header), sizeof(header)));
    const UINT width = header[4], height = header[3];
    const size_t rowBytes = ((width + 3) / 4) * 16;
    IDirect3DTexture8* texture = nullptr;
    CHECK(SUCCEEDED(device->CreateTexture(width, height, 1, 0, D3DFMT_DXT3, D3DPOOL_MANAGED, &texture)));
    D3DLOCKED_RECT lock{};
    CHECK(SUCCEEDED(texture->LockRect(0, &lock, nullptr, 0)));
    CHECK(lock.Pitch >= static_cast<INT>(rowBytes));
    for (UINT row = 0; row < (height + 3) / 4; ++row)
        CHECK(stream.read(static_cast<char*>(lock.pBits) + row * lock.Pitch, rowBytes));
    CHECK(SUCCEEDED(texture->UnlockRect(0)));
    return texture;
}

static void test_automatic_mips(IDirect3DDevice8* device, MipmapExperiment& experiment,
                               const std::filesystem::path& folder, IDirect3DTexture8* color,
                               IDirect3DTexture8* detail, const std::filesystem::path& install)
{
    // Starting without a DDS directory proves generation is independent of the
    // curated asset library. First check that a second color image is rejected.
    std::string message;
    auto* wrongDetail = original_from_chain(device, folder / "pavement-a-color.dds");
    CHECK(SUCCEEDED(device->SetTexture(1, wrongDetail)));
    CHECK(experiment.start(device, {}, MipmapExperiment::Mode::Auto, message));
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(experiment.automatic().pending());
    experiment.present(device);
    CHECK(!experiment.automatic().pending() && experiment.automatic().stats().rejected == 1);
    experiment.stop();
    CHECK(SUCCEEDED(device->SetTexture(1, detail)));
    CHECK(wrongDetail->Release() == 0);

    const auto cache = install / ("disk-runtime-" + std::to_string(GetCurrentProcessId()) + "-" +
                                  std::to_string(GetTickCount64()));
    experiment.set_disk_directory(cache);
    CHECK(experiment.start_ground_mipmaps(device, message));
    CHECK(experiment.mode() == MipmapExperiment::Mode::Auto && experiment.detail_enabled() &&
          experiment.blend_enabled() && experiment.linear_enabled() && !experiment.smoothing());
    CHECK(experiment.set_paused(true) && experiment.set_linear(device, false));
    CHECK(experiment.start_ground_mipmaps(device, message) && experiment.linear_enabled() && !experiment.paused());
    experiment.stop();
    const auto blend_pass = [device](bool enable) {
        CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ALPHABLENDENABLE, enable ? TRUE : FALSE)));
        CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ZWRITEENABLE, enable ? FALSE : TRUE)));
        CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ZFUNC, D3DCMP_LESSEQUAL)));
        CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ZBIAS, enable ? 8 : 0)));
    };
    CHECK(experiment.start(device, {}, MipmapExperiment::Mode::Auto, message));
    CHECK(experiment.set_blend(true));
    blend_pass(true);
    // A blended draw alone must never queue a candidate.
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1) && !experiment.automatic().pending());
    blend_pass(false);
    CHECK(experiment.set_blend(false));
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(experiment.automatic().pending());
    experiment.present(device);
    experiment.present(device);
    CHECK(experiment.automatic().pending() && experiment.automatic().count() == 0);
    const auto finish = [device](MipmapExperiment& target) {
        for (int i = 0; i < 160 && target.automatic().pending(); ++i) {
            Sleep(1);
            target.present(device);
        }
    };
    finish(experiment);
    CHECK(experiment.automatic().count() == 1 && experiment.automatic().stats().generated == 1);
    CHECK(experiment.automatic().stats().diskMisses == 1 && experiment.automatic().stats().diskWrites == 1);
    {
        MipmapExperiment reopened;
        reopened.set_disk_directory(cache);
        CHECK(reopened.start(device, {}, MipmapExperiment::Mode::Auto, message));
        CHECK(!reopened.draw(device, D3DPT_TRIANGLELIST, 0, 1) && reopened.automatic().pending());
        finish(reopened);
        const auto& stats = reopened.automatic().stats();
        CHECK(reopened.automatic().count() == 1 && stats.diskHits == 1 && stats.diskWrites == 0 && stats.buildUs == 0);
        CHECK(reopened.draw(device, D3DPT_TRIANGLELIST, 0, 1));
        reopened.stop();
    }

    auto* otherColor = original_from_chain(device, folder / "pavement-b-color.dds");
    auto* otherDetail = original_from_chain(device, folder / "pavement-b-detail.dds");
    CHECK(SUCCEEDED(device->SetTexture(0, otherColor)));
    CHECK(SUCCEEDED(device->SetTexture(1, otherDetail)));
    experiment.set_cache_only(true);
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(!experiment.automatic().pending());
    experiment.set_cache_only(false);
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    finish(experiment);
    CHECK(experiment.automatic().count() == 2);

    {
        MipmapExperiment queued;
        queued.set_disk_directory(cache);
        CHECK(queued.start(device, {}, MipmapExperiment::Mode::Auto, message));
        CHECK(SUCCEEDED(device->SetTexture(0, color)));
        CHECK(SUCCEEDED(device->SetTexture(1, detail)));
        CHECK(!queued.draw(device, D3DPT_TRIANGLELIST, 0, 1));
        CHECK(!queued.draw(device, D3DPT_TRIANGLELIST, 0, 1));
        CHECK(queued.automatic().waiting() == 1);
        CHECK(SUCCEEDED(device->SetTexture(0, otherColor)));
        CHECK(SUCCEEDED(device->SetTexture(1, otherDetail)));
        CHECK(!queued.draw(device, D3DPT_TRIANGLELIST, 0, 1));
        CHECK(queued.automatic().waiting() == 2);
        finish(queued);
        const auto& stats = queued.automatic().stats();
        CHECK(queued.automatic().count() == 2 && stats.diskHits == 2 && stats.buildUs == 0);
        std::printf("PASS: queue deduplication and disk reuse for two textures (%llu overlapping Presents).\n",
                    stats.overlapFrames);
        queued.stop();
        CHECK(!queued.automatic().pending());
    }

    CHECK(SUCCEEDED(device->SetTexture(0, color)));
    CHECK(SUCCEEDED(device->SetTexture(1, detail)));
    CHECK(experiment.set_paused(true) && experiment.paused());
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    experiment.present(device);
    CHECK(experiment.automatic().count() == 2 && experiment.stats().color == 0);
    CHECK(experiment.set_paused(false) && !experiment.paused());
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(experiment.stats().color == 1 && experiment.stats().detail == 0);
    IDirect3DBaseTexture8* current = nullptr;
    CHECK(SUCCEEDED(device->GetTexture(0, &current)) && current == color); current->Release();
    CHECK(SUCCEEDED(device->GetTexture(1, &current)) && current == detail); current->Release();
    CHECK(SUCCEEDED(device->SetTextureStageState(0, D3DTSS_MIPFILTER, D3DTEXF_NONE)));
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(SUCCEEDED(device->SetTextureStageState(0, D3DTSS_MIPFILTER, D3DTEXF_LINEAR)));

    CHECK(SUCCEEDED(device->SetTexture(0, otherColor)));
    CHECK(SUCCEEDED(device->SetTexture(1, otherDetail)));
    for (int i = 0; i < 4; ++i) {
        CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
        experiment.present(device);
    }
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(SUCCEEDED(device->SetTexture(0, color)));
    CHECK(SUCCEEDED(device->SetTexture(1, detail)));

    CHECK(SUCCEEDED(device->SetTextureStageState(1, D3DTSS_MIPFILTER, D3DTEXF_LINEAR)));
    CHECK(experiment.set_detail(true));
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1) && experiment.automatic().pending());
    CHECK(experiment.stats().detail == 0);
    finish(experiment);
    CHECK(experiment.automatic().detail_count() == 1 && experiment.automatic().count() == 2);
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1) && experiment.stats().detail == 1);
    CHECK(SUCCEEDED(device->GetTexture(0, &current)) && current == color); current->Release();
    CHECK(SUCCEEDED(device->GetTexture(1, &current)) && current == detail); current->Release();
    CHECK(experiment.set_detail(false));
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1) && experiment.stats().detail == 1);
    CHECK(experiment.automatic().detail_count() == 1);

    // The cached detail chain stays available but obeys the game's sampler.
    CHECK(experiment.set_detail(true));
    CHECK(SUCCEEDED(device->SetTextureStageState(1, D3DTSS_MIPFILTER, D3DTEXF_NONE)));
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1) && experiment.stats().detail == 1);
    CHECK(SUCCEEDED(device->SetTextureStageState(1, D3DTSS_MIPFILTER, D3DTEXF_LINEAR)));
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1) && experiment.stats().detail == 2);

    const DWORD colorBias = std::bit_cast<DWORD>(-0.25f);
    const DWORD detailBias = std::bit_cast<DWORD>(0.125f);
    CHECK(SUCCEEDED(device->SetTextureStageState(0, D3DTSS_MIPMAPLODBIAS, colorBias)));
    CHECK(SUCCEEDED(device->SetTextureStageState(1, D3DTSS_MIPMAPLODBIAS, detailBias)));
    for (DWORD stage : {0u, 1u}) {
        CHECK(SUCCEEDED(device->SetTextureStageState(stage, D3DTSS_MINFILTER, D3DTEXF_POINT)));
        CHECK(SUCCEEDED(device->SetTextureStageState(stage, D3DTSS_MAGFILTER, D3DTEXF_LINEAR)));
    }
    CHECK(experiment.set_smoothing(device, true) && experiment.smoothing());
    CHECK(experiment.set_linear(device, true) && experiment.linear_enabled());
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1) && experiment.stats().smooth == 1);
    CHECK(experiment.stats().linear == 1 && experiment.stats().linearDetail == 1);
    DWORD readback = 0;
    CHECK(SUCCEEDED(device->GetTextureStageState(0, D3DTSS_MIPMAPLODBIAS, &readback)) && readback == colorBias);
    CHECK(SUCCEEDED(device->GetTextureStageState(1, D3DTSS_MIPMAPLODBIAS, &readback)) && readback == detailBias);
    for (DWORD stage : {0u, 1u}) {
        CHECK(SUCCEEDED(device->GetTextureStageState(stage, D3DTSS_MINFILTER, &readback)) && readback == D3DTEXF_POINT);
        CHECK(SUCCEEDED(device->GetTextureStageState(stage, D3DTSS_MAGFILTER, &readback)) && readback == D3DTEXF_LINEAR);
        CHECK(SUCCEEDED(device->GetTextureStageState(stage, D3DTSS_MIPFILTER, &readback)) && readback == D3DTEXF_LINEAR);
    }
    CHECK(experiment.stats().detail == 3 && experiment.automatic().detail_count() == 1);
    CHECK(experiment.set_smoothing(device, false) && !experiment.smoothing());
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1) && experiment.stats().smooth == 1);
    CHECK(experiment.stats().linear == 2 && experiment.stats().linearDetail == 2);
    CHECK(experiment.stats().detail == 4);

    blend_pass(true);
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(experiment.set_blend(true) && experiment.blend_enabled());
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(experiment.stats().blend == 1 && experiment.stats().blendDetail == 1);
    CHECK(experiment.stats().linear == 3 && experiment.stats().linearDetail == 3);
    CHECK(SUCCEEDED(device->GetTextureStageState(0, D3DTSS_MINFILTER, &readback)) && readback == D3DTEXF_POINT);
    CHECK(SUCCEEDED(device->GetTextureStageState(1, D3DTSS_MINFILTER, &readback)) && readback == D3DTEXF_POINT);
    CHECK(SUCCEEDED(device->GetTexture(0, &current)) && current == color); current->Release();
    CHECK(SUCCEEDED(device->GetTexture(1, &current)) && current == detail); current->Release();
    CHECK(SUCCEEDED(device->GetRenderState(D3DRS_ZBIAS, &readback)) && readback == 8);
    CHECK(SUCCEEDED(device->GetRenderState(D3DRS_ZWRITEENABLE, &readback)) && readback == FALSE);
    CHECK(SUCCEEDED(device->GetRenderState(D3DRS_ALPHABLENDENABLE, &readback)) && readback == TRUE);

    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ALPHATESTENABLE, TRUE)));
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ALPHATESTENABLE, FALSE)));
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ZBIAS, 0)));
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ZBIAS, 8)));
    CHECK(SUCCEEDED(device->SetTexture(1, otherDetail)));
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(SUCCEEDED(device->SetTexture(1, detail)));
    CHECK(!experiment.automatic().pending() && experiment.stats().blend == 1);
    CHECK(experiment.set_blend(false));
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    blend_pass(false);
    CHECK(experiment.set_linear(device, false) && !experiment.linear_enabled());
    CHECK(experiment.set_detail(false));
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1) && experiment.stats().linear == 3);

    D3DLOCKED_RECT lock{};
    CHECK(SUCCEEDED(detail->LockRect(0, &lock, nullptr, 0)));
    static_cast<BYTE*>(lock.pBits)[0] ^= 255;
    CHECK(SUCCEEDED(detail->UnlockRect(0)));
    for (int i = 0; i < 62; ++i) experiment.present(device);
    CHECK(experiment.automatic().stats().invalidated == 1 && experiment.automatic().detail_count() == 0);
    CHECK(experiment.automatic().count() == 2);

    CHECK(SUCCEEDED(color->LockRect(0, &lock, nullptr, 0)));
    static_cast<BYTE*>(lock.pBits)[0] ^= 255;
    CHECK(SUCCEEDED(color->UnlockRect(0)));
    for (int i = 0; i < 62; ++i) experiment.present(device);
    CHECK(experiment.automatic().stats().invalidated == 2 && experiment.automatic().count() == 1);
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(experiment.automatic().stats().errors == 0 && experiment.stats().failures == 0);
    experiment.stop();
    CHECK(otherColor->Release() == 0 && otherDetail->Release() == 0);

    std::printf("PASS: automatic generation without DDS files, material gate, staged work, "
                "first-use pacing, detail/smooth/blend/linear toggles, state restoration and invalidation.\n");
    const auto& stats = experiment.automatic().stats();
    std::printf("Standalone peaks (us): Present %llu, snapshot %llu, build thread %llu, "
                "create %llu, copy level %llu, first draw %llu.\n",
                stats.peakUs, stats.snapshotUs, stats.buildUs, stats.createUs, stats.uploadUs, stats.firstUseUs);

    CHECK(experiment.start(device, {}, MipmapExperiment::Mode::Auto, message));
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    experiment.present(device); // Snapshot and worker start.
    CHECK(experiment.automatic().pending());
    experiment.stop();
    CHECK(!experiment.automatic().pending() && experiment.automatic().count() == 0);
}

static void test_fixed_function_terrain(IDirect3DDevice8* device, IDirect3DTexture8* color)
{
    MipmapExperiment experiment;
    std::string message;
    CHECK(experiment.start_ground_mipmaps(device, message));
    constexpr DWORD fvf = D3DFVF_XYZ | D3DFVF_NORMAL | D3DFVF_DIFFUSE | D3DFVF_TEX1;
    struct Vertex { float xyz[3], normal[3]; DWORD diffuse; float uv[2]; };
    const Vertex vertices[] = {
        {{-.5f,-.5f,.5f}, {0,0,1}, 0xffffffff, {0,0}},
        {{ .5f,-.5f,.5f}, {0,0,1}, 0xffffffff, {1,0}},
        {{-.5f, .5f,.5f}, {0,0,1}, 0xffffffff, {0,1}},
    };
    Microsoft::WRL::ComPtr<IDirect3DVertexBuffer8> buffer;
    CHECK(SUCCEEDED(device->CreateVertexBuffer(sizeof(vertices), 0, fvf, D3DPOOL_MANAGED, buffer.GetAddressOf())));
    BYTE* data = nullptr;
    CHECK(SUCCEEDED(buffer->Lock(0, 0, &data, 0)));
    std::memcpy(data, vertices, sizeof(vertices));
    CHECK(SUCCEEDED(buffer->Unlock()));
    CHECK(SUCCEEDED(device->SetStreamSource(0, buffer.Get(), sizeof(Vertex))));
    CHECK(SUCCEEDED(device->SetVertexShader(fvf)));
    CHECK(SUCCEEDED(device->SetPixelShader(0)));
    CHECK(SUCCEEDED(device->SetTexture(0, color)));
    CHECK(SUCCEEDED(device->SetTexture(1, nullptr)));
    CHECK(SUCCEEDED(device->SetTextureStageState(0, D3DTSS_MINFILTER, D3DTEXF_POINT)));
    CHECK(SUCCEEDED(device->SetTextureStageState(0, D3DTSS_MIPFILTER, D3DTEXF_LINEAR)));
    CHECK(SUCCEEDED(device->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_DISABLE)));
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ZENABLE, D3DZB_TRUE)));
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ZWRITEENABLE, TRUE)));
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE)));
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ALPHATESTENABLE, FALSE)));
    CHECK(SUCCEEDED(device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE)));
    CHECK(!experiment.draw(device, D3DPT_TRIANGLESTRIP, 0, 1) && !experiment.automatic().pending());
    CHECK(SUCCEEDED(device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE2X)));
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1) && !experiment.automatic().pending());
    CHECK(!experiment.draw(device, D3DPT_TRIANGLESTRIP, 0, 1) && experiment.automatic().pending());
    for (unsigned i = 0; i < 160 && experiment.automatic().pending(); ++i) {
        Sleep(1);
        experiment.present(device);
    }
    CHECK(experiment.automatic().count() == 1 && experiment.automatic().stats().errors == 0);
    CHECK(experiment.draw(device, D3DPT_TRIANGLESTRIP, 0, 1));
    CHECK(experiment.stats().color == 1 && experiment.stats().linear == 1 && experiment.stats().detail == 0);
    CHECK(!experiment.automatic().pending() && experiment.automatic().detail_count() == 0);
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ZWRITEENABLE, FALSE)));
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE)));
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ZFUNC, D3DCMP_LESSEQUAL)));
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ZBIAS, 8)));
    CHECK(experiment.draw(device, D3DPT_TRIANGLESTRIP, 0, 1) && experiment.stats().blend == 1);
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ALPHATESTENABLE, TRUE)));
    CHECK(!experiment.draw(device, D3DPT_TRIANGLESTRIP, 0, 1));
    DWORD filter = 0;
    CHECK(SUCCEEDED(device->GetTextureStageState(0, D3DTSS_MINFILTER, &filter)) && filter == D3DTEXF_POINT);
    Microsoft::WRL::ComPtr<IDirect3DBaseTexture8> current;
    CHECK(SUCCEEDED(device->GetTexture(0, current.GetAddressOf())) && current.Get() == color);
    experiment.stop();
    std::puts("PASS: fixed-function terrain color mipmaps, blend, sampler restoration, and exclusion of other passes.");
}

static void test_mipmaps(IDirect3DDevice8* device, const std::filesystem::path& folder,
                         const std::filesystem::path& install)
{
    MipmapExperiment experiment;
    std::string message;
    const bool started = experiment.start(device, folder, MipmapExperiment::Mode::Color, message);
    std::puts(message.c_str());
    CHECK(started);

    auto* color = original_from_chain(device, folder / "pavement-a-color.dds");
    auto* detail = original_from_chain(device, folder / "pavement-a-detail.dds");
    CHECK(SUCCEEDED(device->SetTexture(0, color)));
    CHECK(SUCCEEDED(device->SetTexture(1, detail)));
    CHECK(SUCCEEDED(device->SetTextureStageState(0, D3DTSS_MIPFILTER, D3DTEXF_LINEAR)));
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ZWRITEENABLE, TRUE)));
    // ps_1_1: mov r0, c0
    const DWORD bytecode[] = {0xffff0101, 1, 0x800f0000, 0xa0e40000, 0xffff};
    DWORD shader = 0;
    CHECK(SUCCEEDED(device->CreatePixelShader(bytecode, &shader)));
    CHECK(SUCCEEDED(device->SetPixelShader(shader)));
    const DWORD fvf = D3DFVF_XYZRHW;
    const float vertices[][4] = {{2, 2, .5f, 1}, {50, 2, .5f, 1}, {2, 50, .5f, 1}};
    IDirect3DVertexBuffer8* vb = nullptr;
    CHECK(SUCCEEDED(device->CreateVertexBuffer(sizeof(vertices), 0, fvf, D3DPOOL_MANAGED, &vb)));
    BYTE* data = nullptr;
    CHECK(SUCCEEDED(vb->Lock(0, 0, &data, 0)));
    std::memcpy(data, vertices, sizeof(vertices));
    CHECK(SUCCEEDED(vb->Unlock()));
    CHECK(SUCCEEDED(device->SetVertexShader(fvf)));
    CHECK(SUCCEEDED(device->SetStreamSource(0, vb, sizeof(vertices[0]))));
    CHECK(SUCCEEDED(device->BeginScene()));

    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(experiment.stats().color == 1 && experiment.stats().detail == 0);
    CHECK(experiment.start(device, folder, MipmapExperiment::Mode::Pair, message));
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(experiment.stats().color == 2 && experiment.stats().detail == 2);
    CHECK(experiment.stats().checks == 2 && experiment.stats().failures == 0);
    IDirect3DBaseTexture8* current = nullptr;
    CHECK(SUCCEEDED(device->GetTexture(0, &current)) && current == color); current->Release();
    CHECK(SUCCEEDED(device->GetTexture(1, &current)) && current == detail); current->Release();

    // After a frame boundary, mutation of the original must invalidate the match.
    experiment.present(device);
    D3DLOCKED_RECT lock{};
    CHECK(SUCCEEDED(detail->LockRect(0, &lock, nullptr, 0)));
    static_cast<BYTE*>(lock.pBits)[0] ^= 255;
    CHECK(SUCCEEDED(detail->UnlockRect(0)));
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    CHECK(experiment.stats().color == 2 && experiment.stats().failures == 0);
    experiment.stop();
    CHECK(!experiment.draw(device, D3DPT_TRIANGLELIST, 0, 1));
    test_automatic_mips(device, experiment, folder, color, detail, install);
    test_fixed_function_terrain(device, color);

    CHECK(SUCCEEDED(device->EndScene()));
    CHECK(SUCCEEDED(device->SetTexture(0, nullptr)));
    CHECK(SUCCEEDED(device->SetTexture(1, nullptr)));
    CHECK(color->Release() == 0 && detail->Release() == 0);
    CHECK(SUCCEEDED(device->SetPixelShader(0)));
    CHECK(SUCCEEDED(device->DeletePixelShader(shader)));
    CHECK(SUCCEEDED(device->SetStreamSource(0, nullptr, 0)));
    vb->Release();
    std::puts("PASS: DDS upload, color/pair draws, cache reuse, binding restoration, invalidation, off.");
}

static void test_fog_state(IDirect3DDevice8* device)
{
    FogDeviceState fog;
    const FogDeviceState::Constant original{0.25f, 0.0f, 120.0f, 0.0f};
    const FogDeviceState::Constant forced{0.5f, 0.0f, 180.0f, 0.0f};
    const FogDeviceState::Constant later{0.75f, 0.0f, 150.0f, 0.0f};
    const D3DRENDERSTATETYPE states[] = {D3DRS_FOGSTART, D3DRS_FOGEND, D3DRS_FOGVERTEXMODE,
                                       D3DRS_FOGTABLEMODE, D3DRS_RANGEFOGENABLE};
    const DWORD defaults[] = {0x41A00000, 0x42F00000, D3DFOG_NONE, D3DFOG_EXP, TRUE};
    for (size_t i = 0; i < std::size(states); ++i)
        CHECK(SUCCEEDED(device->SetRenderState(states[i], defaults[i])));
    CHECK(SUCCEEDED(device->SetVertexShaderConstant(9, original.data(), 1)));
    fog.apply(device, 0x42200000, 0x43340000, forced);
    fog.apply(device, 0x42200000, 0x43340000, forced);

    // State blocks and shader constant writes can bypass Ashita's render-state callback.
    DWORD stateBlock = 0;
    CHECK(SUCCEEDED(device->BeginStateBlock()));
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_FOGVERTEXMODE, D3DFOG_EXP)));
    CHECK(SUCCEEDED(device->EndStateBlock(&stateBlock)));
    CHECK(SUCCEEDED(device->ApplyStateBlock(stateBlock)));
    CHECK(SUCCEEDED(device->DeleteStateBlock(stateBlock)));
    CHECK(SUCCEEDED(device->SetVertexShaderConstant(9, later.data(), 1)));
    fog.apply(device, 0x42200000, 0x43340000, forced);
    DWORD vertexFog = 0;
    CHECK(SUCCEEDED(device->GetRenderState(D3DRS_FOGVERTEXMODE, &vertexFog)) && vertexFog == D3DFOG_LINEAR);
    FogDeviceState::Constant live{};
    CHECK(SUCCEEDED(device->GetVertexShaderConstant(9, live.data(), 1)) && live == forced);

    fog.apply(device, 0x42200000, 0x43480000, forced);
    fog.observe(FogDeviceState::TableMode, D3DFOG_EXP2);
    fog.restore(device);
    for (size_t i = 0; i < std::size(states); ++i) {
        DWORD actual = 0;
        CHECK(SUCCEEDED(device->GetRenderState(states[i], &actual)));
        CHECK(actual == (states[i] == D3DRS_FOGTABLEMODE ? DWORD(D3DFOG_EXP2) : defaults[i]));
    }
    CHECK(SUCCEEDED(device->GetVertexShaderConstant(9, live.data(), 1)) && live == later);
    fog.apply(device, 0x42200000, 0x43340000, forced);
    CHECK(SUCCEEDED(device->SetVertexShaderConstant(9, original.data(), 1)));
    fog.restore(device);
    CHECK(SUCCEEDED(device->GetVertexShaderConstant(9, live.data(), 1)) && live == original);
    std::puts("PASS: fog write deduplication, state-block and shader changes, range updates and state restoration.");
}

int main(int argc, char** argv)
{
    CHECK(argc >= 2 && argc <= 4);
    test_bc2_generation();
    test_disk_cache(argv[1]);
    char system[MAX_PATH]{};
    CHECK(GetSystemDirectoryA(system, MAX_PATH));
    const std::string dll = std::string(system) + "\\d3d8.dll";
    HMODULE module = LoadLibraryA(argc >= 3 ? argv[2] : dll.c_str()); CHECK(module);
    auto create = reinterpret_cast<IDirect3D8* (WINAPI*)(UINT)>(GetProcAddress(module, "Direct3DCreate8"));
    CHECK(create);
    IDirect3D8* d3d = create(D3D_SDK_VERSION); CHECK(d3d);
    HWND window = CreateWindowExA(0, "STATIC", "VanaView rendering test", WS_POPUP,
        0, 0, 64, 64, nullptr, nullptr, GetModuleHandleA(nullptr), nullptr); CHECK(window);
    D3DPRESENT_PARAMETERS pp{};
    pp.Windowed = TRUE; pp.SwapEffect = D3DSWAPEFFECT_DISCARD; pp.hDeviceWindow = window;
    D3DDISPLAYMODE mode{}; CHECK(SUCCEEDED(d3d->GetAdapterDisplayMode(0, &mode)));
    pp.BackBufferFormat = mode.Format; pp.BackBufferCount = 1;
    pp.BackBufferWidth = 64; pp.BackBufferHeight = 64;
    pp.EnableAutoDepthStencil = TRUE; pp.AutoDepthStencilFormat = D3DFMT_D16;
    IDirect3DDevice8* device = nullptr;
    HRESULT hr = d3d->CreateDevice(0, D3DDEVTYPE_HAL, window, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &device);
    std::printf("CreateDevice HRESULT: %08lX\n", hr); CHECK(SUCCEEDED(hr));
    test_fog_state(device);
    CHECK(SUCCEEDED(device->SetRenderState(D3DRS_ZENABLE, D3DZB_TRUE)));
    if (argc == 4) test_mipmaps(device, argv[3], argv[1]);
    device->Release(); d3d->Release(); DestroyWindow(window); FreeLibrary(module);
    std::puts("PASS: Direct3D regression tests.");
}
