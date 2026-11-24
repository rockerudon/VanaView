#pragma once

#include "Dxt3Mipmaps.h"
#include <chrono>
#include <cstdio>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <tuple>

// Cache I/O runs on the worker. Keep the VVM1 payload format so existing
// chains can be reused. Small sidecars track use without rewriting a chain.
class MipmapDiskCache
{
public:
    static constexpr size_t Budget = 64 * 1024 * 1024;
    static constexpr size_t MaxPayload = 384 * 1024;

    static uint64_t key(const Dxt3::Layout& layout, const uint8_t* top)
    {
        const auto shape = (uint64_t(layout.width) << 32) | layout.height;
        return checksum(top, layout.top_bytes(), HashOffset ^ shape);
    }

    static bool load(const std::filesystem::path& dir, uint64_t id, Dxt3::Builder& builder, bool countUse = false)
    {
        const auto& layout = builder.layout;
        const std::size_t topBytes = layout.top_bytes();
        for (unsigned way = 0; way < Ways; ++way) {
            const auto path = slot(dir, id % Buckets, way);
            std::ifstream input(path, std::ios::binary | std::ios::ate);
            if (!input || input.tellg() != static_cast<std::streamoff>(sizeof(Header) + layout.bytes)) continue;
            input.seekg(0);
            Header header{};
            if (!input.read(reinterpret_cast<char*>(&header), sizeof(header)) ||
                header.signature != Signature || header.version != Algorithm || header.id != id ||
                header.width != layout.width || header.height != layout.height || header.bytes != layout.bytes) continue;

            std::vector<uint8_t> cached(layout.bytes);
            if (!input.read(reinterpret_cast<char*>(cached.data()), cached.size()) ||
                std::memcmp(cached.data(), builder.data.data(), topBytes) != 0 ||
                checksum(cached.data() + topBytes, cached.size() - topBytes) != header.lowerChecksum) continue;
            builder.data.swap(cached);
            input.close();
            if (countUse) {
                try { record_use(dir, path, id); }
                catch (...) {} // A valid chain remains usable if its access record cannot be saved.
            }
            return true;
        }
        return false;
    }

    static bool trim(const std::filesystem::path& dir)
    {
        std::error_code error;
        if (!std::filesystem::exists(dir, error)) return !error;
        const WriteLock lock(dir);
        if (!lock) return false;
        std::vector<Entry> entries;
        uintmax_t bytes = 0;
        return scan(dir, entries, bytes) && make_room(entries, bytes, {});
    }

    static bool store(const std::filesystem::path& dir, uint64_t id, const Dxt3::Builder& builder)
    {
        const auto& layout = builder.layout;
        if (layout.bytes > MaxPayload || builder.data.size() != layout.bytes) return false;
        std::error_code error;
        std::filesystem::create_directories(dir, error);
        if (error) return false;
        const WriteLock lock(dir);
        if (!lock) return false;

        std::vector<Entry> entries;
        uintmax_t bytes = 0;
        if (!scan(dir, entries, bytes)) return false;
        auto target = pick_slot(dir, id % Buckets, entries);
        const auto old = std::find_if(entries.begin(), entries.end(), [&](const Entry& entry) {
            return entry.path == target;
        });
        if (old != entries.end()) bytes -= old->size;

        const auto topBytes = layout.top_bytes();
        const Header header{Signature, Algorithm, static_cast<uint16_t>(layout.width),
            static_cast<uint16_t>(layout.height), static_cast<uint32_t>(layout.bytes), id,
            checksum(builder.data.data() + topBytes, layout.bytes - topBytes)};
        const auto temp = dir / L"chain.tmp";
        const auto usage = use_path(target);
        const auto usageTemp = dir / L"usage.tmp";
        if (!make_room(entries, bytes + sizeof(header) + layout.bytes, target) ||
            !write_temp(temp, &header, sizeof(header), builder.data.data(), builder.data.size())) return false;

        // Clear the old slot's count before publishing a different chain there.
        if (!remove_file(usage)) {
            DeleteFileW(temp.c_str());
            return false;
        }
        if (!publish(temp, target)) return false;
        save_use(usageTemp, usage, id, FileTime::clock::now(), 1);
        return true;
    }

private:
    using Path = std::filesystem::path;
    using FileTime = std::filesystem::file_time_type;
    static constexpr unsigned Buckets = 80, Ways = 4;
    // Reserve space for metadata and one staged payload during replacement.
    static constexpr uintmax_t PayloadBudget = Budget - 512 * 1024;
    static constexpr uint32_t Signature = 0x314D5656; // VVM1
    static constexpr uint32_t Algorithm = 1;
    static constexpr uint32_t UseSignature = 0x31555656; // VVU1
    static constexpr uint64_t HashOffset = 14695981039346656037ull;
    static constexpr auto DecayInterval = std::chrono::days(14);

    struct Header
    {
        uint32_t signature, version;
        uint16_t width, height;
        uint32_t bytes;
        uint64_t id, lowerChecksum;
    };
    static_assert(sizeof(Header) == 32);

    struct Usage
    {
        uint32_t signature, count;
        uint64_t id;
        int64_t last;
    };
    static_assert(sizeof(Usage) == 24);

    struct Entry
    {
        Path path;
        unsigned bucket;
        unsigned way;
        uintmax_t size;
        uint32_t score = 0;
        FileTime last{};
    };

    class WriteLock
    {
    public:
        explicit WriteLock(const Path& dir)
            : m_handle(CreateFileW((dir / L"cache.lock").c_str(), GENERIC_WRITE, 0, nullptr,
                                   OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr))
        {}
        WriteLock(const WriteLock&) = delete;
        WriteLock& operator=(const WriteLock&) = delete;
        ~WriteLock() { if (*this) CloseHandle(m_handle); }
        explicit operator bool() const { return m_handle != INVALID_HANDLE_VALUE; }

    private:
        HANDLE m_handle;
    };

    static Path slot(const Path& dir, unsigned bucket, unsigned way)
    {
        return dir / (L"mip-" + std::to_wstring(bucket) + L"-" + std::to_wstring(way) + L".bc2");
    }

    static Path use_path(Path path)
    {
        return path.replace_extension(L".use");
    }

    static bool scan(const Path& dir, std::vector<Entry>& entries, uintmax_t& bytes)
    {
        std::error_code error;
        for (std::filesystem::directory_iterator it(dir, error), end; !error && it != end; it.increment(error)) {
            const auto name = it->path().filename().wstring();
            unsigned bucket = 0, way = 0;
            if (swscanf_s(name.c_str(), L"mip-%2u-%1u", &bucket, &way) != 2 ||
                bucket >= Buckets || way >= Ways || slot({}, bucket, way).native() != name) continue;
            if (!std::filesystem::is_regular_file(it->symlink_status(error))) continue;
            const auto size = it->file_size(error);
            if (error) return false;
            entries.push_back({it->path(), bucket, way, size});
            bytes += size;
        }
        return !error;
    }

    static Usage read_use(const Path& path)
    {
        std::ifstream file(path, std::ios::binary);
        Usage usage{};
        if (!file.read(reinterpret_cast<char*>(&usage), sizeof(usage)) || usage.signature != UseSignature) return {};
        return usage;
    }

    static FileTime time_of(const Usage& usage)
    {
        return FileTime(FileTime::duration(usage.last));
    }

    static uint32_t score_at(const Usage& usage, FileTime now)
    {
        const auto last = time_of(usage);
        if (!usage.count || last < now - DecayInterval * 32) return 0;
        const auto idle = now - std::min(now, last);
        const auto intervals = idle / DecayInterval;
        return intervals >= 32 ? 0 : usage.count >> intervals;
    }

    static void rank(Entry& entry, FileTime now)
    {
        const auto usage = read_use(use_path(entry.path));
        entry.score = score_at(usage, now);
        if (usage.count) {
            entry.last = std::min(now, time_of(usage));
        } else {
            std::error_code error;
            entry.last = std::filesystem::last_write_time(entry.path, error);
            if (error) entry.last = FileTime::min();
        }
    }

    static bool less_used(const Entry& a, const Entry& b)
    {
        return std::tie(a.score, a.last, a.bucket, a.way) < std::tie(b.score, b.last, b.bucket, b.way);
    }

    static Path pick_slot(const Path& dir, unsigned bucket, std::vector<Entry>& entries)
    {
        std::array<Entry*, Ways> ways{};
        for (auto& entry : entries)
            if (entry.bucket == bucket) ways[entry.way] = &entry;
        for (unsigned way = 0; way < Ways; ++way)
            if (!ways[way]) return slot(dir, bucket, way);

        const auto now = FileTime::clock::now();
        for (auto* entry : ways) rank(*entry, now);
        return (*std::min_element(ways.begin(), ways.end(), [](auto* a, auto* b) {
            return less_used(*a, *b);
        }))->path;
    }

    static bool make_room(std::vector<Entry>& entries, uintmax_t bytes, const Path& keep)
    {
        if (bytes <= PayloadBudget) return true;
        const auto now = FileTime::clock::now();
        for (auto& entry : entries) rank(entry, now);
        std::sort(entries.begin(), entries.end(), less_used);
        for (const auto& entry : entries) {
            if (entry.path == keep || !remove_file(entry.path)) continue;
            bytes -= entry.size;
            remove_file(use_path(entry.path));
            if (bytes <= PayloadBudget) return true;
        }
        return false;
    }

    static bool remove_file(const Path& path)
    {
        std::error_code error;
        std::filesystem::remove(path, error);
        return !error;
    }

    static bool write_temp(const Path& temp, const void* header, size_t size, const uint8_t* data = nullptr,
                           size_t bytes = 0)
    {
        FILE* file = nullptr;
        if (_wfopen_s(&file, temp.c_str(), L"wb") != 0 || !file) return false;
        const bool wrote = std::fwrite(header, 1, size, file) == size &&
            (!bytes || std::fwrite(data, 1, bytes, file) == bytes);
        const bool closed = std::fclose(file) == 0;
        if (wrote && closed) return true;
        DeleteFileW(temp.c_str());
        return false;
    }

    static bool publish(const Path& temp, const Path& target)
    {
        if (MoveFileExW(temp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING)) return true;
        DeleteFileW(temp.c_str());
        return false;
    }

    static void save_use(const Path& temp, const Path& path, uint64_t id, FileTime now, uint32_t count)
    {
        const Usage usage{UseSignature, count, id, now.time_since_epoch().count()};
        if (write_temp(temp, &usage, sizeof(usage))) publish(temp, path);
    }

    static void record_use(const Path& dir, const Path& path, uint64_t id)
    {
        const WriteLock lock(dir);
        if (!lock) return;
        // The slot may have been replaced between the read and the write lock.
        std::ifstream file(path, std::ios::binary);
        Header header{};
        if (!file.read(reinterpret_cast<char*>(&header), sizeof(header)) || header.signature != Signature ||
            header.version != Algorithm || header.id != id) return;

        const auto target = use_path(path);
        const auto old = read_use(target);
        const auto now = FileTime::clock::now();
        uint32_t count = old.id == id ? score_at(old, now) : 0;
        if (count < UINT32_MAX) ++count;
        save_use(dir / L"usage.tmp", target, id, now, count);
    }

    static uint64_t checksum(const uint8_t* data, size_t bytes, uint64_t hash = HashOffset)
    {
        for (size_t i = 0; i < bytes; ++i) hash = (hash ^ data[i]) * 1099511628211ull;
        return hash;
    }
};
