/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include "linglong/runtime/host_nvidia_extension.h"

#include "linglong/utils/log/log.h"

#include <glob.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <elf.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace linglong::runtime {

namespace {

constexpr const char *kMountTypeBind = "bind";

const std::vector<std::string> kBindRoOptions = {
    "rbind",
    "ro",
};

const std::vector<std::string> kIpcMountOptions = {
    "ro",
    "nosuid",
    "nodev",
    "rbind",
    "rprivate",
    "noexec",
};

std::string trim(std::string_view input)
{
    size_t start = 0;
    while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start]))) {
        ++start;
    }
    if (start == input.size()) {
        return {};
    }
    size_t end = input.size() - 1;
    while (end > start && std::isspace(static_cast<unsigned char>(input[end]))) {
        --end;
    }
    return std::string(input.substr(start, end - start + 1));
}

bool isRegularOrSymlink(const std::filesystem::path &path)
{
    std::error_code ec;
    if (std::filesystem::is_regular_file(path, ec)) {
        return true;
    }
    ec.clear();
    if (std::filesystem::is_symlink(path, ec)) {
        return true;
    }
    return false;
}

bool isDirectory(const std::filesystem::path &path)
{
    std::error_code ec;
    return std::filesystem::is_directory(path, ec);
}

bool isCharOrBlockDevice(const std::filesystem::path &path)
{
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) {
        return false;
    }
    return S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode);
}

std::vector<std::filesystem::path> splitPathList(const std::string &value)
{
    std::vector<std::filesystem::path> parts;
    size_t start = 0;
    while (start <= value.size()) {
        size_t end = value.find(':', start);
        std::string item = (end == std::string::npos)
          ? value.substr(start)
          : value.substr(start, end - start);
        if (!item.empty()) {
            parts.emplace_back(item);
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    return parts;
}

std::vector<std::filesystem::path> dedupPaths(const std::vector<std::filesystem::path> &paths)
{
    std::vector<std::filesystem::path> result;
    std::unordered_set<std::string> seen;
    for (const auto &path : paths) {
        auto key = path.lexically_normal().string();
        if (seen.insert(key).second) {
            result.push_back(path);
        }
    }
    return result;
}

std::vector<std::filesystem::path> defaultLibrarySearchPaths()
{
    std::vector<std::filesystem::path> paths = {
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/i386-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu/nvidia/current",
        "/usr/lib/i386-linux-gnu/nvidia/current",
        "/usr/lib/aarch64-linux-gnu/nvidia/current",
        "/lib64",
        "/lib/x86_64-linux-gnu",
        "/lib/i386-linux-gnu",
        "/lib/aarch64-linux-gnu",
        "/lib/x86_64-linux-gnu/nvidia/current",
        "/lib/i386-linux-gnu/nvidia/current",
        "/lib/aarch64-linux-gnu/nvidia/current",
        "/usr/lib",
        "/lib",
    };
    return dedupPaths(paths);
}

std::vector<std::filesystem::path> xdgDataDirs()
{
    const char *env = std::getenv("XDG_DATA_DIRS");
    if (env && env[0] != '\0') {
        return splitPathList(env);
    }
    return { "/usr/local/share", "/usr/share" };
}

std::vector<std::filesystem::path> defaultConfigSearchPaths()
{
    std::vector<std::filesystem::path> paths = { "/etc" };
    auto extra = xdgDataDirs();
    paths.insert(paths.end(), extra.begin(), extra.end());
    return dedupPaths(paths);
}

const std::array<std::string, 7> kAllowedHostRoots = {
    "/usr",
    "/lib",
    "/lib64",
    "/etc",
    "/bin",
    "/sbin",
    "/opt",
};

std::optional<std::filesystem::path> hostRootForPath(const std::filesystem::path &path)
{
    if (!path.is_absolute()) {
        return std::nullopt;
    }
    auto rel = path.relative_path();
    auto it = rel.begin();
    if (it == rel.end()) {
        return std::nullopt;
    }
    std::filesystem::path root = std::filesystem::path("/") / *it;
    auto rootStr = root.string();
    for (const auto &allowed : kAllowedHostRoots) {
        if (rootStr == allowed) {
            return root;
        }
    }
    return std::nullopt;
}

std::filesystem::path hostTargetPath(const std::filesystem::path &source, const std::string &prefix)
{
    return std::filesystem::path(prefix) / "host" / source.relative_path();
}

std::optional<std::string> readFileToString(const std::filesystem::path &path)
{
    std::ifstream in(path);
    if (!in.is_open()) {
        return std::nullopt;
    }
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

std::optional<std::string> extractVersionToken(std::string_view text)
{
    for (size_t i = 0; i < text.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(text[i]))) {
            continue;
        }
        size_t start = i;
        bool hasDot = false;
        for (; i < text.size(); ++i) {
            char c = text[i];
            if (c == '.') {
                hasDot = true;
                continue;
            }
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                break;
            }
        }
        if (hasDot) {
            return std::string(text.substr(start, i - start));
        }
    }
    return std::nullopt;
}

std::optional<std::string> readDriverVersion()
{
    if (auto sys = readFileToString("/sys/module/nvidia/version")) {
        auto version = trim(*sys);
        if (!version.empty()) {
            return version;
        }
    }

    if (auto proc = readFileToString("/proc/driver/nvidia/version")) {
        auto version = extractVersionToken(*proc);
        if (version) {
            return version;
        }
    }

    return std::nullopt;
}

std::optional<std::string> versionFromFilename(const std::string &filename,
                                               const std::string &prefix)
{
    if (filename.rfind(prefix, 0) != 0) {
        return std::nullopt;
    }
    auto version = filename.substr(prefix.size());
    if (version.empty()) {
        return std::nullopt;
    }
    return version;
}

int compareVersionStrings(const std::string &left, const std::string &right)
{
    auto split = [](const std::string &value) {
        std::vector<int> parts;
        std::string current;
        for (char c : value) {
            if (c == '.') {
                if (!current.empty()) {
                    parts.push_back(std::stoi(current));
                    current.clear();
                } else {
                    parts.push_back(0);
                }
                continue;
            }
            if (std::isdigit(static_cast<unsigned char>(c))) {
                current.push_back(c);
            } else {
                break;
            }
        }
        if (!current.empty()) {
            parts.push_back(std::stoi(current));
        }
        return parts;
    };

    auto lhs = split(left);
    auto rhs = split(right);
    size_t count = std::max(lhs.size(), rhs.size());
    lhs.resize(count);
    rhs.resize(count);
    for (size_t i = 0; i < count; ++i) {
        if (lhs[i] < rhs[i]) {
            return -1;
        }
        if (lhs[i] > rhs[i]) {
            return 1;
        }
    }
    return 0;
}

std::vector<std::filesystem::path>
collectGlobMatches(const std::vector<std::filesystem::path> &prefixes,
                   const std::string &pattern)
{
    std::vector<std::filesystem::path> matches;
    std::unordered_set<std::string> seen;

    auto addPath = [&](const std::string &pathStr) {
        std::filesystem::path p(pathStr);
        auto key = p.lexically_normal().string();
        if (seen.insert(key).second) {
            matches.push_back(std::move(p));
        }
    };

    auto runGlob = [&](const std::string &pathPattern) {
        glob_t g{};
        if (::glob(pathPattern.c_str(), GLOB_NOSORT, nullptr, &g) == 0) {
            for (size_t i = 0; i < g.gl_pathc; ++i) {
                addPath(g.gl_pathv[i]);
            }
        }
        globfree(&g);
    };

    if (std::filesystem::path(pattern).is_absolute()) {
        runGlob(pattern);
        return matches;
    }

    for (const auto &prefix : prefixes) {
        auto pathPattern = (prefix / pattern).string();
        runGlob(pathPattern);
    }

    return matches;
}

std::vector<std::filesystem::path>
collectFiles(const std::vector<std::filesystem::path> &prefixes, const std::string &pattern)
{
    std::vector<std::filesystem::path> matches = collectGlobMatches(prefixes, pattern);
    std::vector<std::filesystem::path> filtered;
    filtered.reserve(matches.size());
    for (const auto &path : matches) {
        if (isRegularOrSymlink(path)) {
            filtered.push_back(path);
        }
    }
    return filtered;
}

std::optional<std::filesystem::path> findFirstExisting(const std::vector<std::filesystem::path> &roots,
                                                       const std::filesystem::path &relative)
{
    for (const auto &root : roots) {
        std::filesystem::path candidate = root / relative;
        if (isRegularOrSymlink(candidate)) {
            return candidate;
        }
    }
    return std::nullopt;
}

std::optional<std::filesystem::path> findExecutable(const std::string &name)
{
    std::vector<std::filesystem::path> search;
    const char *pathEnv = std::getenv("PATH");
    if (pathEnv && pathEnv[0] != '\0') {
        auto parts = splitPathList(pathEnv);
        search.insert(search.end(), parts.begin(), parts.end());
    }
    const std::vector<std::filesystem::path> defaults = {
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    };
    search.insert(search.end(), defaults.begin(), defaults.end());
    search = dedupPaths(search);

    for (const auto &dir : search) {
        std::filesystem::path candidate = dir / name;
        if (!isRegularOrSymlink(candidate)) {
            continue;
        }
        if (::access(candidate.c_str(), X_OK) == 0) {
            return candidate;
        }
    }
    return std::nullopt;
}

std::string utsRelease()
{
    struct utsname uts{};
    if (::uname(&uts) == 0) {
        return std::string(uts.release);
    }
    return {};
}

std::vector<std::filesystem::path> firmwareSearchPaths()
{
    std::vector<std::filesystem::path> paths;

    if (auto custom = readFileToString("/sys/module/firmware_class/parameters/path")) {
        auto trimmed = trim(*custom);
        if (!trimmed.empty()) {
            paths.emplace_back(trimmed);
        }
    }

    auto release = utsRelease();
    if (!release.empty()) {
        paths.emplace_back(std::filesystem::path("/lib/firmware/updates") / release);
    }
    paths.emplace_back("/lib/firmware/updates");
    if (!release.empty()) {
        paths.emplace_back(std::filesystem::path("/lib/firmware") / release);
    }
    paths.emplace_back("/lib/firmware");

    return dedupPaths(paths);
}

struct DriverInfo
{
    std::string version;
    std::filesystem::path libDir;
};

std::optional<std::filesystem::path>
selectBestVersionedLib(const std::vector<std::filesystem::path> &paths,
                       const std::string &prefix,
                       const std::optional<std::string> &preferVersion)
{
    std::optional<std::filesystem::path> best;
    std::optional<std::string> bestVersion;

    for (const auto &path : paths) {
        auto name = path.filename().string();
        auto version = versionFromFilename(name, prefix);
        if (!version) {
            continue;
        }
        if (preferVersion && *version != *preferVersion) {
            continue;
        }
        if (!best || compareVersionStrings(*version, *bestVersion) > 0) {
            best = path;
            bestVersion = version;
        }
    }

    if (best) {
        return best;
    }

    if (preferVersion) {
        for (const auto &path : paths) {
            auto name = path.filename().string();
            auto version = versionFromFilename(name, prefix);
            if (!version) {
                continue;
            }
            if (!best || compareVersionStrings(*version, *bestVersion) > 0) {
                best = path;
                bestVersion = version;
            }
        }
    }

    return best;
}

DriverInfo detectDriverInfo()
{
    DriverInfo info;
    info.version = readDriverVersion().value_or("");

    auto searchPaths = defaultLibrarySearchPaths();
    auto cudaCandidates = collectFiles(searchPaths, "libcuda.so.*");
    auto nvidiaMlCandidates = collectFiles(searchPaths, "libnvidia-ml.so.*");

    std::optional<std::filesystem::path> selected;
    if (!cudaCandidates.empty()) {
        selected = selectBestVersionedLib(cudaCandidates, "libcuda.so.",
                                          info.version.empty()
                                            ? std::optional<std::string>{}
                                            : std::optional<std::string>{ info.version });
    }
    if (!selected && !nvidiaMlCandidates.empty()) {
        selected = selectBestVersionedLib(nvidiaMlCandidates, "libnvidia-ml.so.",
                                          info.version.empty()
                                            ? std::optional<std::string>{}
                                            : std::optional<std::string>{ info.version });
    }

    if (selected) {
        if (info.version.empty()) {
            auto name = selected->filename().string();
            if (auto version = versionFromFilename(name, "libcuda.so.")) {
                info.version = *version;
            } else if (auto version = versionFromFilename(name, "libnvidia-ml.so.")) {
                info.version = *version;
            }
        }
        info.libDir = selected->parent_path();
    }

    if (info.libDir.empty()) {
        for (const auto &path : searchPaths) {
            if (isDirectory(path)) {
                info.libDir = path;
                break;
            }
        }
    }

    return info;
}

std::vector<std::filesystem::path> buildXOrgSearchPaths(const std::filesystem::path &libRoot)
{
    std::vector<std::filesystem::path> paths;
    if (!libRoot.empty()) {
        paths.push_back(libRoot / "nvidia" / "xorg");
        paths.push_back(libRoot / "xorg" / "modules" / "drivers");
        paths.push_back(libRoot / "xorg" / "modules" / "extensions");
        paths.push_back(libRoot / "xorg" / "modules/updates" / "drivers");
        paths.push_back(libRoot / "xorg" / "modules/updates" / "extensions");
    }

    const std::array<std::filesystem::path, 16> fallback = {
        "/usr/lib/xorg/modules/drivers",
        "/usr/lib/xorg/modules/extensions",
        "/usr/lib/xorg/modules/updates/drivers",
        "/usr/lib/xorg/modules/updates/extensions",
        "/usr/lib64/xorg/modules/drivers",
        "/usr/lib64/xorg/modules/extensions",
        "/usr/lib64/xorg/modules/updates/drivers",
        "/usr/lib64/xorg/modules/updates/extensions",
        "/usr/X11R6/lib/modules/drivers",
        "/usr/X11R6/lib/modules/extensions",
        "/usr/X11R6/lib/modules/updates/drivers",
        "/usr/X11R6/lib/modules/updates/extensions",
        "/usr/X11R6/lib64/modules/drivers",
        "/usr/X11R6/lib64/modules/extensions",
        "/usr/X11R6/lib64/modules/updates/drivers",
        "/usr/X11R6/lib64/modules/updates/extensions",
    };
    for (const auto &item : fallback) {
        paths.push_back(item);
    }

    return dedupPaths(paths);
}

template <typename Ehdr, typename Phdr, typename Dyn>
std::optional<std::string> readElfSonameImpl(std::ifstream &file)
{
    Ehdr header{};
    file.seekg(0);
    file.read(reinterpret_cast<char *>(&header), sizeof(header));
    if (!file) {
        return std::nullopt;
    }
    if (header.e_phoff == 0 || header.e_phnum == 0) {
        return std::nullopt;
    }

    file.seekg(header.e_phoff);
    std::vector<Phdr> phdrs(header.e_phnum);
    file.read(reinterpret_cast<char *>(phdrs.data()), sizeof(Phdr) * phdrs.size());
    if (!file) {
        return std::nullopt;
    }

    std::optional<Phdr> dynamicPhdr;
    for (const auto &phdr : phdrs) {
        if (phdr.p_type == PT_DYNAMIC) {
            dynamicPhdr = phdr;
            break;
        }
    }
    if (!dynamicPhdr || dynamicPhdr->p_offset == 0 || dynamicPhdr->p_filesz == 0) {
        return std::nullopt;
    }

    file.seekg(dynamicPhdr->p_offset);
    size_t entryCount = dynamicPhdr->p_filesz / sizeof(Dyn);
    std::optional<std::uint64_t> sonameOffset;
    std::optional<std::uint64_t> strtabAddr;
    std::optional<std::uint64_t> strtabSize;
    for (size_t i = 0; i < entryCount; ++i) {
        Dyn entry{};
        file.read(reinterpret_cast<char *>(&entry), sizeof(entry));
        if (!file) {
            return std::nullopt;
        }
        if (entry.d_tag == DT_NULL) {
            break;
        }
        if (entry.d_tag == DT_SONAME) {
            sonameOffset = static_cast<std::uint64_t>(entry.d_un.d_val);
        } else if (entry.d_tag == DT_STRTAB) {
            strtabAddr = static_cast<std::uint64_t>(entry.d_un.d_ptr);
        } else if (entry.d_tag == DT_STRSZ) {
            strtabSize = static_cast<std::uint64_t>(entry.d_un.d_val);
        }
    }

    if (!sonameOffset || !strtabAddr || !strtabSize) {
        return std::nullopt;
    }

    std::optional<std::uint64_t> strtabOffset;
    for (const auto &phdr : phdrs) {
        if (phdr.p_type != PT_LOAD) {
            continue;
        }
        auto begin = static_cast<std::uint64_t>(phdr.p_vaddr);
        auto end = begin + static_cast<std::uint64_t>(phdr.p_memsz);
        auto addr = static_cast<std::uint64_t>(*strtabAddr);
        if (addr >= begin && addr < end) {
            strtabOffset = static_cast<std::uint64_t>(phdr.p_offset) + (addr - begin);
            break;
        }
    }
    if (!strtabOffset) {
        return std::nullopt;
    }

    std::vector<char> buffer(*strtabSize);
    file.seekg(*strtabOffset);
    file.read(buffer.data(), buffer.size());
    if (!file) {
        return std::nullopt;
    }

    if (*sonameOffset >= buffer.size()) {
        return std::nullopt;
    }

    const char *start = buffer.data() + *sonameOffset;
    size_t maxLen = buffer.size() - *sonameOffset;
    size_t len = strnlen(start, maxLen);
    if (len == 0 || len == maxLen) {
        return std::nullopt;
    }

    return std::string(start, len);
}

std::optional<std::string> readElfSoname(const std::filesystem::path &path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return std::nullopt;
    }

    unsigned char ident[EI_NIDENT]{};
    file.read(reinterpret_cast<char *>(ident), sizeof(ident));
    if (!file) {
        return std::nullopt;
    }
    if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 || ident[EI_MAG2] != ELFMAG2
        || ident[EI_MAG3] != ELFMAG3) {
        return std::nullopt;
    }
    if (ident[EI_DATA] != ELFDATA2LSB) {
        return std::nullopt;
    }

    if (ident[EI_CLASS] == ELFCLASS64) {
        return readElfSonameImpl<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn>(file);
    }
    if (ident[EI_CLASS] == ELFCLASS32) {
        return readElfSonameImpl<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn>(file);
    }
    return std::nullopt;
}

bool isElf32(const std::filesystem::path &path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        return false;
    }

    std::array<unsigned char, 5> header{};
    stream.read(reinterpret_cast<char *>(header.data()), header.size());
    if (!stream || header[0] != 0x7f || header[1] != 'E' || header[2] != 'L'
        || header[3] != 'F') {
        return false;
    }

    return header[4] == 1;
}

std::string joinWithColon(const std::vector<std::string> &paths)
{
    std::string merged;
    for (size_t i = 0; i < paths.size(); ++i) {
        if (i) {
            merged.push_back(':');
        }
        merged.append(paths[i]);
    }
    return merged;
}

void appendUnique(std::unordered_set<std::string> &seen,
                  std::vector<std::string> &ordered,
                  const std::string &value)
{
    if (!value.empty() && seen.insert(value).second) {
        ordered.push_back(value);
    }
}

void appendEnvPath(std::map<std::string, std::string> &envMap,
                   const std::string &key,
                   const std::vector<std::string> &paths)
{
    if (paths.empty()) {
        return;
    }
    std::vector<std::string> ordered;
    std::unordered_set<std::string> seen;
    for (const auto &path : paths) {
        if (!path.empty() && seen.insert(path).second) {
            ordered.push_back(path);
        }
    }

    auto it = envMap.find(key);
    if (it != envMap.end() && !it->second.empty()) {
        const auto &current = it->second;
        size_t start = 0;
        while (start <= current.size()) {
            size_t end = current.find(':', start);
            std::string segment = (end == std::string::npos)
              ? current.substr(start)
              : current.substr(start, end - start);
            if (!segment.empty() && seen.insert(segment).second) {
                ordered.push_back(segment);
            }
            if (end == std::string::npos) {
                break;
            }
            start = end + 1;
        }
    }

    if (ordered.empty()) {
        return;
    }
    envMap[key] = joinWithColon(ordered);
}

void setEnvIfEmpty(std::map<std::string, std::string> &envMap,
                   const std::string &key,
                   const std::string &value)
{
    if (value.empty()) {
        return;
    }
    auto it = envMap.find(key);
    if (it != envMap.end() && !it->second.empty()) {
        return;
    }
    envMap[key] = value;
}

bool ensureSymlink(const std::filesystem::path &target, const std::filesystem::path &linkPath)
{
    std::error_code ec;
    if (std::filesystem::exists(linkPath, ec)) {
        ec.clear();
        if (std::filesystem::is_symlink(linkPath, ec)) {
            auto existing = std::filesystem::read_symlink(linkPath, ec);
            if (!ec && existing == target) {
                return true;
            }
        }
        ec.clear();
        std::filesystem::remove(linkPath, ec);
        if (ec) {
            LogW("failed to remove existing path {}: {}", linkPath.string(), ec.message());
            return false;
        }
    }

    std::filesystem::create_directories(linkPath.parent_path(), ec);
    if (ec) {
        LogW("failed to create dir {}: {}", linkPath.parent_path().string(), ec.message());
        return false;
    }
    ec.clear();
    std::filesystem::create_symlink(target, linkPath, ec);
    if (ec) {
        LogW("failed to create symlink {} -> {}: {}", linkPath.string(), target.string(), ec.message());
        return false;
    }
    return true;
}

} // namespace

utils::error::Result<std::optional<HostNvidiaExtension>>
prepareHostNvidiaExtension(const std::filesystem::path &bundle,
                           const std::string &extensionName) noexcept
{
    LINGLONG_TRACE("prepare host NVIDIA extension");

    if (bundle.empty() || extensionName.empty()) {
        return std::optional<HostNvidiaExtension>{};
    }

    HostNvidiaExtension ext;
    ext.name = extensionName;
    ext.root = bundle / "host-extensions" / extensionName;

    std::error_code ec;
    std::filesystem::create_directories(ext.root, ec);
    if (ec) {
        return LINGLONG_ERR("failed to create host extension root: " + ec.message());
    }

    std::string prefix = "/opt/extensions/" + extensionName;
    DriverInfo driver = detectDriverInfo();

    std::vector<std::filesystem::path> libSearchPaths = defaultLibrarySearchPaths();
    if (!driver.libDir.empty()) {
        libSearchPaths.insert(libSearchPaths.begin(), driver.libDir);
    }
    libSearchPaths = dedupPaths(libSearchPaths);

    std::string versionPattern = driver.version.empty() ? "*.*" : driver.version;

    std::unordered_set<std::string> libSeen;
    std::unordered_set<std::string> fileSeen;
    std::vector<std::filesystem::path> libFiles;
    std::vector<std::filesystem::path> otherFiles;
    std::unordered_set<std::string> hostRootSet;
    std::vector<std::filesystem::path> hostRoots;

    auto addFile = [&](const std::filesystem::path &path, bool isLib) {
        if (path.empty()) {
            return;
        }
        auto key = path.lexically_normal().string();
        if (isLib) {
            if (libSeen.insert(key).second) {
                libFiles.push_back(path);
            }
            return;
        }
        if (fileSeen.insert(key).second) {
            otherFiles.push_back(path);
        }
    };

    if (!driver.libDir.empty()) {
        auto versioned = collectFiles({ driver.libDir, driver.libDir / "vdpau" },
                                      "*.so." + versionPattern);
        for (const auto &path : versioned) {
            addFile(path, true);
        }
    }

    const std::array<std::string, 11> explicitLibs = {
        "libEGL.so",
        "libGL.so",
        "libGLESv1_CM.so",
        "libGLESv2.so",
        "libGLX.so",
        "libGLdispatch.so",
        "libOpenCL.so",
        "libOpenGL.so",
        "libnvidia-api.so",
        "libnvidia-egl-xcb.so",
        "libnvidia-egl-xlib.so",
    };
    for (const auto &lib : explicitLibs) {
        auto located = collectFiles(libSearchPaths, lib);
        for (const auto &path : located) {
            addFile(path, true);
        }
    }

    const std::array<std::string, 11> graphicsLibs = {
        "libGLX_nvidia.so.*",
        "libEGL_nvidia.so.*",
        "libGLESv1_CM_nvidia.so.*",
        "libGLESv2_nvidia.so.*",
        "libnvidia-glcore.so.*",
        "libnvidia-glsi.so.*",
        "libnvidia-tls.so.*",
        "libnvidia-*.so.*",
        "libnvidia-egl-gbm.so.*.*",
        "libnvidia-egl-wayland.so.*.*",
        "libnvidia-vulkan-producer.so.*",
    };
    for (const auto &lib : graphicsLibs) {
        auto located = collectFiles(libSearchPaths, lib);
        for (const auto &path : located) {
            addFile(path, true);
        }
    }

    auto xorgPaths = buildXOrgSearchPaths(driver.libDir);
    auto xorgDriver = collectFiles(xorgPaths, "nvidia_drv.so");
    for (const auto &path : xorgDriver) {
        addFile(path, false);
    }
    auto xorgGlx = collectFiles(xorgPaths, "libglxserver_nvidia.so." + versionPattern);
    for (const auto &path : xorgGlx) {
        addFile(path, false);
    }

    auto configRoots = defaultConfigSearchPaths();
    const std::array<std::filesystem::path, 6> configFiles = {
        "glvnd/egl_vendor.d/10_nvidia.json",
        "egl/egl_external_platform.d/15_nvidia_gbm.json",
        "egl/egl_external_platform.d/10_nvidia_wayland.json",
        "nvidia/nvoptix.bin",
        "X11/xorg.conf.d/10-nvidia.conf",
        "X11/xorg.conf.d/nvidia-drm-outputclass.conf",
    };
    for (const auto &rel : configFiles) {
        if (auto path = findFirstExisting(configRoots, rel)) {
            addFile(*path, false);
        }
    }

    std::vector<std::filesystem::path> vulkanRoots = configRoots;
    vulkanRoots.push_back("/");
    vulkanRoots = dedupPaths(vulkanRoots);

    std::vector<std::filesystem::path> vulkanFiles = {
        "vulkan/icd.d/nvidia_icd.json",
        "vulkan/icd.d/nvidia_layers.json",
        "vulkan/implicit_layer.d/nvidia_layers.json",
    };
#if defined(__x86_64__)
    vulkanFiles.emplace_back("vulkan/icd.d/nvidia_icd.x86_64.json");
#elif defined(__aarch64__)
    vulkanFiles.emplace_back("vulkan/icd.d/nvidia_icd.aarch64.json");
#endif

    for (const auto &rel : vulkanFiles) {
        if (auto path = findFirstExisting(vulkanRoots, rel)) {
            addFile(*path, false);
        }
    }

    auto firmwareRoots = firmwareSearchPaths();
    std::string firmwarePattern = driver.version.empty()
      ? "nvidia/*/gsp*.bin"
      : (std::string("nvidia/") + driver.version + "/gsp*.bin");
    auto firmwareFiles = collectFiles(firmwareRoots, firmwarePattern);
    for (const auto &path : firmwareFiles) {
        addFile(path, false);
    }

    const std::array<std::string, 7> binaries = {
        "nvidia-smi",
        "nvidia-debugdump",
        "nvidia-persistenced",
        "nvidia-cuda-mps-control",
        "nvidia-cuda-mps-server",
        "nvidia-imex",
        "nvidia-imex-ctl",
    };
    for (const auto &bin : binaries) {
        if (auto path = findExecutable(bin)) {
            addFile(*path, false);
        }
    }

    bool has32 = false;
    bool has64 = false;
    bool hasGlxLib = false;
    std::unordered_set<std::string> destSeen;
    std::unordered_set<std::string> eglExternalDirSet;
    std::unordered_set<std::string> eglVendorDirSet;
    std::unordered_set<std::string> vkIcdFileSet;
    std::vector<std::string> eglExternalDirs;
    std::vector<std::string> eglVendorDirs;
    std::vector<std::string> vkIcdFiles;

    auto addHostRoot = [&](const std::filesystem::path &sourcePath) -> bool {
        auto root = hostRootForPath(sourcePath);
        if (!root) {
            LogW("skip host path outside allowed roots: {}", sourcePath.string());
            return false;
        }
        auto key = root->string();
        if (hostRootSet.insert(key).second) {
            hostRoots.push_back(*root);
        }
        return true;
    };

    auto recordEnvPath = [&](const std::filesystem::path &destPath) {
        auto rel = destPath.lexically_relative(ext.root);
        if (rel.empty() || rel.native().rfind("..", 0) == 0) {
            return;
        }
        std::filesystem::path containerPath = std::filesystem::path(prefix) / rel;
        auto parent = containerPath.parent_path();
        if (parent.filename() == "egl_external_platform.d") {
            appendUnique(eglExternalDirSet, eglExternalDirs, parent.string());
        } else if (parent.filename() == "egl_vendor.d") {
            appendUnique(eglVendorDirSet, eglVendorDirs, parent.string());
        } else if (parent.filename() == "icd.d"
                   && parent.parent_path().filename() == "vulkan") {
            appendUnique(vkIcdFileSet, vkIcdFiles, containerPath.string());
        }
    };

    auto linkLibraryFile = [&](const std::filesystem::path &sourcePath) {
        if (!isRegularOrSymlink(sourcePath)) {
            return;
        }
        if (!addHostRoot(sourcePath)) {
            return;
        }
        auto targetPath = hostTargetPath(sourcePath, prefix);
        bool is32 = isElf32(sourcePath);
        auto destDir = ext.root / (is32 ? "orig/32" : "orig");
        std::string filename = sourcePath.filename().string();
        std::vector<std::string> names{ filename };
        if (auto soname = readElfSoname(sourcePath)) {
            if (!soname->empty() && *soname != filename) {
                names.push_back(*soname);
            }
        }
        for (const auto &name : names) {
            auto destPath = destDir / name;
            auto key = destPath.lexically_normal().string();
            if (!destSeen.insert(key).second) {
                continue;
            }
            if (ensureSymlink(targetPath, destPath)) {
                if (is32) {
                    has32 = true;
                } else {
                    has64 = true;
                }
                if (name.rfind("libGLX_nvidia", 0) == 0) {
                    hasGlxLib = true;
                }
            }
        }
    };

    auto linkRegularFile = [&](const std::filesystem::path &sourcePath) {
        if (!isRegularOrSymlink(sourcePath)) {
            return;
        }
        if (!addHostRoot(sourcePath)) {
            return;
        }
        auto targetPath = hostTargetPath(sourcePath, prefix);
        auto destPath = ext.root / sourcePath.relative_path();
        auto key = destPath.lexically_normal().string();
        if (!destSeen.insert(key).second) {
            return;
        }
        if (ensureSymlink(targetPath, destPath)) {
            recordEnvPath(destPath);
            auto filename = destPath.filename().string();
            if (filename.rfind("libglxserver_nvidia", 0) == 0) {
                hasGlxLib = true;
            }
        }
    };

    for (const auto &path : libFiles) {
        linkLibraryFile(path);
    }
    for (const auto &path : otherFiles) {
        linkRegularFile(path);
    }

    for (const auto &root : hostRoots) {
        if (!isDirectory(root)) {
            continue;
        }
        auto rootRel = root.relative_path();
        std::filesystem::path hostDir = ext.root / "host" / rootRel;
        std::filesystem::create_directories(hostDir, ec);
        if (ec) {
            LogW("failed to create host mount dir {}: {}", hostDir.string(), ec.message());
            ec.clear();
            continue;
        }
        ext.extraMounts.push_back(ocppi::runtime::config::types::Mount{
          .destination = (std::filesystem::path(prefix) / "host" / rootRel).string(),
          .options = kBindRoOptions,
          .source = root.string(),
          .type = kMountTypeBind,
        });
    }

    if (has64 || has32) {
        std::filesystem::create_directories(ext.root / "etc", ec);
        if (!ec) {
            std::ofstream ldConf(ext.root / "etc/ld.so.conf",
                                 std::ios::binary | std::ios::out | std::ios::trunc);
            if (ldConf.is_open()) {
                ldConf << prefix << "/orig\n";
                if (has32) {
                    ldConf << prefix << "/orig/32\n";
                }
            }
        }
    }

    appendEnvPath(ext.env,
                  "LD_LIBRARY_PATH",
                  [&]() {
                      std::vector<std::string> dirs;
                      if (has64) {
                          dirs.push_back(prefix + "/orig");
                      }
                      if (has32) {
                          dirs.push_back(prefix + "/orig/32");
                      }
                      return dirs;
                  }());
    appendEnvPath(ext.env, "EGL_EXTERNAL_PLATFORM_CONFIG_DIRS", eglExternalDirs);
    appendEnvPath(ext.env, "__EGL_EXTERNAL_PLATFORM_CONFIG_DIRS", eglExternalDirs);
    appendEnvPath(ext.env, "__EGL_VENDOR_LIBRARY_DIRS", eglVendorDirs);
    appendEnvPath(ext.env, "VK_ICD_FILENAMES", vkIcdFiles);
    appendEnvPath(ext.env, "VK_ADD_DRIVER_FILES", vkIcdFiles);

    if (has64 || has32) {
        ext.env["NVIDIA_CTK_LIBCUDA_DIR"] = prefix + "/orig";
    }
    if (hasGlxLib) {
        setEnvIfEmpty(ext.env, "__GLX_VENDOR_LIBRARY_NAME", "nvidia");
        setEnvIfEmpty(ext.env, "__NV_PRIME_RENDER_OFFLOAD", "1");
    }

    const std::array<std::filesystem::path, 4> controlDevices = {
        "/dev/nvidia-modeset",
        "/dev/nvidia-uvm-tools",
        "/dev/nvidia-uvm",
        "/dev/nvidiactl",
    };
    for (const auto &path : controlDevices) {
        if (isCharOrBlockDevice(path)) {
            ext.deviceNodes.push_back(api::types::v1::DeviceNode{
              .hostPath = path.string(),
              .path = path.string(),
            });
        }
    }

    auto nvidiaDevices = collectGlobMatches({}, "/dev/nvidia[0-9]*");
    for (const auto &path : nvidiaDevices) {
        if (isCharOrBlockDevice(path)) {
            ext.deviceNodes.push_back(api::types::v1::DeviceNode{
              .hostPath = path.string(),
              .path = path.string(),
            });
        }
    }

    auto driDevices = collectGlobMatches({}, "/dev/dri/card*");
    for (const auto &path : driDevices) {
        if (isCharOrBlockDevice(path)) {
            ext.deviceNodes.push_back(api::types::v1::DeviceNode{
              .hostPath = path.string(),
              .path = path.string(),
            });
        }
    }
    auto driRenders = collectGlobMatches({}, "/dev/dri/renderD*");
    for (const auto &path : driRenders) {
        if (isCharOrBlockDevice(path)) {
            ext.deviceNodes.push_back(api::types::v1::DeviceNode{
              .hostPath = path.string(),
              .path = path.string(),
            });
        }
    }

    std::filesystem::path dxg = "/dev/dxg";
    if (isCharOrBlockDevice(dxg)) {
        ext.deviceNodes.push_back(api::types::v1::DeviceNode{
          .hostPath = dxg.string(),
          .path = dxg.string(),
        });
    }

    const std::array<std::string, 2> ipcSockets = {
        "nvidia-persistenced/socket",
        "nvidia-fabricmanager/socket",
    };
    for (const auto &socketRel : ipcSockets) {
        std::filesystem::path runPath = std::filesystem::path("/run") / socketRel;
        if (isRegularOrSymlink(runPath)) {
            ext.extraMounts.push_back(ocppi::runtime::config::types::Mount{
              .destination = runPath.string(),
              .options = kIpcMountOptions,
              .source = runPath.string(),
              .type = kMountTypeBind,
            });
        }
        std::filesystem::path varRunPath = std::filesystem::path("/var/run") / socketRel;
        if (isRegularOrSymlink(varRunPath)) {
            ext.extraMounts.push_back(ocppi::runtime::config::types::Mount{
              .destination = varRunPath.string(),
              .options = kIpcMountOptions,
              .source = varRunPath.string(),
              .type = kMountTypeBind,
            });
        }
    }
    std::filesystem::path mpsPath = "/tmp/nvidia-mps";
    if (isDirectory(mpsPath)) {
        ext.extraMounts.push_back(ocppi::runtime::config::types::Mount{
          .destination = mpsPath.string(),
          .options = kIpcMountOptions,
          .source = mpsPath.string(),
          .type = kMountTypeBind,
        });
    }

    ext.has32Bit = has32;

    if (libFiles.empty() && otherFiles.empty() && ext.deviceNodes.empty()) {
        return std::optional<HostNvidiaExtension>{};
    }

    return ext;
}

} // namespace linglong::runtime
