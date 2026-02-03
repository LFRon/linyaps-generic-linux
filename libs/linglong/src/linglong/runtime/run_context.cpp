/* SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.  + *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include "run_context.h"

#include "linglong/common/display.h"
#include "linglong/extension/extension.h"
#include "linglong/runtime/container_builder.h"
#include "linglong/runtime/host_nvidia_extension.h"
#include "linglong/utils/log/log.h"
#include "linglong/utils/runtime_config_json.h"

#include <fmt/ranges.h>

#include <QDebug>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <unordered_set>
#include <utility>
#include <vector>

#include <unistd.h>

#include <string_view>

namespace linglong::runtime {

namespace {

constexpr std::string_view kNvidiaExtensionPrefix =
  extension::ExtensionImplNVIDIADisplayDriver::Identify;

bool isNvidiaDriverExtensionName(std::string_view name)
{
    return name.rfind(kNvidiaExtensionPrefix, 0) == 0;
}

std::vector<std::string> splitEnvPaths(const std::string &value)
{
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= value.size()) {
        size_t end = value.find(':', start);
        auto part = (end == std::string::npos) ? value.substr(start) : value.substr(start, end - start);
        if (!part.empty()) {
            parts.push_back(part);
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    return parts;
}

std::string mergePathValues(const std::string &preferred, const std::string &existing)
{
    std::vector<std::string> ordered;
    std::unordered_set<std::string> seen;
    for (const auto &part : splitEnvPaths(preferred)) {
        if (seen.insert(part).second) {
            ordered.push_back(part);
        }
    }
    for (const auto &part : splitEnvPaths(existing)) {
        if (seen.insert(part).second) {
            ordered.push_back(part);
        }
    }
    std::string merged;
    for (size_t i = 0; i < ordered.size(); ++i) {
        if (i) {
            merged.push_back(':');
        }
        merged.append(ordered[i]);
    }
    return merged;
}

void mergeEnv(std::map<std::string, std::string> &base,
              const std::map<std::string, std::string> &extra)
{
    static const std::unordered_set<std::string> pathKeys = {
        "LD_LIBRARY_PATH",
        "EGL_EXTERNAL_PLATFORM_CONFIG_DIRS",
        "__EGL_EXTERNAL_PLATFORM_CONFIG_DIRS",
        "__EGL_VENDOR_LIBRARY_DIRS",
        "VK_ICD_FILENAMES",
        "VK_ADD_DRIVER_FILES",
    };

    for (const auto &pair : extra) {
        const auto &key = pair.first;
        const auto &value = pair.second;
        if (value.empty()) {
            continue;
        }
        if (pathKeys.find(key) != pathKeys.end()) {
            auto it = base.find(key);
            std::string merged = mergePathValues(value, it != base.end() ? it->second : "");
            if (!merged.empty()) {
                base[key] = merged;
            }
            continue;
        }
        auto it = base.find(key);
        if (it == base.end() || it->second.empty()) {
            base[key] = value;
        }
    }
}

using json = nlohmann::json;

json loadMergedJsonWithBase(const std::string &appId, const std::string &baseId)
{
    return linglong::utils::loadMergedRuntimeConfigJson(appId, baseId);
}

std::string expandUserHome(const std::string &path)
{
    if (path == "~" || path.rfind("~/", 0) == 0) {
        const char *home = ::getenv("HOME");
        if (home && home[0]) {
            return path == "~" ? std::string(home) : (std::string(home) + path.substr(1));
        }
    }
    return path;
}

void collectEnvFromJson(const json &j, std::vector<std::string> &out)
{
    if (!j.contains("env") || !j.at("env").is_object()) {
        return;
    }
    for (auto it = j.at("env").begin(); it != j.at("env").end(); ++it) {
        const std::string key = it.key();
        std::string val = it.value().is_string() ? it.value().get<std::string>() : std::string();
        if (val.find('$') != std::string::npos) {
            qWarning() << "ignore env with variable expansion:" << QString::fromStdString(key);
            continue;
        }
        if (!key.empty() && key.back() == '+') {
            out.emplace_back(key.substr(0, key.size() - 1) + "+=" + val);
        } else {
            out.emplace_back(key + "=" + val);
        }
    }
}

std::unordered_set<std::string> getPermissionSet(const json &root, const char *category)
{
    std::unordered_set<std::string> enabled;
    auto it = root.find("permissions");
    if (it == root.end() || !it->is_object()) {
        return enabled;
    }
    auto cat = it->find(category);
    if (cat == it->end()) {
        return enabled;
    }
    if (cat->is_array()) {
        for (const auto &entry : *cat) {
            if (entry.is_string()) {
                enabled.insert(entry.get<std::string>());
            }
        }
    } else if (cat->is_object()) {
        for (auto iter = cat->begin(); iter != cat->end(); ++iter) {
            bool value = iter.value().is_boolean() ? iter.value().get<bool>() : false;
            if (value) {
                enabled.insert(iter.key());
            }
        }
    } else if (cat->is_string()) {
        enabled.insert(cat->get<std::string>());
    }
    return enabled;
}

bool addReadonlyMount(generator::ContainerCfgBuilder &builder,
                      const std::filesystem::path &source,
                      const std::string &destination)
{
    std::error_code ec;
    if (!std::filesystem::exists(source, ec)) {
        if (ec) {
            LogW("skip permission mount {} -> {}: {}", source.string(), destination, ec.message());
        }
        return false;
    }

    ocppi::runtime::config::types::Mount mount{
        .destination = destination,
        .options = std::vector<std::string>{ "rbind", "ro" },
        .source = source.string(),
        .type = "bind",
    };
    builder.addExtraMount(std::move(mount));
    return true;
}

bool isConfigWhitelistMatch(const json &entry, const std::string &appId)
{
    if (!entry.is_string() || appId.empty()) {
        return false;
    }
    auto val = entry.get<std::string>();
    if (val == "*" || val == appId) {
        return true;
    }
    return false;
}

bool allowHostConfigAccess(const json &root, const std::string &appId)
{
    if (appId.empty()) {
        return false;
    }
    auto it = root.find("config_access_whitelist");
    if (it == root.end()) {
        return false;
    }
    if (it->is_boolean()) {
        return it->get<bool>();
    }
    if (it->is_string()) {
        return isConfigWhitelistMatch(*it, appId);
    }
    if (!it->is_array()) {
        return false;
    }
    for (const auto &entry : *it) {
        if (isConfigWhitelistMatch(entry, appId)) {
            return true;
        }
    }
    return false;
}

bool allowHostRootAccess(const json &root, const std::string &appId)
{
    auto it = root.find("host_root_whitelist");
    if (it == root.end()) {
        return false;
    }
    if (it->is_boolean()) {
        return it->get<bool>();
    }
    if (it->is_string()) {
        return isConfigWhitelistMatch(*it, appId);
    }
    if (!it->is_array()) {
        return false;
    }
    for (const auto &entry : *it) {
        if (isConfigWhitelistMatch(entry, appId)) {
            return true;
        }
    }
    return false;
}

void applyFilesystemPermissions(generator::ContainerCfgBuilder &builder,
                                const std::unordered_set<std::string> &enabled,
                                bool allowLinglongConfig,
                                bool allowHostRoot)
{
    bool wantsHost = enabled.count("host") > 0;
    bool wantsHostOS = enabled.count("host-os") > 0;
    bool wantsHostEtc = enabled.count("host-etc") > 0;
    bool wantsHome = enabled.count("home") > 0;

    if (!wantsHost && !wantsHostOS && !wantsHostEtc && !wantsHome) {
        wantsHost = true;
        wantsHostOS = true;
        wantsHome = true;
    }

    if (wantsHost && allowHostRoot) {
        builder.bindHostRoot();
    }
    if (wantsHostOS) {
        builder.bindHostStatics();
        if (!wantsHost) {
            addReadonlyMount(builder, "/usr", "/run/host-os/usr");
            addReadonlyMount(builder, "/lib", "/run/host-os/lib");
            addReadonlyMount(builder, "/lib64", "/run/host-os/lib64");
        }
    }
    if (wantsHostEtc) {
        if (!addReadonlyMount(builder, "/etc", "/run/host-etc")) {
            LogW("host-etc permission requested but /etc is not accessible");
        }
    }
    if (wantsHome) {
        const char *home = ::getenv("HOME");
        if (!home || home[0] == '\0') {
            LogW("HOME is not set, skip home permission");
        } else {
            builder.bindHome(home)
              .enablePrivateDir()
              .mapPrivate(std::string{ home } + "/.ssh", true)
              .mapPrivate(std::string{ home } + "/.gnupg", true);
            if (!allowLinglongConfig) {
                builder.mapPrivate(std::string{ home } + "/.config/linglong", true);
            }
        }
    }
}

void applySocketPermissions(generator::ContainerCfgBuilder &builder,
                            const std::unordered_set<std::string> &enabled)
{
    auto mountRwDir = [&](const std::filesystem::path &source, const std::string &destination) {
        std::error_code ec;
        if (!std::filesystem::exists(source, ec)) {
            if (ec) {
                LogW("skip socket mount {} -> {}: {}", source.string(), destination, ec.message());
            }
            return;
        }
        ocppi::runtime::config::types::Mount mount{
            .destination = destination,
            .options = std::vector<std::string>{ "rbind" },
            .source = source.string(),
            .type = "bind",
        };
        builder.addExtraMount(std::move(mount));
    };

    if (enabled.count("pcsc") > 0) {
        mountRwDir("/run/pcscd", "/run/pcscd");
    }
    if (enabled.count("cups") > 0) {
        mountRwDir("/run/cups", "/run/cups");
        mountRwDir("/var/run/cups", "/var/run/cups");
    }
}

void applyPortalPermissions(const std::unordered_set<std::string> &enabled,
                            std::map<std::string, std::string> &environment)
{
    const std::vector<std::string> known = {
        "background", "notifications", "microphone", "speaker", "camera", "location"
    };
    for (const auto &name : known) {
        std::string key = name;
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
            if (c == '-') {
                return static_cast<unsigned char>('_');
            }
            return static_cast<unsigned char>(std::toupper(c));
        });
        auto envKey = "LINGLONG_PORTAL_" + key;
        environment[envKey] = enabled.count(name) > 0 ? "1" : "0";
    }
}

bool bindPath(generator::ContainerCfgBuilder &builder,
              const std::filesystem::path &source,
              const std::string &destination,
              bool recursive,
              bool readOnly)
{
    std::error_code ec;
    if (!std::filesystem::exists(source, ec)) {
        if (ec) {
            LogW("skip device mount {} -> {}: {}", source.string(), destination, ec.message());
        }
        return false;
    }
    std::vector<std::string> options;
    options.push_back(recursive ? "rbind" : "bind");
    if (readOnly) {
        options.push_back("ro");
    }
    ocppi::runtime::config::types::Mount mount{
        .destination = destination,
        .options = options,
        .source = source.string(),
        .type = "bind",
    };
    builder.addExtraMount(std::move(mount));
    return true;
}

void bindHidrawNodes(generator::ContainerCfgBuilder &builder)
{
    std::error_code ec;
    const std::filesystem::path devDir = "/dev";
    if (!std::filesystem::exists(devDir, ec)) {
        return;
    }
    for (const auto &entry : std::filesystem::directory_iterator(devDir, ec)) {
        if (ec) {
            break;
        }
        auto name = entry.path().filename().string();
        if (name.rfind("hidraw", 0) != 0) {
            continue;
        }
        bindPath(builder, entry.path(), entry.path().string(), false, false);
    }
}

std::vector<std::pair<std::string, std::string>> collectCustomUdevRules(const json &root)
{
    std::vector<std::pair<std::string, std::string>> rules;
    auto it = root.find("udev_rules");
    if (it == root.end() || !it->is_array()) {
        return rules;
    }
    for (const auto &entry : *it) {
        if (!entry.is_object()) {
            continue;
        }
        auto nameIt = entry.find("name");
        auto contentIt = entry.find("content");
        if (nameIt == entry.end() || contentIt == entry.end()) {
            continue;
        }
        if (!nameIt->is_string() || !contentIt->is_string()) {
            continue;
        }
        auto name = nameIt->get<std::string>();
        auto content = contentIt->get<std::string>();
        if (!name.empty() && !content.empty()) {
            rules.emplace_back(std::move(name), std::move(content));
        }
    }
    return rules;
}

std::string sanitizeUdevRuleName(std::string raw)
{
    if (raw.empty()) {
        return {};
    }
    for (auto &ch : raw) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (!std::isalnum(c) && ch != '-' && ch != '_' && ch != '.') {
            ch = '_';
        }
    }
    if (raw.size() < 6 || raw.substr(raw.size() - 6) != ".rules") {
        if (!raw.empty() && raw.back() != '.') {
            raw += ".rules";
        } else {
            raw += "rules";
        }
    }
    return raw;
}

std::filesystem::path prepareCustomUdevRulesDir()
{
    auto uid = ::getuid();
    std::filesystem::path dir =
      std::filesystem::path("/run/linglong/custom-udev") / std::to_string(uid);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        LogW("failed to prepare custom udev dir {}: {}", dir.string(), ec.message());
        return {};
    }
    return dir;
}

bool syncCustomUdevRules(const json &root, std::filesystem::path &outDir)
{
    auto rules = collectCustomUdevRules(root);
    if (rules.empty()) {
        return false;
    }
    auto dir = prepareCustomUdevRulesDir();
    if (dir.empty()) {
        return false;
    }
    std::error_code ec;
    for (const auto &entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) {
            break;
        }
        std::filesystem::remove_all(entry.path(), ec);
    }
    for (const auto &[name, content] : rules) {
        auto sanitized = sanitizeUdevRuleName(name);
        if (sanitized.empty()) {
            continue;
        }
        std::ofstream out(dir / sanitized, std::ios::trunc);
        if (!out.is_open()) {
            LogW("failed to write custom udev rule {}", sanitized);
            continue;
        }
        out << content;
    }
    outDir = dir;
    return true;
}

void applyDevicePermissions(generator::ContainerCfgBuilder &builder,
                            std::map<std::string, std::string> &environment,
                            const std::unordered_set<std::string> &enabled,
                            const json &mergedCfg)
{
    if (enabled.empty()) {
        return;
    }

    if (enabled.count("usb") > 0) {
        bindPath(builder, "/dev/bus/usb", "/dev/bus/usb", true, false);
    }
    if (enabled.count("usb-hid") > 0) {
        bindHidrawNodes(builder);
    }
    if (enabled.count("udev") > 0) {
        bindPath(builder, "/run/udev", "/run/udev", true, false);
        const std::filesystem::path hostRulesBase = "/run/host-udev-rules";
        bindPath(builder, "/etc/udev/rules.d", (hostRulesBase / "etc").string(), true, true);
        bindPath(builder, "/lib/udev/rules.d", (hostRulesBase / "lib").string(), true, true);
        std::filesystem::path customDir;
        if (syncCustomUdevRules(mergedCfg, customDir)) {
            bindPath(builder, customDir, (hostRulesBase / "custom").string(), true, true);
        }
        environment["LINGLONG_UDEV_RULES_DIR"] = hostRulesBase.string();
    }
}

std::optional<std::string> appendEnvWithMergedPath(
  linglong::generator::ContainerCfgBuilder &builder,
  const std::vector<std::string> &envKVs,
  const std::map<std::string, std::string> &baseEnv,
  const std::optional<std::string> &currentPath,
  const char *warnContext)
{
    if (envKVs.empty()) {
        return currentPath;
    }

    std::map<std::string, std::string> envToAppend;
    std::string systemPath;
    if (auto sysPath = ::getenv("PATH")) {
        systemPath = sysPath;
    }
    auto basePathIt = baseEnv.find("PATH");

    auto appendPath = [&](const std::string &add) {
        if (auto it = envToAppend.find("PATH"); it != envToAppend.end()) {
            it->second += ":" + add;
            return;
        }
        if (currentPath) {
            envToAppend["PATH"] = currentPath->empty() ? add : *currentPath + ":" + add;
            return;
        }
        if (basePathIt != baseEnv.end()) {
            envToAppend["PATH"] =
              basePathIt->second.empty() ? add : basePathIt->second + ":" + add;
            return;
        }
        if (!systemPath.empty()) {
            envToAppend["PATH"] = systemPath + ":" + add;
            return;
        }
        envToAppend["PATH"] = add;
    };

    for (const auto &kv : envKVs) {
        auto pos = kv.find("+=");
        if (pos != std::string::npos) {
            auto key = kv.substr(0, pos);
            auto add = kv.substr(pos + 2);
            if (key == "PATH") {
                appendPath(add);
            } else {
                if (warnContext && warnContext[0]) {
                    qWarning() << "ignore '+=' env for key" << warnContext << ":"
                               << QString::fromStdString(key);
                } else {
                    qWarning() << "ignore '+=' env for key:" << QString::fromStdString(key);
                }
            }
            continue;
        }
        auto eq = kv.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        envToAppend[kv.substr(0, eq)] = kv.substr(eq + 1);
    }

    if (!envToAppend.empty()) {
        builder.appendEnv(envToAppend);
        if (auto it = envToAppend.find("PATH"); it != envToAppend.end()) {
            return it->second;
        }
    }

    return currentPath;
}

std::vector<ocppi::runtime::config::types::Mount> parseFilesystemMounts(const std::string &appId,
                                                                       const json &arr)
{
    using Mount = ocppi::runtime::config::types::Mount;
    std::vector<Mount> mounts;
    if (!arr.is_array()) {
        return mounts;
    }
    for (const auto &e : arr) {
        if (!e.is_object()) {
            continue;
        }
        std::string host = e.value("host", "");
        std::string target = e.value("target", "");
        std::string mode = e.value("mode", "ro");
        bool persist = e.value("persist", false);

        if (host.empty() || target.empty()) {
            continue;
        }
        if (host.find('$') != std::string::npos || target.find('$') != std::string::npos) {
            qWarning() << "ignore mount with variable expansion:" << QString::fromStdString(host)
                       << "->" << QString::fromStdString(target);
            continue;
        }

        host = expandUserHome(host);
        if (persist) {
            const char *home = ::getenv("HOME");
            if (home && home[0] && !appId.empty()) {
                std::filesystem::path p(home);
                p /= ".var/app";
                p /= appId;
                p /= std::filesystem::path(host).filename();
                host = p.string();
            }

            std::error_code ec;
            std::filesystem::path hostPath(host);
            std::filesystem::create_directories(hostPath, ec);
            if (ec || !std::filesystem::is_directory(hostPath, ec)) {
                qWarning() << "failed to prepare persist directory for"
                           << QString::fromStdString(host) << ":" << ec.message().c_str();
                continue;
            }
        }

        Mount m;
        m.type = "bind";
        m.source = host;
        m.destination = target;
        m.options = { (mode == "rw" ? "rw" : "ro"), "rbind" };
        mounts.emplace_back(std::move(m));
    }

    return mounts;
}

void collectMountsFromJson(const std::string &appId,
                           const json &j,
                           std::vector<ocppi::runtime::config::types::Mount> &out)
{
    if (!j.contains("filesystem") || !j.at("filesystem").is_array()) {
        return;
    }
    auto mounts = parseFilesystemMounts(appId, j.at("filesystem"));
    std::move(mounts.begin(), mounts.end(), std::back_inserter(out));
}

const json *pickCommandNode(const json &merged, const std::string &execName)
{
    if (!merged.contains("commands") || !merged.at("commands").is_object()) {
        return nullptr;
    }
    const auto &cmds = merged.at("commands");
    if (auto it = cmds.find(execName); it != cmds.end() && it->is_object()) {
        return &(*it);
    }
    if (auto it = cmds.find("*"); it != cmds.end() && it->is_object()) {
        return &(*it);
    }
    return nullptr;
}

void loadStrVec(const json &node, const char *key, std::vector<std::string> &out)
{
    if (!node.contains(key) || !node.at(key).is_array()) {
        return;
    }
    for (const auto &v : node.at(key)) {
        if (v.is_string()) {
            out.emplace_back(v.get<std::string>());
        }
    }
}

RunContext::CommandSettings parseCommandSettings(const std::string &appId, const json &node)
{
    RunContext::CommandSettings cs;
    if (node.contains("env") && node.at("env").is_object()) {
        for (auto it = node.at("env").begin(); it != node.at("env").end(); ++it) {
            const std::string key = it.key();
            std::string val = it.value().is_string() ? it.value().get<std::string>() : std::string();
            if (val.find('$') != std::string::npos) {
                qWarning() << "ignore env with variable expansion in command settings:"
                           << QString::fromStdString(key);
                continue;
            }
            if (!key.empty() && key.back() == '+') {
                cs.envKVs.emplace_back(key.substr(0, key.size() - 1) + "+=" + val);
            } else {
                cs.envKVs.emplace_back(key + "=" + val);
            }
        }
    }
    if (node.contains("filesystem") && node.at("filesystem").is_array()) {
        collectMountsFromJson(appId, node, cs.mounts);
    }
    loadStrVec(node, "args_prefix", cs.argsPrefix);
    loadStrVec(node, "args_suffix", cs.argsSuffix);
    if (node.contains("entrypoint") && node.at("entrypoint").is_string()) {
        cs.entrypoint = node.at("entrypoint").get<std::string>();
    }
    if (node.contains("cwd") && node.at("cwd").is_string()) {
        cs.cwd = node.at("cwd").get<std::string>();
    }
    return cs;
}

} // namespace

utils::error::Result<RuntimeLayer> RuntimeLayer::create(package::Reference ref, RunContext &context)
{
    LINGLONG_TRACE(fmt::format("create runtime layer from ref {}", ref.toString()));

    try {
        return RuntimeLayer(ref, context);
    } catch (const std::exception &e) {
        return LINGLONG_ERR("failed to create runtime layer", e);
    }
}

RuntimeLayer::RuntimeLayer(package::Reference ref, RunContext &context)
    : reference(std::move(ref))
    , runContext(context)
    , temporary(false)
{
    const auto &repo = context.getRepo();
    auto item = repo.getLayerItem(reference);
    if (!item) {
        throw std::runtime_error("no cached item found");
    }
    cachedItem = std::move(item).value();
}

RuntimeLayer::~RuntimeLayer()
{
    if (temporary && layerDir) {
        std::error_code ec;
        std::filesystem::remove_all(layerDir->path(), ec);
    }
}

utils::error::Result<void> RuntimeLayer::resolveLayer(const std::vector<std::string> &modules,
                                                      const std::optional<std::string> &subRef)
{
    LINGLONG_TRACE("resolve layer");

    auto &repo = runContext.get().getRepo();
    utils::error::Result<package::LayerDir> layer(LINGLONG_ERR("null"));
    if (modules.empty() || (modules.size() == 1 && modules[0] == "binary")) {
        layer = repo.getMergedModuleDir(reference, true, subRef);
    } else if (modules.size() > 1) {
        layer = repo.createTempMergedModuleDir(reference, modules);
        temporary = true;
    } else {
        return LINGLONG_ERR(
          fmt::format("resolve module {} is not supported", fmt::join(modules, ",")));
    }

    if (!layer) {
        return LINGLONG_ERR("layer doesn't exist: " + reference.toString(), layer);
    }

    layerDir = *layer;
    return LINGLONG_OK;
}

RunContext::~RunContext()
{
    if (!bundle.empty()) {
        std::error_code ec;
        if (std::filesystem::exists(bundle, ec)) {
            if (std::filesystem::remove_all(bundle, ec) == static_cast<std::uintmax_t>(-1)) {
                LogW("failed to remove bundle directory {}: {}", bundle, ec.message());
            }
        }
    }
}

utils::error::Result<void> RunContext::resolve(const linglong::package::Reference &runnable,
                                               const ResolveOptions &options)
{
    LINGLONG_TRACE("resolve RunContext from runnable " + runnable.toString());
    runtimeConfigEnabled = true;
    hostNvidiaExtensionName.reset();

    auto layer = RuntimeLayer::create(runnable, *this);
    if (!layer) {
        return LINGLONG_ERR(layer);
    }

    containerID = runtime::genContainerID(runnable);

    const auto &info = layer->getCachedItem().info;
    if (info.kind == "base") {
        baseLayer = std::move(layer).value();
    } else if (info.kind == "app") {
        appLayer = std::move(layer).value();
        auto runtime = options.runtimeRef.value_or(info.runtime.value_or(""));
        if (!runtime.empty()) {
            auto runtimeFuzzyRef = package::FuzzyReference::parse(runtime);
            if (!runtimeFuzzyRef) {
                return LINGLONG_ERR(runtimeFuzzyRef);
            }

            auto ref = repo.clearReference(*runtimeFuzzyRef,
                                           {
                                             .forceRemote = false,
                                             .fallbackToRemote = false,
                                             .semanticMatching = true,
                                           });
            if (!ref) {
                return LINGLONG_ERR("ref doesn't exist " + runtimeFuzzyRef->toString());
            }
            auto res = RuntimeLayer::create(std::move(ref).value(), *this);
            if (!res) {
                return LINGLONG_ERR(res);
            }
            runtimeLayer = std::move(res).value();
        }
    } else if (info.kind == "runtime") {
        runtimeLayer = std::move(layer).value();
    } else {
        return LINGLONG_ERR(fmt::format("kind {} is not runnable", info.kind));
    }

    // base layer must be resolved for all kinds
    if (!baseLayer) {
        auto baseRef = options.baseRef.value_or(info.base);
        auto baseFuzzyRef = package::FuzzyReference::parse(baseRef);
        if (!baseFuzzyRef) {
            return LINGLONG_ERR(baseFuzzyRef);
        }

        auto ref = repo.clearReference(*baseFuzzyRef,
                                       {
                                         .forceRemote = false,
                                         .fallbackToRemote = false,
                                         .semanticMatching = true,
                                       });
        if (!ref) {
            return LINGLONG_ERR(ref);
        }
        auto res = RuntimeLayer::create(std::move(ref).value(), *this);
        if (!res) {
            return LINGLONG_ERR(res);
        }
        baseLayer = std::move(res).value();
    }

    // resolve base extension
    auto ret = resolveExtension(
      *baseLayer,
      matchedExtensionDefines(baseLayer->getReference(), options.externalExtensionDefs));
    if (!ret) {
        return LINGLONG_ERR(ret);
    }

    // resolve runtime extension
    if (runtimeLayer) {
        auto ret = resolveExtension(
          *runtimeLayer,
          matchedExtensionDefines(runtimeLayer->getReference(), options.externalExtensionDefs));
        if (!ret) {
            return LINGLONG_ERR(ret);
        }
    }

    // resolve app extension
    if (appLayer) {
        auto ret = resolveExtension(
          *appLayer,
          matchedExtensionDefines(appLayer->getReference(), options.externalExtensionDefs));
        if (!ret) {
            return LINGLONG_ERR(ret);
        }
    }

    // 手动解析多个扩展
    if (options.extensionRefs && !options.extensionRefs->empty()) {
        auto manualExtensionDef = makeManualExtensionDefine(*options.extensionRefs);
        if (!manualExtensionDef) {
            return LINGLONG_ERR(manualExtensionDef);
        }

        auto ret = resolveExtension(*manualExtensionDef);
        if (!ret) {
            return LINGLONG_ERR(ret);
        }
    }

    // all reference are cleard , we can get actual layer directory now
    return resolveLayer(options.depsBinaryOnly,
                        options.appModules.value_or(std::vector<std::string>{}));
}

utils::error::Result<void> RunContext::resolve(const api::types::v1::BuilderProject &target,
                                               const std::filesystem::path &buildOutput)
{
    LINGLONG_TRACE("resolve RunContext from builder project " + target.package.id);
    runtimeConfigEnabled = false;
    hostNvidiaExtensionName.reset();

    auto targetRef = package::Reference::fromBuilderProject(target);
    if (!targetRef) {
        return LINGLONG_ERR(targetRef);
    }
    containerID = runtime::genContainerID(*targetRef);
    targetId = target.package.id;

    if (target.package.kind == "extension") {
        extensionOutput = buildOutput;
    } else if (target.package.kind == "app") {
        appOutput = buildOutput;
    } else if (target.package.kind == "runtime") {
        runtimeOutput = buildOutput;
    } else {
        return LINGLONG_ERR("can't resolve run context from package kind " + target.package.kind);
    }

    auto baseFuzzyRef = package::FuzzyReference::parse(target.base);
    if (!baseFuzzyRef) {
        return LINGLONG_ERR(baseFuzzyRef);
    }

    auto ref = repo.clearReference(*baseFuzzyRef,
                                   {
                                     .forceRemote = false,
                                     .fallbackToRemote = false,
                                     .semanticMatching = true,
                                   });
    if (!ref) {
        return LINGLONG_ERR(ref);
    }
    auto res = RuntimeLayer::create(std::move(ref).value(), *this);
    if (!res) {
        return LINGLONG_ERR(res);
    }
    baseLayer = std::move(res).value();

    if (target.runtime) {
        auto runtimeFuzzyRef = package::FuzzyReference::parse(*target.runtime);
        if (!runtimeFuzzyRef) {
            return LINGLONG_ERR(runtimeFuzzyRef);
        }

        ref = repo.clearReference(*runtimeFuzzyRef,
                                  {
                                    .forceRemote = false,
                                    .fallbackToRemote = false,
                                    .semanticMatching = true,
                                  });
        if (!ref) {
            return LINGLONG_ERR("ref doesn't exist " + runtimeFuzzyRef->toString());
        }
        auto res = RuntimeLayer::create(std::move(ref).value(), *this);
        if (!res) {
            return LINGLONG_ERR(res);
        }
        runtimeLayer = std::move(res).value();

        const auto &info = runtimeLayer->getCachedItem().info;
        auto fuzzyRef = package::FuzzyReference::parse(info.base);
        if (!fuzzyRef) {
            return LINGLONG_ERR(fuzzyRef);
        }
        auto ref = repo.clearReference(*fuzzyRef,
                                       {
                                         .forceRemote = false,
                                         .fallbackToRemote = false,
                                         .semanticMatching = true,
                                       });
        if (!ref || *ref != baseLayer->getReference()) {
            auto msg = fmt::format("Base is not compatible with runtime. \n - Current base: {}\n - "
                                   "Current runtime: {}\n - Base required by runtime: {}",
                                   baseLayer->getReference().toString(),
                                   runtimeLayer->getReference().toString(),
                                   info.base);
            return LINGLONG_ERR(msg);
        }
    }

    return resolveLayer(false, {});
}

utils::error::Result<void> RunContext::resolveLayer(bool depsBinaryOnly,
                                                    const std::vector<std::string> &appModules)
{
    LINGLONG_TRACE("resolve layers");

    std::optional<std::string> subRef;
    if (appLayer) {
        const auto &info = appLayer->getCachedItem().info;
        if (info.uuid) {
            subRef = info.uuid;
        }
    }

    std::vector<std::string> depsModules;
    if (depsBinaryOnly) {
        depsModules.emplace_back("binary");
    }
    auto ref = baseLayer->resolveLayer(depsModules, subRef);
    if (!ref.has_value()) {
        return LINGLONG_ERR("failed to resolve base layer", ref);
    }

    if (appLayer) {
        auto ref = appLayer->resolveLayer(appModules);
        if (!ref.has_value()) {
            return LINGLONG_ERR("failed to resolve app layer", ref);
        }
    }

    if (runtimeLayer) {
        auto ref = runtimeLayer->resolveLayer(depsModules, subRef);
        if (!ref.has_value()) {
            return LINGLONG_ERR("failed to resolve runtime layer", ref);
        }
    }

    for (auto &ext : extensionLayers) {
        if (!ext.resolveLayer()) {
            LogW("ignore failed extension layer");
            continue;
        }

        auto extensionOf = ext.getExtensionInfo();
        if (!extensionOf) {
            continue;
        }

        const auto &[extensionDefine, layer] = *extensionOf;
        const auto &extInfo = ext.getCachedItem().info;
        if (!extInfo.extImpl) {
            LogW("no ext_impl found for {}", ext.getReference().toString());
            continue;
        }
        const auto &extImpl = *extInfo.extImpl;
        if (!extImpl.env) {
            continue;
        }
        for (const auto &env : *extImpl.env) {
            // if allowEnv is not defined, all envs are allowed
            std::string defaultValue;
            if (extensionDefine.allowEnv) {
                const auto &allowEnv = *extensionDefine.allowEnv;
                auto allowed = allowEnv.find(env.first);
                if (allowed == allowEnv.end()) {
                    LogW("env {} not allowed in {}", env.first, ext.getReference().toString());
                    continue;
                }
                defaultValue = allowed->second;
            }

            std::string res =
              common::strings::replaceSubstring(env.second,
                                                "$PREFIX",
                                                "/opt/extensions/" + ext.getReference().id);
            auto &value = environment[env.first];
            if (value.empty()) {
                value = defaultValue;
            }
            // If $ORIGIN is unset and the default value is empty, the environment variable
            // may become ":NEW_VALUE" or "NEW_VALUE:". We cannot remove the leading/trailing
            // colon because the value might represent a non-path element (e.g., a delimiter)
            res = common::strings::replaceSubstring(res, "$ORIGIN", value);

            value = res;
            LogD("environment[{}]={}", env.first, res);
        }
    }

    return LINGLONG_OK;
}

utils::error::Result<void> RunContext::resolveExtension(
  RuntimeLayer &layer, const std::vector<api::types::v1::ExtensionDefine> &externalExtensionDefs)
{
    LINGLONG_TRACE("resolve RuntimeLayer extension");

    const auto &info = layer.getCachedItem().info;
    if (info.extensions) {
        auto res = resolveExtension(*info.extensions, info.channel, true);
        if (!res) {
            return LINGLONG_ERR(res);
        }
    }

    // merge external extensions
    if (!externalExtensionDefs.empty()) {
        return resolveExtension(externalExtensionDefs, info.channel, true);
    }

    return LINGLONG_OK;
}

utils::error::Result<void>
RunContext::resolveExtension(const std::vector<api::types::v1::ExtensionDefine> &extDefs,
                             std::optional<std::string> channel,
                             bool skipOnNotFound)
{
    LINGLONG_TRACE("resolve extension define");

    for (const auto &extDef : extDefs) {
        LogD("handle extensions: {}", extDef.name);
        LogD("version: {}", extDef.version);
        LogD("directory: {}", extDef.directory);
        if (extDef.allowEnv) {
            for (const auto &allowEnv : *extDef.allowEnv) {
                LogD("allowEnv: {}:{}", allowEnv.first, allowEnv.second);
            }
        }

        std::string name = extDef.name;
        auto ext = extension::ExtensionFactory::makeExtension(name);
        if (!ext->shouldEnable(name)) {
            continue;
        }

        std::optional<std::string> version;
        if (!extDef.version.empty()) {
            version = extDef.version;
        }
        auto fuzzyRef = package::FuzzyReference::create(channel, name, version, std::nullopt);
        auto ref =
          repo.clearReference(*fuzzyRef, { .fallbackToRemote = false, .semanticMatching = true });
        if (!ref) {
            LogD("extension is not installed: {}", fuzzyRef->toString());
            if (isNvidiaDriverExtensionName(name)) {
                if (!hostNvidiaExtensionName) {
                    hostNvidiaExtensionName = name;
                    LogI("use host NVIDIA driver fallback for {}", name);
                }
                continue;
            }
            if (skipOnNotFound) {
                continue;
            }
            return LINGLONG_ERR("extension is not installed", ref);
        }

        auto layer = RuntimeLayer::create(*ref, *this);
        if (!layer) {
            return LINGLONG_ERR(layer);
        }

        if (layer->getCachedItem().info.kind != "extension") {
            return LINGLONG_ERR(fmt::format("{} is not an extension", ref->toString()));
        }

        auto &extensionLayer = extensionLayers.emplace_back(std::move(layer).value());
        extensionLayer.setExtensionInfo(
          std::make_pair(extDef, std::reference_wrapper<RuntimeLayer>(extensionLayer)));
    }

    return LINGLONG_OK;
}

utils::error::Result<std::vector<api::types::v1::ExtensionDefine>>
RunContext::makeManualExtensionDefine(const std::vector<std::string> &refs)
{
    LINGLONG_TRACE("make extension define");

    std::vector<api::types::v1::ExtensionDefine> extDefs;
    extDefs.reserve(refs.size());
    for (const auto &ref : refs) {
        auto fuzzyRef = package::FuzzyReference::parse(ref);
        if (!fuzzyRef) {
            return LINGLONG_ERR("failed to parse extension ref", fuzzyRef);
        }

        extDefs.emplace_back(api::types::v1::ExtensionDefine{
          .directory = "/opt/extensions/" + fuzzyRef->id,
          .name = fuzzyRef->id,
          .version = fuzzyRef->version.value_or(""),
        });
    }
    return extDefs;
}

std::vector<api::types::v1::ExtensionDefine> RunContext::matchedExtensionDefines(
  const package::Reference &ref,
  const std::optional<std::map<std::string, std::vector<api::types::v1::ExtensionDefine>>>
    &externalExtensionDefs)
{
    std::vector<api::types::v1::ExtensionDefine> result;

    if (externalExtensionDefs.has_value()) {
        for (const auto &[key, defs] : *externalExtensionDefs) {
            auto fuzzyRef = package::FuzzyReference::parse(key);
            if (!fuzzyRef) {
                LogE("invalid ref {}: {}", key, fuzzyRef.error());
                continue;
            }

            if (fuzzyRef->id != ref.id) {
                continue;
            }

            if (fuzzyRef->version) {
                if (!ref.version.semanticMatch(*fuzzyRef->version)) {
                    continue;
                }
            }

            result.insert(result.end(), defs.begin(), defs.end());
        }
    }

    return result;
}

void RunContext::detectDisplaySystem(generator::ContainerCfgBuilder &builder) noexcept
{
    while (true) {
        auto *xOrgDisplayEnv = ::getenv("DISPLAY");
        if (xOrgDisplayEnv == nullptr || xOrgDisplayEnv[0] == '\0') {
            LogD("DISPLAY is not set, ignore it");
            break;
        }

        auto xOrgDisplay = common::display::getXOrgDisplay(xOrgDisplayEnv);
        if (!xOrgDisplay) {
            LogW("failed to get XOrg display: {}, ignore it", xOrgDisplay.error());
            break;
        }

        builder.bindXOrgSocket(xOrgDisplay.value());
        break;
    }

    while (true) {
        auto *xOrgAuthFileEnv = ::getenv("XAUTHORITY");
        if (xOrgAuthFileEnv == nullptr || xOrgAuthFileEnv[0] == '\0') {
            LogD("XAUTHORITY is not set, ignore it");
            break;
        }

        auto xOrgAuthFile = common::display::getXOrgAuthFile(xOrgAuthFileEnv);
        if (!xOrgAuthFile) {
            LogW("failed to get XOrg auth file: {}, ignore it", xOrgAuthFile.error());
            break;
        }

        builder.bindXAuthFile(xOrgAuthFile.value());
        break;
    }

    while (true) {
        auto *waylandDisplayEnv = ::getenv("WAYLAND_DISPLAY");
        if (waylandDisplayEnv == nullptr || waylandDisplayEnv[0] == '\0') {
            LogD("WAYLAND_DISPLAY is not set, ignore it");
            break;
        }

        auto waylandDisplay = common::display::getWaylandDisplay(waylandDisplayEnv);
        if (!waylandDisplay) {
            LogW("failed to get Wayland display: {}, ignore it", waylandDisplay.error());
            break;
        }

        builder.bindWaylandSocket(waylandDisplay.value());
        break;
    }
}

utils::error::Result<void> RunContext::fillContextCfg(
  linglong::generator::ContainerCfgBuilder &builder, const std::string &bundleSuffix)
{
    LINGLONG_TRACE("fill ContainerCfgBuilder with run context");

    builder.setContainerId(containerID);

    if (!baseLayer) {
        return LINGLONG_ERR("run context doesn't resolved");
    }

    auto bundleDir = runtime::makeBundleDir(containerID, bundleSuffix);
    if (!bundleDir) {
        return LINGLONG_ERR("failed to get bundle dir of " + containerID);
    }
    bundle = *bundleDir;
    builder.setBundlePath(bundle);

    builder.setBasePath(baseLayer->getLayerDir()->filesDirPath());

    if (appOutput) {
        builder.setAppPath(*appOutput, false);
    } else {
        if (appLayer) {
            builder.setAppPath(appLayer->getLayerDir()->filesDirPath());
        }
    }

    if (runtimeOutput) {
        builder.setRuntimePath(*runtimeOutput, false);
    } else {
        if (runtimeLayer) {
            builder.setRuntimePath(runtimeLayer->getLayerDir()->filesDirPath());
        }
    }

    std::vector<ocppi::runtime::config::types::Mount> extensionMounts{};
    std::optional<HostNvidiaExtension> hostNvidiaExtension;
    if (extensionOutput) {
        extensionMounts.push_back(ocppi::runtime::config::types::Mount{
          .destination = "/opt/extensions/" + targetId,
          .gidMappings = {},
          .options = { { "rbind" } },
          .source = extensionOutput,
          .type = "bind",
          .uidMappings = {},
        });
    }

    for (auto &ext : extensionLayers) {
        const auto &info = ext.getCachedItem().info;
        if (info.extImpl && info.extImpl->deviceNodes) {
            for (auto &node : *info.extImpl->deviceNodes) {
                ocppi::runtime::config::types::Mount mount = {
                    .destination = node.path,
                    .options = { { "bind" } },
                    .source = node.hostPath.value_or(node.path),
                    .type = "bind",
                };
                builder.addExtraMount(mount);
            }
        }

        std::string name = ext.getReference().id;
        if (extensionOutput && name == targetId) {
            continue;
        }
        extensionMounts.push_back(ocppi::runtime::config::types::Mount{
          .destination = "/opt/extensions/" + name,
          .gidMappings = {},
          .options = { { "rbind", "ro" } },
          .source = ext.getLayerDir()->filesDirPath(),
          .type = "bind",
          .uidMappings = {},
        });
    }

    if (hostNvidiaExtensionName) {
        auto hostExt = prepareHostNvidiaExtension(bundle, *hostNvidiaExtensionName);
        if (!hostExt) {
            return LINGLONG_ERR(hostExt);
        }
        if (hostExt->has_value()) {
            hostNvidiaExtension = std::move(*hostExt);
            bool mountHostExtension =
              !(extensionOutput && hostNvidiaExtension->name == targetId);
            if (mountHostExtension) {
                extensionMounts.push_back(ocppi::runtime::config::types::Mount{
                  .destination = "/opt/extensions/" + hostNvidiaExtension->name,
                  .gidMappings = {},
                  .options = { { "rbind", "ro" } },
                  .source = hostNvidiaExtension->root.string(),
                  .type = "bind",
                  .uidMappings = {},
                });
                for (const auto &node : hostNvidiaExtension->deviceNodes) {
                    ocppi::runtime::config::types::Mount mount = {
                        .destination = node.path,
                        .options = { { "bind" } },
                        .source = node.hostPath.value_or(node.path),
                        .type = "bind",
                    };
                    builder.addExtraMount(mount);
                }
                if (!hostNvidiaExtension->extraMounts.empty()) {
                    builder.addExtraMounts(hostNvidiaExtension->extraMounts);
                }
                mergeEnv(environment, hostNvidiaExtension->env);
            }
        }
    }
    if (!extensionMounts.empty()) {
        builder.setExtensionMounts(extensionMounts);
    }

    auto res = fillExtraAppMounts(builder);
    if (!res) {
        return res;
    }

    if (runtimeConfigEnabled) {
        builder.bindIPC();
        std::string currentApp = currentAppId();
        std::string currentBase;
        if (baseLayer) {
            currentBase = baseLayer->getReference().id;
        }

        auto mergedCfg = loadMergedJsonWithBase(currentApp, currentBase);
        bool allowConfigDir = allowHostConfigAccess(mergedCfg, currentApp);
        std::optional<std::string> mergedPath;

        // 1) common env
        {
            std::vector<std::string> envKVs;
            collectEnvFromJson(mergedCfg, envKVs);
            mergedPath = appendEnvWithMergedPath(builder, envKVs, environment, mergedPath, "");
        }

        // 2) common filesystem
        if (auto it = mergedCfg.find("filesystem_allow_only"); it != mergedCfg.end()) {
            if (it->is_array()) {
                auto allowList = parseFilesystemMounts(currentApp, *it);
                if (!allowList.empty()) {
                    builder.addExtraMounts(std::move(allowList));
                }
            }
        } else if (auto it = mergedCfg.find("filesystem"); it != mergedCfg.end()) {
            if (it->is_array()) {
                auto extraMounts = parseFilesystemMounts(currentApp, *it);
                if (!extraMounts.empty()) {
                    builder.addExtraMounts(std::move(extraMounts));
                }
            }
        }

        bool allowHostRoot = allowHostRootAccess(mergedCfg, currentApp);
        applyFilesystemPermissions(
          builder, getPermissionSet(mergedCfg, "filesystem"), allowConfigDir, allowHostRoot);
        applySocketPermissions(builder, getPermissionSet(mergedCfg, "sockets"));
        applyPortalPermissions(getPermissionSet(mergedCfg, "portals"), environment);
        applyDevicePermissions(builder, environment, getPermissionSet(mergedCfg, "devices"), mergedCfg);

        if (!environment.empty()) {
            if (auto it = environment.find("PATH"); it != environment.end()) {
                mergedPath = it->second;
            }
            builder.appendEnv(environment);
        }

        // 3) command-level settings (highest priority)
        if (auto settings = commandSettings()) {
            if (!settings->envKVs.empty()) {
                mergedPath = appendEnvWithMergedPath(builder,
                                                     settings->envKVs,
                                                     environment,
                                                     mergedPath,
                                                     "in command settings");
            }
            if (!settings->mounts.empty()) {
                builder.addExtraMounts(settings->mounts);
            }
        }
    } else if (!environment.empty()) {
        builder.appendEnv(environment);
    }

    detectDisplaySystem(builder);

    for (auto ctx = securityContexts.begin(); ctx != securityContexts.end(); ++ctx) {
        auto manager = getSecurityContextManager(ctx->first);
        if (!manager) {
            auto msg = "failed to get security context manager: " + fromType(ctx->first);
            return LINGLONG_ERR(msg.c_str());
        }

        auto secCtx = manager->createSecurityContext(builder);
        if (!secCtx) {
            auto msg = "failed to create security context: " + fromType(ctx->first);
            return LINGLONG_ERR(msg.c_str());
        }
        ctx->second = std::move(secCtx).value();

        auto res = ctx->second->apply(builder);
        if (!res) {
            auto msg = "failed to apply security context: " + fromType(ctx->first);
            ctx = securityContexts.erase(ctx);
            return LINGLONG_ERR(msg.c_str(), res);
        }
    }

    return LINGLONG_OK;
}

void RunContext::enableSecurityContext(const std::vector<SecurityContextType> &ctxs)
{
    for (const auto &type : ctxs) {
        securityContexts.try_emplace(type, nullptr);
    }
}

utils::error::Result<void> RunContext::fillExtraAppMounts(generator::ContainerCfgBuilder &builder)
{
    LINGLONG_TRACE("fill extra app mounts");

    auto fillPermissionsBinds = [&builder,
                                 this](RuntimeLayer &layer) -> utils::error::Result<void> {
        LINGLONG_TRACE("fill permissions binds");

        const auto &info = layer.getCachedItem().info;

        if (info.permissions) {
            std::vector<ocppi::runtime::config::types::Mount> applicationMounts{};
            auto bindMount =
              [&applicationMounts](
                const api::types::v1::ApplicationConfigurationPermissionsBind &bind) {
                  applicationMounts.push_back(ocppi::runtime::config::types::Mount{
                    .destination = bind.destination,
                    .gidMappings = {},
                    .options = { { "rbind" } },
                    .source = bind.source,
                    .type = "bind",
                    .uidMappings = {},
                  });
              };

            auto bindInnerMount =
              [&applicationMounts,
               this](const api::types::v1::ApplicationConfigurationPermissionsInnerBind &bind) {
                  applicationMounts.push_back(ocppi::runtime::config::types::Mount{
                    .destination = bind.destination,
                    .gidMappings = {},
                    .options = { { "rbind" } },
                    .source = bundle.string() + "/rootfs" + bind.source,
                    .type = "bind",
                    .uidMappings = {},
                  });
              };

            const auto &perm = info.permissions;
            if (perm->binds) {
                const auto &binds = perm->binds;
                std::for_each(binds->cbegin(), binds->cend(), bindMount);
            }

            if (perm->innerBinds) {
                const auto &innerBinds = perm->innerBinds;
                std::for_each(innerBinds->cbegin(), innerBinds->cend(), bindInnerMount);
            }

            builder.addExtraMounts(applicationMounts);
        }

        return LINGLONG_OK;
    };

    if (appLayer) {
        auto res = fillPermissionsBinds(*appLayer);
        if (!res) {
            return LINGLONG_ERR("failed to apply permission binds for "
                                  + appLayer->getReference().toString(),
                                res);
        }
    }

    for (auto &ext : extensionLayers) {
        if (!fillPermissionsBinds(ext)) {
            LogW("failed to apply permission binds for {}", ext.getReference().toString());
            continue;
        }
    }

    return LINGLONG_OK;
}

api::types::v1::ContainerProcessStateInfo RunContext::stateInfo()
{
    auto state = linglong::api::types::v1::ContainerProcessStateInfo{
        .containerID = containerID,
    };

    if (baseLayer) {
        state.base = baseLayer->getReference().toString();
    }

    if (appLayer) {
        state.app = appLayer->getReference().toString();
    }

    if (runtimeLayer) {
        state.runtime = runtimeLayer->getReference().toString();
    }

    state.extensions = std::vector<std::string>{};
    for (auto &ext : extensionLayers) {
        state.extensions->push_back(ext.getReference().toString());
    }

    return state;
}

utils::error::Result<std::filesystem::path> RunContext::getBaseLayerPath() const
{
    LINGLONG_TRACE("get base layer path");

    if (!baseLayer) {
        return LINGLONG_ERR("run context doesn't resolved");
    }

    return baseLayer->getLayerDir()->path();
}

std::string RunContext::currentAppId() const
{
    if (appLayer) {
        return appLayer->getReference().id;
    }
    return targetId;
}

std::optional<RunContext::CommandSettings> RunContext::commandSettings() const
{
    if (!runtimeConfigEnabled) {
        return std::nullopt;
    }

    auto appId = currentAppId();
    if (appId.empty()) {
        return std::nullopt;
    }

    std::string baseId;
    if (baseLayer) {
        baseId = baseLayer->getReference().id;
    }

    auto mergedCfg = loadMergedJsonWithBase(appId, baseId);
    const json *node = pickCommandNode(mergedCfg, appId);
    if (!node) {
        return std::nullopt;
    }

    return parseCommandSettings(appId, *node);
}

utils::error::Result<std::filesystem::path> RunContext::getRuntimeLayerPath() const
{
    LINGLONG_TRACE("get runtime layer path");

    if (!runtimeLayer) {
        return LINGLONG_ERR("no runtime layer exist");
    }

    return runtimeLayer->getLayerDir()->path();
}

utils::error::Result<api::types::v1::RepositoryCacheLayersItem> RunContext::getCachedAppItem()
{
    LINGLONG_TRACE("get cached app item");

    if (!appLayer) {
        return LINGLONG_ERR("no app layer exist");
    }

    return appLayer->getCachedItem();
}

} // namespace linglong::runtime
