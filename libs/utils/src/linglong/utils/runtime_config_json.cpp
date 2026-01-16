/*
 * SPDX-FileCopyrightText: 2026 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include "runtime_config_json.h"

#include "linglong/common/dir.h"

#include <fstream>
#include <optional>

namespace linglong::utils {

std::vector<std::filesystem::path> runtimeConfigBasesUserFirst()
{
    auto userConfigDir = linglong::common::dir::getUserRuntimeConfigDir();
    if (userConfigDir.empty()) {
        return {};
    }
    return { userConfigDir };
}

std::vector<std::filesystem::path> runtimeConfigBasesFallbackFirst()
{
    // With mainline roots (user only), fallback order is identical.
    return runtimeConfigBasesUserFirst();
}

nlohmann::json loadMergedRuntimeConfigJson(const std::string &appId, const std::string &baseId)
{
    namespace fs = std::filesystem;
    using json = nlohmann::json;

    json merged = json::object();
    (void)baseId;

    auto readIfExists = [](const fs::path &p) -> std::optional<json> {
        try {
            if (!fs::exists(p)) {
                return std::nullopt;
            }
            std::ifstream in(p);
            if (!in.is_open()) {
                return std::nullopt;
            }
            json j;
            in >> j;
            return j;
        } catch (...) {
            return std::nullopt;
        }
    };

    for (const auto &root : runtimeConfigBasesFallbackFirst()) {
        if (auto g = readIfExists(root / "config.json")) {
            merged.merge_patch(*g);
        }
        if (!appId.empty()) {
            if (auto a = readIfExists(root / "apps" / appId / "config.json")) {
                merged.merge_patch(*a);
            }
        }
    }

    return merged;
}

} // namespace linglong::utils
