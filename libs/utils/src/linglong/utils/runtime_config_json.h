/*
 * SPDX-FileCopyrightText: 2026 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */
#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace linglong::utils {

// Returns config roots in priority order.
// Mainline behavior: user config dir only (see linglong::common::dir::getUserRuntimeConfigDir()).
std::vector<std::filesystem::path> runtimeConfigBasesUserFirst();

// Returns config roots in merge order for JSON merge_patch: low priority first.
// With mainline roots this is identical to runtimeConfigBasesUserFirst().
std::vector<std::filesystem::path> runtimeConfigBasesFallbackFirst();

// Loads and merges runtime config JSON from:
//   <root>/config.json
//   <root>/apps/<appId>/config.json
// across all roots, using JSON merge_patch.
//
// This is intentionally JSON-level and schema-agnostic so it can carry both
// mainline RuntimeConfigure keys (env/ext_defs) and 1471-style keys
// (permissions, filesystem, udev, whitelist, ...).
//
// On any read/parse failure for a single file, that file is ignored.
// Note: base-level overrides are intentionally not merged here (mainline handles base
// configuration via its own mechanisms).
nlohmann::json loadMergedRuntimeConfigJson(const std::string &appId, const std::string &baseId);

} // namespace linglong::utils
