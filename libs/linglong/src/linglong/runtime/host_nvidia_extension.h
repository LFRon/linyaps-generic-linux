/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#pragma once

#include "linglong/api/types/v1/DeviceNode.hpp"
#include "linglong/utils/error/error.h"
#include "ocppi/runtime/config/types/Mount.hpp"

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace linglong::runtime {

struct HostNvidiaExtension
{
    std::string name;
    std::filesystem::path root;
    std::map<std::string, std::string> env;
    std::vector<api::types::v1::DeviceNode> deviceNodes;
    std::vector<ocppi::runtime::config::types::Mount> extraMounts;
    bool has32Bit{ false };
};

utils::error::Result<std::optional<HostNvidiaExtension>>
prepareHostNvidiaExtension(const std::filesystem::path &bundle,
                           const std::string &extensionName) noexcept;

} // namespace linglong::runtime
