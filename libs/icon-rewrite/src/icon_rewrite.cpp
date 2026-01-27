// SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <dlfcn.h>

#include <cstdlib>
#include <cstring>
#include <string>

struct _AppIndicator;
using AppIndicator = struct _AppIndicator;

namespace {

const char *rewrite_icon_path(const char *icon_name, std::string &storage)
{
    if (icon_name == nullptr || icon_name[0] == '\0') {
        return icon_name;
    }
    if (icon_name[0] != '/') {
        return icon_name;
    }

    const char *appId = std::getenv("LINGLONG_APPID");
    const char *hostFiles = std::getenv("LINGLONG_APP_FILES_HOST");
    if (appId == nullptr || appId[0] == '\0' || hostFiles == nullptr || hostFiles[0] == '\0') {
        return icon_name;
    }

    std::string prefix = std::string("/opt/apps/") + appId + "/files";
    if (std::strncmp(icon_name, prefix.c_str(), prefix.size()) != 0) {
        return icon_name;
    }

    const char *rest = icon_name + prefix.size();
    if (rest[0] == '/') {
        ++rest;
    } else if (rest[0] != '\0') {
        return icon_name;
    }

    std::string hostPath = hostFiles;
    if (!hostPath.empty() && hostPath.back() == '/') {
        hostPath.pop_back();
    }

    storage = hostPath;
    if (rest[0] != '\0') {
        storage.push_back('/');
        storage.append(rest);
    }

    return storage.c_str();
}

} // namespace

using set_icon_fn = void (*)(AppIndicator *, const char *);
using set_icon_full_fn = void (*)(AppIndicator *, const char *, const char *);

extern "C" void app_indicator_set_icon(AppIndicator *self, const char *icon_name)
{
    static auto real = reinterpret_cast<set_icon_fn>(dlsym(RTLD_NEXT, "app_indicator_set_icon"));
    if (!real) {
        return;
    }

    thread_local std::string rewritten;
    const char *final_name = rewrite_icon_path(icon_name, rewritten);
    real(self, final_name);
}

extern "C" void app_indicator_set_icon_full(AppIndicator *self,
                                            const char *icon_name,
                                            const char *icon_desc)
{
    static auto real =
      reinterpret_cast<set_icon_full_fn>(dlsym(RTLD_NEXT, "app_indicator_set_icon_full"));
    if (!real) {
        return;
    }

    thread_local std::string rewritten;
    const char *final_name = rewrite_icon_path(icon_name, rewritten);
    real(self, final_name, icon_desc);
}
