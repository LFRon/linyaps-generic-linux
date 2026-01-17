// SPDX-FileCopyrightText: 2024 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <gtest/gtest.h>

#include "linglong/utils/cmd.h"
#include "linglong/utils/error/error.h"

TEST(command, Exec)
{
    auto ret = linglong::utils::Cmd("echo").exec({ "-n", "hello" });
    EXPECT_TRUE(ret);
    EXPECT_EQ(ret->length(), 5);
    EXPECT_EQ(*ret, "hello");
    auto ret2 = linglong::utils::Cmd("id").exec({ "-u" });
    EXPECT_TRUE(ret2.has_value());

    auto userId = *ret2;
    userId.erase(std::remove(userId.begin(), userId.end(), '\n'), userId.end());
    EXPECT_EQ(userId, std::to_string(getuid()));

    // 测试command不存在时
    auto ret3 = linglong::utils::Cmd("nonexistent").exec();
    EXPECT_FALSE(ret3.has_value());

    // 测试exec出错时
    auto ret4 = linglong::utils::Cmd("ls").exec({ "nonexistent" });
    EXPECT_FALSE(ret4.has_value());
}

TEST(command, commandExists)
{
    auto ret = linglong::utils::Cmd("ls").exists();
    EXPECT_TRUE(ret) << "ls command should exist";
    ret = linglong::utils::Cmd("nonexistent").exists();
    EXPECT_FALSE(ret) << "nonexistent should not exist";
}

TEST(command, setEnv)
{
    linglong::utils::Cmd cmd("bash");
    // test set
    cmd.setEnv("LINGLONG_TEST_SETENV", "OK");
    auto existsRef = cmd.exists();
    EXPECT_TRUE(existsRef);
    // test unset
    cmd.setEnv("PATH", "");
    auto ret = cmd.exec({ "-c", "export" });
    EXPECT_TRUE(ret.has_value()) << ret.error().message();
    const auto &retStr = *ret;
    EXPECT_TRUE(retStr.find("declare -x LINGLONG_TEST_SETENV=") != std::string::npos) << retStr;
    EXPECT_FALSE(retStr.find("declare -x PATH=\"") != std::string::npos) << retStr;
}
