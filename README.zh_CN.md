<!-- markdownlint-disable-next-line MD033 -->
# <img src="./misc/image/logo.svg" alt="如意玲珑图标" width="24" height="24" style="vertical-align:middle;">如意玲珑：更先进的 Linux 跨发行版软件包管理工具集

## :package: 介绍

[English](README.md) | [简体中文](README.zh_CN.md)

[![Contributors](https://img.shields.io/github/contributors/OpenAtom-Linyaps/linyaps)](https://github.com/OpenAtom-Linyaps/linyaps/graphs/contributors)
[![Latest Release](https://img.shields.io/github/v/release/OpenAtom-Linyaps/linyaps?style=flat&color=brightgreen)](https://github.com/OpenAtom-Linyaps/linyaps/releases)
[![Powered by Linyaps](https://img.shields.io/badge/powered%20by-Linyaps-ff69b4)](https://github.com/OpenAtom-Linyaps/linyaps)
[![Build Status](https://build.deepin.com/projects/linglong:CI:latest/packages/linyaps/badge.svg?type=default)](https://build.deepin.com/projects/linglong:CI:latest)

[![GitHub Stars](https://img.shields.io/github/stars/OpenAtom-Linyaps/linyaps?style=social)](https://github.com/OpenAtom-Linyaps/linyaps/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/OpenAtom-Linyaps/linyaps?style=social&label=Fork)](https://github.com/OpenAtom-Linyaps/linyaps/network/members)
[![Code Size](https://img.shields.io/github/languages/code-size/OpenAtom-Linyaps/linyaps)](https://github.com/OpenAtom-Linyaps/linyaps)
[![GitHub Issues](https://img.shields.io/github/issues/OpenAtom-Linyaps/linyaps?style=social)](https://github.com/OpenAtom-Linyaps/linyaps/issues)

**如意玲珑**（Linyaps Is Not Yet Another Packaging System）是由如意玲珑社区团队开发并开源共建的**Linux 跨发行版软件包格式**，项目以独立沙盒容器的形式实现应用包的开发、管理、分发，用于替代 deb、rpm 等传统包管理工具，让 Linux 软件运行更兼容、更安全、更高效。

### :sparkles: 亮点

- **独创的非全量运行时（Runtime）设计**：基于标准化沙箱 Runtime，应用一次构建即可覆盖所有 Linux 发行版。Runtime 多版本共存且文件共享减少冗余，启动时通过动态库共享复用已加载资源，**速度提升显著，避免依赖冲突**。
- **非特权沙箱与双层隔离**：默认无 root 权限运行，通过内核  Namespace 隔离（进程/文件系统/网络等）构建**安全沙箱**。通过 OSTree 仓库提供原子化增量更新与版本回滚，相比全量沙箱方案，**资源占用更低**。

### :flags: 进展

- **发行版支持**：deepin、UOS、openEuler、Ubuntu、Debian、openKylin、Anolis OS，更多发行版适配中，欢迎参与贡献。
- **CPU 架构支持**：X86、ARM64、LoongArch，未来将提供对 RISC-V 等更多架构的支持。


### :本仓库用途
本仓库是去除玲珑对于deepin专门的patch等,让其可以正常在其他发行版上运行的源代码
当前Master分支移植版本:1.9.7