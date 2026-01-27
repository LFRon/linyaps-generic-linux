# SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

pfl_add_library(
  LIBRARY_TYPE
  SHARED
  OUTPUT_NAME
  ll-icon-rewrite
  SOURCES
  src/icon_rewrite.cpp
  COMPILE_FEATURES
  PUBLIC
  cxx_std_17
  LINK_LIBRARIES
  PUBLIC
  dl)
