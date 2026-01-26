// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include "efi_deps.h"

struct args_t {
  module_type_t module_type;
  int disable_ui;
  int disable_vuln_hunt;
};

extern args_t g_args;
extern efi_deps_t g_deps;
