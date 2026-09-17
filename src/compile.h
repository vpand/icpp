// Interpreting C++(ICPP) - Run C++ anywhere, just like a script.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#pragma once

#include "utils.h"

namespace icpp {

// original clang-format main entry
int cformat_main(int argc, const char **argv);

// original clang compiler main entry
int clang_main(int argc, const char **argv);

// incremental clang compiler main entry
int increment_main(int argc, const char **argv);

int compile_source_clang(int argc, const char **argv, bool cl = false);

int compile_source_icpp(int argc, const char **argv);

fs::path compile_source_icpp(const char *argv0, std::string_view path,
                             const char *opt,
                             const std::vector<const char *> &incdirs);

void precompile_module(const char *argv0);

const char *current_main();

} // namespace icpp
