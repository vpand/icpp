// Interpreting C++(ICPP) - Run C++ anywhere, just like a script.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.
//

#include <filesystem>
#include <thread>

#include <dlfcn.h>

extern "C" void start_icpp_server(const char *program) {
  auto icpp_gadget =
      std::filesystem::path(program).parent_path() / "lib/icpp-gadget.dylib";
  auto path = icpp_gadget.string();

  printf("Loading %s...\n", path.data());
  auto handle = dlopen(path.data(), RTLD_NOW);
  if (handle) {
    // The server starts running automatically by its module ctors
    printf("The icpp-server is running...\n");
  } else {
    printf("Failed to load %s: %s.\n", path.data(), dlerror());
  }
}
