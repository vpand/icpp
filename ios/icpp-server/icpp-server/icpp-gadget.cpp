// Interpreting C++(ICPP) - Run C++ anywhere, just like a script.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.
//

#include <filesystem>
#include <thread>

#include <dlfcn.h>

namespace fs = std::filesystem;

extern "C" void start_icpp_server(const char *program) {
  printf("Initializing...\n");

  auto main_exe = fs::path(program);
  auto bundle_dir = main_exe.parent_path();
  auto icpp_gadget = bundle_dir / "lib/icpp-gadget.dylib";

  auto path = icpp_gadget.string();
  auto handle = dlopen(path.data(), RTLD_NOW);
  if (!handle) {
    printf("Failed to load %s: %s.\n", path.data(), dlerror());
    return;
  }

  auto entry = (void (*)(int, const char **))dlsym(handle, "icpp_gadget");
  if (!entry) {
    printf("Failed to locate entry point: %s.\n", dlerror());
    return;
  }

  std::thread([entry] {
    const char *argv[]{"icpp-server"};
    entry(1, &argv[0]);
  }).detach();
  printf("The icpp-server is running...\n");
}
