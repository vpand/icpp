// Interpreting C++(ICPP) - Run C++ anywhere, just like a script.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#include "runcfg.h"
#include "arch.h"
#include "utils.h"

#include <boost/json.hpp>

#include <cstdio>
#include <fstream>
#include <memory>
#include <string_view>

#include <AetherBinary.h>
#include <Disassembler.h>

namespace json = boost::json;

namespace icpp {

constexpr std::string_view key_debugger = "vm_debugger";
constexpr std::string_view key_dbgport = "vm_debug_port";
constexpr std::string_view key_stepsize = "vm_step_size";

bool RunConfig::repl = false;
bool RunConfig::gadget = false;
int (*RunConfig::printf)(const char *, ...) = std::printf;
int (*RunConfig::puts)(const char *) = std::puts;

RunConfig *RunConfig::inst(const char *argv0, const char *cfg) {
  static std::unique_ptr<RunConfig> runcfg;
  if (runcfg)
    return runcfg.get();

  // trigger the llvm targets initialization
  aether::Disassembler diser(aether::Binary::arch(host_arch()));

  runcfg = std::make_unique<RunConfig>(cfg);
  runcfg->program = argv0;
  return runcfg.get();
}

RunConfig::RunConfig(const char *cfg) {
  if (!cfg || !cfg[0])
    return; // use the default config

  std::ifstream inf(cfg);
  if (!inf.is_open()) {
    log_print(Runtime, "Failed to read the running configuration file.");
    return;
  }
  try {
    auto jcfg = json::parse(inf);
    auto object = jcfg.as_object();
    if (object.contains(key_debugger)) {
      auto value = object.at(key_debugger);
      if (value.is_bool())
        has_debugger_ = value.as_bool();
      else
        log_print(Runtime, "The value of '{}' must be a bool value.",
                  key_debugger);
    }
    if (object.contains(key_dbgport)) {
      auto value = object.at(key_dbgport);
      if (value.is_int64()) {
        auto ivalue = value.as_int64();
        if (1 <= ivalue && ivalue <= 0xffff)
          debug_port_ = ivalue;
        else
          log_print(Runtime,
                    "The value of '{}' must be in the range [1, 65535].",
                    key_dbgport);
      } else {
        log_print(Runtime, "The value of '{}' must be an int value.",
                  key_dbgport);
      }
    }
    if (object.contains(key_stepsize)) {
      auto value = object.at(key_stepsize);
      if (value.is_int64())
        step_size_ = value.as_int64();
      else
        log_print(Runtime, "The value of '{}' must be an int value.",
                  key_stepsize);
    }

    log_print(Runtime,
              "Current running configuration = {{\n\tdebugger : {}\n\tdbgport "
              ": {}\n\tstep size : {}\n}}",
              has_debugger_ ? "on" : "off", debug_port_,
              step_size_ <= 0 ? std::string("max")
                              : std::format("{}", step_size_));
  } catch (std::exception &e) {
    log_print(Runtime, "Failed to parse the running configuration file: {}.",
              e.what());
    return;
  }
}

RunConfig::~RunConfig() {}

int RunConfig::debugPort() { return debug_port_; }

int RunConfig::stepSize() { return step_size_; }

bool RunConfig::hasDebugger() { return has_debugger_; }

} // namespace icpp
