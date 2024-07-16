/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "runcfg.h"
#include "utils.h"
#include <boost/json.hpp>
#include <cstdio>
#include <fstream>
#include <memory>
#include <string_view>

namespace json = boost::json;

namespace icpp {

constexpr const std::string_view key_debugger = "vm_debugger";
constexpr const std::string_view key_stacksize = "vm_stack_size";
constexpr const std::string_view key_stepsize = "uc_step_size";

bool RunConfig::repl = false;
bool RunConfig::gadget = false;
int (*RunConfig::printf)(const char *, ...) = std::printf;
int (*RunConfig::puts)(const char *) = std::puts;

RunConfig *RunConfig::inst(const char *argv0, const char *cfg) {
  static std::unique_ptr<RunConfig> runcfg;
  if (runcfg)
    return runcfg.get();

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
    if (object.contains(key_stacksize)) {
      auto value = object.at(key_stacksize);
      if (value.is_int64()) {
        auto ivalue = value.as_int64();
        if (1 <= ivalue && ivalue <= 64)
          stack_size_ = ivalue * 1024 * 1024;
        else
          log_print(Runtime,
                    "The value of '{}' must be in the range [1, 32], the "
                    "internal unit is 1MB.",
                    key_stacksize);
      } else {
        log_print(Runtime, "The value of '{}' must be an int value.",
                  key_stacksize);
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
              "Current running configuration = {{\n\tdebugger : {}\n\tstack "
              "size : {}MB\n\tstep size : {}\n}}",
              has_debugger_ ? "on" : "off", stack_size_ / 1024 / 1024,
              step_size_ <= 0 ? std::string("max")
                              : std::format("{}", step_size_));
  } catch (std::exception &e) {
    log_print(Runtime, "Failed to parse the running configuration file: {}.",
              e.what());
    return;
  }
}

RunConfig::~RunConfig() {}

int RunConfig::stackSize() { return stack_size_; }

int RunConfig::stepSize() { return step_size_; }

bool RunConfig::hasDebugger() { return has_debugger_; }

} // namespace icpp
