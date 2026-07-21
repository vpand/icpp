/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under GPLv2.
   See LICENSE in root directory for more details
*/

#include "icpp.h"
#include <format>

namespace icpp {

std::string_view version_string() {
  static auto version =
      std::format("v{}.{}.{}.{}", version_major, version_minor, version_patch,
                  version_extra);
  return version;
}

version_t version_value() {
  return version_t{.major = version_major,
                   .minor = version_minor,
                   .patch = version_patch,
                   .extra = version_extra};
}

} // namespace icpp

#if ICPP_DLLIMPL // only for icpp and icpp-gadget

#include "../runtime/include/icpp.hpp"
#include "exec.h"
#include "loader.h"
#include "platform.h"
#include "runcfg.h"
#include "runtime.h"
#include "utils.h"

extern "C" bool icpp_reglib(const char *path);

namespace icpp {

// the icpp interpreter version
std::string_view version() { return icpp::version_string(); }

// the icpp main program argv[0] path
std::string_view program() { return icpp::RunConfig::inst()->program; }

// the current user home directory, e.g.: ~, C:/Users/icpp
std::string_view home() { return icpp::home_directory(); }

// execute a c++ expression
int exec_expression(std::string_view expr) {
  return icpp::exec_string(icpp::RunConfig::inst()->program, expr);
}

// execute a c++ source from string
int exec_string(std::string_view code, int argc, const char **argv) {
  return icpp::exec_string(icpp::RunConfig::inst()->program, code, true, argc,
                           argv);
}

// execute a c++ source file
int exec_source(std::string_view path, int argc, const char **argv) {
  return icpp::exec_source(icpp::RunConfig::inst()->program, path, argc, argv);
}

// execute an icpp module installed by imod
int exec_module(std::string_view module, int argc, const char **argv) {
  auto omain = icpp::RuntimeLib::inst().libFull(module) / "main.o";
  if (fs::exists(omain)) {
    std::vector<std::string> deps;
    int iargc = 1;
    auto mname = module.data();
    const char **iarg = &mname;
    if (argc) {
      iargc = argc;
      iarg = argv;
    }
    bool validcache;
    return icpp::exec_main(omain.string(), deps, omain.string(), iargc,
                           const_cast<char **>(iarg), validcache);
  }
  icpp::log_print(
      Runtime, "The module '{}' doesn't contain a main.o entry file.", module);
  return -1;
}

// result setter/getter for main script and its sub script
// which is executed by exec_* api
/*
e.g.:
  icpp::exec_expression("result_set(520)");
  icpp::prints("Result: {}", result_get());
*/
static std::uint64_t result_i = 0;
static std::string result_s;

void result_set(std::uint64_t result) { result_i = result; }

void result_sets(const std::string_view &result) { result_s = result; }

std::uint64_t result_get() { return result_i; }

std::string_view result_gets() { return result_s; }

// load a native library, and register it to icpp's runtime, so the script can
// refer its APIs dynamically
void *load_library(std::string_view path) {
  return icpp_reglib(path.data()) ? const_cast<void *>(icpp::load_native(path))
                                  : nullptr;
}

// unload a native library
void *unload_library(void *handle) {
  icpp::log_print(Runtime,
                  "Doesn't support unloading native library currently.");
  return handle;
}

// lookup a native symbol
// default search in the whole program
void *resolve_symbol(std::string_view name, void *handle) {
  return const_cast<void *>(icpp::find_symbol(handle, name));
}

// iterate all the native modules in this running process,
// return true to break iterating
void iterate_library(
    const std::function<bool(uint64_t base, std::string_view path)> &callback) {
  icpp::iterate_modules(callback);
}

// random value or string generator
int rand_int() { return icpp::rand_value(); }

std::string rand_str(int length) { return icpp::rand_string(length); }

void regex::init(std::string_view pattern, int flags) {
  auto rflags = static_cast<std::regex_constants::syntax_option_type>(flags);
  context_ = new std::regex(pattern.data(), rflags);
}

void regex::deinit() {
  auto preg = static_cast<std::regex *>(context_);
  delete preg;
}

// return true if str matches the initial pattern
bool regex::search(std::string_view str) const {
  auto preg = static_cast<std::regex *>(context_);
  return std::regex_search(str.data(), str.data() + str.size(), *preg);
}

void print(std::uint64_t val) { std::cout << val << std::endl; }

void print_hex(std::uint64_t val) { std::cout << std::format("0x{:x}\n", val); }

} // namespace icpp

#endif // end of ICPP_DLLIMPL
