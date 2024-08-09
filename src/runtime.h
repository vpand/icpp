/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include "utils.h"
#include <map>
#include <vector>

namespace com {
namespace vpand {
namespace imod {
class SymbolHash;
}
} // namespace vpand
} // namespace com

namespace vpimod = com::vpand::imod;

namespace icpp {

// third-part module extension for icpp runtime, usually it's installed
// by imod package manager
class RuntimeLib {
public:
  static RuntimeLib &inst();

  fs::path repo(bool force = true);
  fs::path includeFull();
  fs::path libFull();

  fs::path assetRelative() { return "asset"; }
  fs::path includeRelative() { return "include"; }
  fs::path binRelative() { return "bin"; }
  fs::path libRelative() { return "lib"; }

  fs::path assetRelative(std::string_view module) {
    return assetRelative() / module;
  }

  fs::path includeRelative(std::string_view module) {
    return includeRelative() / module;
  }
  fs::path binRelative(std::string_view module) {
    return binRelative() / module;
  }
  fs::path libRelative(std::string_view module) {
    return libRelative() / module;
  }
  fs::path includeFull(std::string_view module);
  fs::path binFull(std::string_view module) {
    return repo() / binRelative(module);
  }
  fs::path libFull(std::string_view module) {
    return repo() / libRelative(module);
  }

  void initHashes();

  /*
  When module loader can't resolve the symbol, before aborting the whole
  program, it will call this function to check whether user installed modules
  contain the symbol or not. The return value is the located object/library full
  path that contains this symbol.
  */
  fs::path find(std::string_view symbol);

  std::vector<std::string_view> modules();

  const std::string_view repoName{".icpp"};
  const std::string_view hashFile{"symbol.hash"};
  const std::string_view packageExtension{".icpp"};

private:
  RuntimeLib();
  ~RuntimeLib();

  // <module name, hashes>
  std::map<std::string, std::unique_ptr<vpimod::SymbolHash>> hashes_;
};

namespace api {

// the icpp interpreter version
std::string_view version();

// the icpp main program argv[0] path
std::string_view program();

// the current user home directory, e.g.: ~, C:/Users/icpp
std::string_view home_directory();

// execute a c++ expression
int exec_expression(std::string_view expr);

// execute a c++ source from string
int exec_string(std::string_view code, int argc = 0,
                const char **argv = nullptr);

// execute a c++ source file
int exec_source(std::string_view path, int argc = 0,
                const char **argv = nullptr);

// execute an icpp module installed by imod
int exec_module(std::string_view module, int argc = 0,
                const char **argv = nullptr);

// result setter/getter for main script and its sub script
// which is executed by exec_* api
/*
e.g.:
  icpp::exec_expression("result_set(520)");
  icpp::prints("Result: {}", result_get());
*/
void result_set(long result);
void result_sets(const std::string_view &result);
long result_get();
std::string_view result_gets();

// load a native library
void *load_library(std::string_view path);
// unload a native library
void *unload_library(void *handle);
// lookup a native symbol
// default search in the whole program
void *resolve_symbol(std::string_view name, void *handle = nullptr);
// iterate all the native modules in this running process,
// return true to break iterating
void iterate_modules(
    const std::function<bool(uint64_t base, std::string_view path)> &callback);

// check whether the given path ends with a c++ source file extension or not
bool is_cpp_source(std::string_view path);

// random value or string generator
int rand_value();
/*
The better prototype should be: std::string rand_string(int length = 8);
But on Windows, icpp itself is built by clang-cl in Visual Studio, icpp.hpp
will be built by clang-icpp, so the std::string may be defined in a different
way, to avoid the type mismatch, herein gives it an old C style one.

As of this, if you want to extend icpp runtime with native modules, the type
mismatch situation must be considered  on Windows.
*/
std::string_view rand_string(char *buff, int length);

} // namespace api

} // namespace icpp
