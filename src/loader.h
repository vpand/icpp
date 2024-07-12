/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace icpp {

class Object;

class Loader {
public:
  Loader(Object *object, const std::vector<std::string> &deps);
  Loader(std::string_view module);
  ~Loader();

  bool valid();

  // initialize the module/object loader
  static void initialize();

  // deinitialize the module loader and cache the iobject modules
  static void deinitialize(int exticode);

  // locate the symbol runtime address in this loader
  const void *locate(std::string_view name, bool data);

  // locate the symbol runtime address
  static const void *locateSymbol(std::string_view name, bool data);

  // locate the module path which the symbol belongs to
  static std::string locateModule(const void *addr, bool update = false);

  // cache the iobject module
  static void cacheObject(std::shared_ptr<Object> imod);

  // cache the symbol with specified implementation
  static void cacheSymbol(std::string_view name, const void *impl);

  // check whether the vm address belongs to a iobject text section
  static bool executable(uint64_t vm, Object **iobject);

  // check whether the vm address belongs to a iobject module
  static bool belong(uint64_t vm);

private:
  Object *object_ = nullptr;
  const void *handle_;
};

} // namespace icpp
