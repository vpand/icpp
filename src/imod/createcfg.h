/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <boost/json.hpp>
#include <vector>

namespace imod {

// icpp module magic value
constexpr const uint32_t module_magic = 'ppci';

/*
The json configuration format to create an icpp module package:
{
  "name": "",
  "headers": [],
  "header-dirs": [],
  "sources": [],
  "binary-objs": [],
  "binary-libs": [],
  "include-dirs": []
}
*/

/*
These "module_" prefixed keys-values are part of icpp module package, they'll be
used or loaded at runtime by icpp. After being installed to icpp module
manager's repository, their layout is as follows:

.icpp
---include
------boost
------icpp
---------name
------------headers.h
------------header-dirs
---lib
------boost
------icpp
---------name
------------binary-objs.o
------------binary-libs
------------sources.o
------------symbol.hash

e.g.:
json {
  "name": "module-demo",
  "headers": ["module.h"],
  "header-dirs": [],
  "sources": ["module.cc"],
  "binary-objs": [],
  "binary-libs": [],
  "include-dirs": []
}

.icpp
---include
------boost
------icpp
---------module-demo
------------module.h
---lib
------boost
------icpp
---------module-demo
------------module.o
------------symbol.hash

The symbol.hash file is kind of symbol-hash cache file which is automatically
generated at installing time, it's used for the icpp interpreter runtime to
check and lazily load their relational library or iobject.
*/
constexpr std::string_view module_name = "name";
constexpr std::string_view module_hdrs = "headers";
constexpr std::string_view module_hdrdirs = "header-dirs";
constexpr std::string_view module_srcs = "sources";
constexpr std::string_view module_objs = "binary-objs";
constexpr std::string_view module_libs = "binary-libs";

/*
These "compile_" prefixed keys-values are used by icpp to compile the module
"sources" to binary object file when creating the package.
*/
constexpr std::string_view compile_incdirs = "include-dirs";

class CreateConfig {
public:
  CreateConfig(std::string_view path);
  ~CreateConfig();

  boost::json::string name();
  std::vector<boost::json::string> headers();
  std::vector<boost::json::string> headerDirs();
  std::vector<boost::json::string> sources();
  std::vector<boost::json::string> binaryObjects();
  std::vector<boost::json::string> binaryLibraries();
  std::vector<boost::json::string> includeDirs();

private:
  std::unique_ptr<boost::json::value> json_;
};

} // namespace imod
