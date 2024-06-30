/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "createcfg.h"
#include <boost/json.hpp>
#include <format>
#include <fstream>

namespace json = boost::json;

namespace imod {

CreateConfig::CreateConfig(std::string_view path)
    : json_(std::make_unique<json::value>()) {
  std::ifstream inf(path);
  *json_ = std::move(json::parse(inf));
}

CreateConfig::~CreateConfig() {}

std::string_view CreateConfig::name() {
  auto object = json_->as_object();
  if (object.contains(module_name))
    return object.at(module_name).as_string();
  throw std::invalid_argument(std::format("Key '{}' is missing.", module_name));
}

static std::vector<std::string_view> get_arrays(const json::value &json,
                                                std::string_view key) {
  std::vector<std::string_view> result;
  auto object = json.as_object();
  if (!object.contains(key))
    return result;
  auto value = object.at(key);
  if (!value.is_array())
    throw std::invalid_argument(
        std::format("Key '{}' should contain array value.", key));
  for (auto &v : value.as_array()) {
    result.push_back(v.as_string());
  }
  return result;
}

std::vector<std::string_view> CreateConfig::headers() {
  return get_arrays(*json_, module_hdrs);
}

std::vector<std::string_view> CreateConfig::headerDirs() {
  return get_arrays(*json_, module_hdrdirs);
}

std::vector<std::string_view> CreateConfig::sources() {
  return get_arrays(*json_, module_srcs);
}

std::vector<std::string_view> CreateConfig::binaryObjects() {
  return get_arrays(*json_, module_objs);
}

std::vector<std::string_view> CreateConfig::binaryLibraries() {
  return get_arrays(*json_, module_libs);
}

std::vector<std::string_view> CreateConfig::includeDirs() {
  return get_arrays(*json_, compile_incdirs);
}

} // namespace imod
