/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

/*
This is a C++ script to format the modified project source files.

The initial icpp package can be downloaded for your local system at:
https://github.com/vpand/icpp/releases
*/

// for boost definitions
#include <boost/algorithm/string.hpp>
#include <boost/process.hpp>

// for standard c++ definitions
import std;

namespace fs = std::filesystem;
namespace bp = boost::process;

using namespace std::literals::string_literals;
using namespace std::literals::string_view_literals;

auto command(const std::string cmd, const std::vector<std::string> &args) {
  bp::ipstream is; // reading pipe-stream
  // cmd args > is
  bp::child(cmd, args, bp::std_out > is).wait();

  std::vector<std::string> data;
  std::string line;
  // read the output lines
  while (std::getline(is, line))
    data.push_back(line);

  return data;
}

int main(int argc, const char *argv[]) {
  auto thisdir = fs::path(argv[0]).parent_path();

  // you can use the following build command to generate clang-format:
  // build % cmake --build . -- clang-format
  auto clang_format_path =
      thisdir / "build/third/llvm-project/llvm/bin/clang-format";
  // the final formatter path
#if _WIN32
  auto clang_format = clang_format_path.string() + ".exe";
#else
  auto clang_format = clang_format_path.string();
#endif
  if (!fs::exists(clang_format)) {
    auto env = std::getenv("CLANG_FORMAT");
    if (!env || !fs::exists(env)) {
      // CLANG_FORMAT env is missing, make sure clang-format is in your system
      // PATH environment.
      clang_format = "clang-format";
    } else {
      clang_format = env;
    }
  }

  // make sure git is in your system PATH environment when running this script.
  auto gitlines = command(bp::search_path("git").string(),
                          {"status"s, "--ignore-submodules"s});
  std::vector<std::string> modifiedfs;
  for (auto &line : gitlines) {
    std::vector<std::string> parts;
    boost::iter_split(parts, line, boost::first_finder("modified:"));
    if (parts.size() != 2)
      boost::iter_split(parts, line, boost::first_finder("new file:"));
    if (parts.size() == 2) {
      boost::trim(parts[1]);
      // save the modified or newly created files
      modifiedfs.push_back(fs::path(parts[1]).filename().string());
    }
  }
  if (!modifiedfs.size()) {
    std::puts("Everything is up to date, nothing needs to be done.");
    return 0;
  }
  auto formatter = [&clang_format, &modifiedfs](std::string_view path) {
    static const std::vector<std::string_view> srcexts = {".c", ".cc", ".cpp",
                                                          ".h", ".hpp"};
    for (auto &f : modifiedfs) {
      // whether modified
      if (path.ends_with(f)) {
        for (auto &ext : srcexts) {
          // whether is c++ relational file
          if (path.ends_with(ext)) {
            // invoke clang-format to do the real work
            std::cout << "Formatting " << path << " ..." << std::endl;
            bp::child(
                clang_format,
                std::vector<std::string>{"-i"s, "-style=LLVM"s, path.data()})
                .wait();
            break;
          }
        }
        break;
      }
    }
  };
  // format self
  formatter(argv[0]);
  // format the icpp api header
  formatter((thisdir / "runtime/include/icpp.hpp").string());
  formatter((thisdir / "runtime/include/icppex.hpp").string());

  std::vector<std::string_view> subdirs = {
      "src", "snippet", "snippet-cppm", "tool-icpp", "test", "vmpstudio"};
  for (auto &d : subdirs) {
    for (auto &entry : fs::recursive_directory_iterator(thisdir / d)) {
      // format the source and header files
      if (entry.is_regular_file())
        formatter(entry.path().string());
    }
  }

  std::puts("Done.");
  return 0;
}
