#include <icpp.hpp>

int main(int argc, const char *argv[]) {
  auto thisdir = fs::path(argv[0]).parent_path();

  icpp::prints("The running {} version is {}.\nCurrent user home is {}.\n",
               icpp::program(), icpp::version(), icpp::home_directory());

  icpp::exec_expression("icpp::result_set(88888888)");
  icpp::exec_string(R"(#include <icpp.hpp>\n"
    "int main(int argc, const char *argv[]) {"
    "std::puts("Executing string");"
    "icpp::result_set(argv[0]);"
    "std::puts("Done.");"
    "return 0;}")",
                    argc, argv);

  icpp::exec_source((thisdir / "split.cc").string());
  icpp::exec_module("module-demo");

  icpp::prints("Current result: i={}, s={}\n", icpp::result_get(),
               icpp::result_gets());

  icpp::prints("The {} is a c++ source? {}.\n", argv[0],
               icpp::is_cpp_source(argv[0]));

  icpp::prints("Random values: {}, {}, {}.\n", icpp::rand_value(),
               icpp::rand_string(16), icpp::rand_filename(8, ".cc"));

  if (argc == -1) {
    icpp::load_library("");
    icpp::unload_library(nullptr);
    icpp::resolve_symbol("");
    icpp::iterate_modules(
        [](uint64_t base, std::string_view path) { return true; });
  }

  return 0;
}
